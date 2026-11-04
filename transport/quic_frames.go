package transport

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/gojue/ecapture_decryptor/types"
)

const (
	maxQUICStreamBytes     = 16 << 20
	maxQUICStreams         = 1024
	maxQUICPendingSegments = 64 << 10
)

var (
	errQUICStreamLimit      = errors.New("QUIC stream exceeds size limit")
	errQUICBufferLimit      = errors.New("QUIC stream reassembly buffer exceeds limit")
	errQUICStreamCountLimit = errors.New("QUIC stream count limit exceeded")
)

type quicStreamKey struct {
	id       uint64
	isClient bool
}

type quicStreamAssembler struct {
	next         uint64
	pending      map[uint64][]byte
	pendingBytes int
	final        uint64
	hasFinal     bool
	finished     bool
}

func (s *quicStreamAssembler) push(offset uint64, data []byte, fin bool) ([][]byte, bool, error) {
	if offset > maxQUICStreamBytes || uint64(len(data)) > maxQUICStreamBytes-offset {
		return nil, false, errQUICStreamLimit
	}
	if fin {
		end := offset + uint64(len(data))
		if s.hasFinal && s.final != end {
			return nil, false, errors.New("QUIC stream has conflicting final offsets")
		}
		s.final, s.hasFinal = end, true
	}
	if s.finished {
		return nil, false, nil
	}
	var ready [][]byte
	if offset > s.next {
		if s.pending == nil {
			s.pending = make(map[uint64][]byte)
		}
		if old, exists := s.pending[offset]; len(old) < len(data) {
			if !exists && len(s.pending) >= maxQUICPendingSegments || s.pendingBytes-len(old)+len(data) > maxQUICStreamBytes {
				return nil, false, errQUICBufferLimit
			}
			s.pendingBytes += len(data) - len(old)
			s.pending[offset] = bytes.Clone(data)
		}
	} else if skip := s.next - offset; skip < uint64(len(data)) {
		part := bytes.Clone(data[skip:])
		ready = append(ready, part)
		s.next += uint64(len(part))
	}
	for {
		found := false
		for start, part := range s.pending {
			if start > s.next {
				continue
			}
			delete(s.pending, start)
			s.pendingBytes -= len(part)
			if skip := s.next - start; skip < uint64(len(part)) {
				tail := part[skip:]
				ready = append(ready, tail)
				s.next += uint64(len(tail))
			}
			found = true
			break
		}
		if !found {
			break
		}
	}
	complete := s.hasFinal && s.next == s.final
	if complete {
		s.finished = true
	}
	return ready, complete, nil
}

func consumeQUICVarint(data *[]byte) (uint64, error) {
	value, n, err := readQUICVarint(*data)
	if err != nil {
		return 0, err
	}
	*data = (*data)[n:]
	return value, nil
}

func consumeQUICBytes(data *[]byte, length uint64) ([]byte, error) {
	if length > uint64(len(*data)) {
		return nil, ioUnexpectedQUICEnd
	}
	part := (*data)[:length]
	*data = (*data)[length:]
	return part, nil
}

// parseQUICFrames handles the frame types that carry HTTP/3 streams and TLS
// CRYPTO data, and advances through the common control frames that can share
// a packet with them.
func (q *QUICDecryptor) parseQUICFrames(plaintext []byte, level int, isClient bool, at time.Time) (frameErr error) {
	reported := false
	defer func() {
		if frameErr != nil && !reported {
			q.options.Report(q.connectionInfo, "protocol", "invalid_frame")
		}
	}()
	data := plaintext
	for len(data) > 0 {
		frameType, err := consumeQUICVarint(&data)
		if err != nil {
			return err
		}
		switch {
		case frameType == 0x00 || frameType == 0x01 || frameType == 0x1e:
			// PADDING, PING, HANDSHAKE_DONE.
		case frameType == 0x02 || frameType == 0x03:
			// ACK: largest acknowledged, delay, count, first range, ranges, ECN.
			for i := 0; i < 2; i++ {
				if _, err := consumeQUICVarint(&data); err != nil {
					return err
				}
			}
			count, err := consumeQUICVarint(&data)
			if err != nil || count > 4096 {
				return errors.New("invalid QUIC ACK range count")
			}
			if _, err := consumeQUICVarint(&data); err != nil {
				return err
			}
			for i := uint64(0); i < count*2; i++ {
				if _, err := consumeQUICVarint(&data); err != nil {
					return err
				}
			}
			if frameType == 0x03 {
				for i := 0; i < 3; i++ {
					if _, err := consumeQUICVarint(&data); err != nil {
						return err
					}
				}
			}
		case frameType == 0x06:
			offset, err := consumeQUICVarint(&data)
			if err != nil {
				return err
			}
			length, err := consumeQUICVarint(&data)
			if err != nil {
				return err
			}
			part, err := consumeQUICBytes(&data, length)
			if err != nil {
				return err
			}
			if level == quicLevelInitial && isClient {
				if err := q.observeClientCrypto(offset, part); err != nil {
					reported = true
					return err
				}
			}
		case frameType >= 0x08 && frameType <= 0x0f:
			id, err := consumeQUICVarint(&data)
			if err != nil {
				return err
			}
			var offset uint64
			if frameType&0x04 != 0 {
				offset, err = consumeQUICVarint(&data)
				if err != nil {
					return err
				}
			}
			length := uint64(len(data))
			if frameType&0x02 != 0 {
				length, err = consumeQUICVarint(&data)
				if err != nil {
					return err
				}
			}
			part, err := consumeQUICBytes(&data, length)
			if err != nil {
				return err
			}
			if level == quicLevelApplication && (q.http3Parser != nil || q.options.RawChunks && q.packetChan != nil) {
				if err := q.feedQUICStream(id, offset, part, frameType&1 != 0, isClient, at); err != nil {
					reported = true
					return err
				}
			}
		case frameType == 0x04:
			for i := 0; i < 3; i++ { // RESET_STREAM
				if _, err := consumeQUICVarint(&data); err != nil {
					return err
				}
			}
		case frameType == 0x05 || frameType == 0x11 || frameType == 0x15:
			for i := 0; i < 2; i++ {
				if _, err := consumeQUICVarint(&data); err != nil {
					return err
				}
			}
		case frameType == 0x07:
			length, err := consumeQUICVarint(&data)
			if err != nil {
				return err
			}
			if _, err := consumeQUICBytes(&data, length); err != nil {
				return err
			}
		case frameType == 0x10 || frameType == 0x12 || frameType == 0x13 || frameType == 0x14 ||
			frameType == 0x16 || frameType == 0x17 || frameType == 0x19:
			if _, err := consumeQUICVarint(&data); err != nil {
				return err
			}
		case frameType == 0x18:
			for i := 0; i < 2; i++ {
				if _, err := consumeQUICVarint(&data); err != nil {
					return err
				}
			}
			cidLen, err := consumeQUICBytes(&data, 1)
			if err != nil || cidLen[0] > 20 {
				return errors.New("invalid QUIC connection ID length")
			}
			if _, err := consumeQUICBytes(&data, uint64(cidLen[0])+16); err != nil {
				return err
			}
		case frameType == 0x1a || frameType == 0x1b:
			if _, err := consumeQUICBytes(&data, 8); err != nil {
				return err
			}
		case frameType == 0x1c || frameType == 0x1d:
			if _, err := consumeQUICVarint(&data); err != nil { // error code
				return err
			}
			if frameType == 0x1c {
				if _, err := consumeQUICVarint(&data); err != nil { // offending frame
					return err
				}
			}
			length, err := consumeQUICVarint(&data)
			if err != nil {
				return err
			}
			if _, err := consumeQUICBytes(&data, length); err != nil {
				return err
			}
		case frameType == 0x30 || frameType == 0x31:
			length := uint64(len(data))
			if frameType == 0x31 {
				var err error
				length, err = consumeQUICVarint(&data)
				if err != nil {
					return err
				}
			}
			if _, err := consumeQUICBytes(&data, length); err != nil {
				return err
			}
		default:
			q.options.Report(q.connectionInfo, "protocol", "unsupported_frame")
			reported = true
			return fmt.Errorf("unsupported QUIC frame type 0x%x", frameType)
		}
	}
	return nil
}

func (q *QUICDecryptor) observeClientCrypto(offset uint64, data []byte) error {
	if len(q.flow.clientRandom) != 0 {
		return nil
	}
	parts, _, err := q.flow.clientCrypto.push(offset, data, false)
	if err != nil {
		q.reportQUICReassemblyError(err)
		return err
	}
	for _, part := range parts {
		if q.flow.clientHello.Len()+len(part) > maxQUICStreamBytes {
			q.options.Report(q.connectionInfo, "reassembly", "resource_limit")
			return errors.New("QUIC ClientHello exceeds size limit")
		}
		_, _ = q.flow.clientHello.Write(part)
	}
	hello := q.flow.clientHello.Bytes()
	if len(hello) >= 38 {
		if hello[0] != 1 {
			q.options.Report(q.connectionInfo, "handshake", "invalid_client_hello")
			return fmt.Errorf("QUIC CRYPTO starts with TLS handshake type 0x%x, want ClientHello", hello[0])
		}
		q.flow.clientRandom = bytes.Clone(hello[6:38])
		q.flow.clientHello.Reset()
	}
	return nil
}

func (q *QUICDecryptor) feedQUICStream(id, offset uint64, data []byte, fin, isClient bool, at time.Time) error {
	key := quicStreamKey{id: id, isClient: isClient}
	stream := q.flow.streams[key]
	if stream == nil {
		if len(q.flow.streams) >= maxQUICStreams {
			q.reportQUICReassemblyError(errQUICStreamCountLimit)
			return errQUICStreamCountLimit
		}
		stream = &quicStreamAssembler{}
		q.flow.streams[key] = stream
	}
	next := stream.next
	parts, complete, err := stream.push(offset, data, fin)
	if err != nil {
		q.reportQUICReassemblyError(err)
		return err
	}
	for index, part := range parts {
		last := complete && index == len(parts)-1
		if q.options.RawChunks {
			q.emitQUICChunk(id, next, part, last, isClient, at)
		} else if err := q.http3Parser.FeedQUICStream(id, isClient, part, last, at); err != nil {
			q.options.Report(q.connectionInfo, "protocol", "parse_failed")
			return err
		}
		next += uint64(len(part))
	}
	if complete && len(parts) == 0 {
		if q.options.RawChunks {
			q.emitQUICChunk(id, next, nil, true, isClient, at)
		} else if err := q.http3Parser.FeedQUICStream(id, isClient, nil, true, at); err != nil {
			q.options.Report(q.connectionInfo, "protocol", "parse_failed")
			return err
		}
	}
	// Keep a small completed-stream marker so repeated packets from loopback
	// captures or QUIC retransmissions cannot emit the same message again.
	if complete {
		stream.pending = nil
		stream.pendingBytes = 0
	}
	return nil
}

func (q *QUICDecryptor) reportQUICReassemblyError(err error) {
	code := "invalid_stream"
	if errors.Is(err, errQUICStreamLimit) || errors.Is(err, errQUICBufferLimit) || errors.Is(err, errQUICStreamCountLimit) {
		code = "resource_limit"
		q.flow.terminalErr = err
		_ = q.Close()
	}
	q.options.Report(q.connectionInfo, "reassembly", code)
}

func (q *QUICDecryptor) emitQUICChunk(id, offset uint64, data []byte, end, isClient bool, at time.Time) {
	if q.packetChan == nil {
		return
	}
	direction := "response"
	if isClient {
		direction = "request"
	}
	kind := "stream_chunk"
	if len(data) == 0 && end {
		kind = "stream_end"
	}
	packet := types.NewDecryptedPacket(types.TransportProtocolUDP, "quic", direction, data, at, q.connectionInfo)
	packet.WithMetadata("kind", kind).WithMetadata("stream_id", id).
		WithMetadata("offset", offset).WithMetadata("end", end)
	q.packetChan <- packet
}
