package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gojue/ecapture_decryptor/types"
	"github.com/quic-go/qpack"
)

const maxHTTP3StreamBytes = 16 << 20

type http3QUICStream struct {
	request  http3QUICMessage
	response http3QUICMessage
}

type http3QUICMessage struct {
	buffer      bytes.Buffer
	body        bytes.Buffer
	headers     http.Header
	method      string
	path        string
	scheme      string
	authority   string
	status      string
	at          time.Time
	headersDone bool
	finished    bool
}

// FeedQUICStream accepts contiguous plaintext bytes from one QUIC STREAM.
// QUIC packet decryption and offset reassembly happen before this call. Each
// client-initiated bidirectional stream is an independent HTTP/3 exchange.
func (p *HTTP3StreamParser) FeedQUICStream(id uint64, isClient bool, data []byte, fin bool, at time.Time) error {
	if id%4 != 0 { // Request streams are client-initiated bidirectional streams.
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	stream := p.quicStreams[id]
	if stream == nil {
		stream = &http3QUICStream{}
		p.quicStreams[id] = stream
	}
	message := &stream.request
	if !isClient {
		message = &stream.response
	}
	if message.finished {
		if len(data) == 0 {
			return nil
		}
		return fmt.Errorf("HTTP/3 stream %d received data after FIN", id)
	}
	if message.at.IsZero() {
		message.at = at
	}
	if message.buffer.Len()+message.body.Len()+len(data) > maxHTTP3StreamBytes {
		return fmt.Errorf("HTTP/3 stream %d exceeds %d bytes", id, maxHTTP3StreamBytes)
	}
	_, _ = message.buffer.Write(data)
	if err := p.parseQUICHTTP3Frames(message, isClient); err != nil {
		return fmt.Errorf("HTTP/3 stream %d: %w", id, err)
	}
	if !fin {
		return nil
	}
	if message.buffer.Len() != 0 || !message.headersDone {
		return fmt.Errorf("HTTP/3 stream %d ended with an incomplete message", id)
	}
	message.finished = true
	p.emitQUICHTTP3Message(id, message, stream, isClient)
	if stream.request.finished && stream.response.finished {
		delete(p.quicStreams, id)
	}
	return nil
}

func (p *HTTP3StreamParser) parseQUICHTTP3Frames(message *http3QUICMessage, isClient bool) error {
	for message.buffer.Len() > 0 {
		data := message.buffer.Bytes()
		frameType, typeLen := readVarInt(data)
		if typeLen == 0 {
			return nil
		}
		frameLen, lenLen := readVarInt(data[typeLen:])
		if lenLen == 0 {
			return nil
		}
		headerLen := typeLen + lenLen
		if frameLen > maxHTTP3StreamBytes || frameLen > uint64(len(data)-headerLen) {
			if frameLen > maxHTTP3StreamBytes {
				return errors.New("HTTP/3 frame exceeds message limit")
			}
			return nil
		}
		payload := data[headerLen : headerLen+int(frameLen)]
		switch frameType {
		case HTTP3FrameHeaders:
			if err := decodeQUICQPACKHeaders(message, payload, isClient); err != nil {
				return err
			}
		case HTTP3FrameData:
			if !message.headersDone {
				return errors.New("HTTP/3 DATA before HEADERS")
			}
			_, _ = message.body.Write(payload)
		case HTTP3FrameSettings, HTTP3FrameGoAway:
			return errors.New("HTTP/3 control frame on request stream")
		}
		message.buffer.Next(headerLen + int(frameLen))
	}
	return nil
}

func decodeQUICQPACKHeaders(message *http3QUICMessage, payload []byte, isClient bool) error {
	if message.headers == nil {
		message.headers = make(http.Header)
	}
	decode := qpack.NewDecoder().Decode(payload)
	for {
		field, err := decode()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("decode QPACK: %w", err)
		}
		if strings.HasPrefix(field.Name, ":") {
			if message.headersDone {
				return errors.New("pseudo-header in HTTP/3 trailers")
			}
			switch field.Name {
			case ":method":
				message.method = field.Value
			case ":path":
				message.path = field.Value
			case ":scheme":
				message.scheme = field.Value
			case ":authority":
				message.authority = field.Value
			case ":status":
				message.status = field.Value
			default:
				return fmt.Errorf("unsupported HTTP/3 pseudo-header %q", field.Name)
			}
		} else {
			message.headers.Add(field.Name, field.Value)
		}
	}
	message.headersDone = true
	if isClient && message.method == "" || !isClient && message.status == "" {
		return errors.New("HTTP/3 message missing required pseudo-header")
	}
	return nil
}

func (p *HTTP3StreamParser) emitQUICHTTP3Message(id uint64, message *http3QUICMessage, stream *http3QUICStream, isClient bool) {
	if p.packetChan == nil {
		return
	}
	var text bytes.Buffer
	direction := "response"
	if isClient {
		direction = "request"
		fmt.Fprintf(&text, "%s %s HTTP/3.0\r\n", message.method, message.path)
	} else {
		fmt.Fprintf(&text, "HTTP/3.0 %s\r\n", message.status)
	}
	for name, values := range message.headers {
		for _, value := range values {
			fmt.Fprintf(&text, "%s: %s\r\n", name, value)
		}
	}
	text.WriteString("\r\n")
	text.Write(message.body.Bytes())
	packet := types.NewDecryptedPacket(types.TransportProtocolUDP, "http/3", direction, text.Bytes(), message.at, p.addr)
	packet.WithMetadata("stream_id", id).WithMetadata("headers", message.headers)
	if isClient {
		packet.WithMetadata("method", message.method).
			WithMetadata("path", message.path).
			WithMetadata("scheme", message.scheme).
			WithMetadata("authority", message.authority)
	} else {
		var status int
		_, _ = fmt.Sscanf(message.status, "%d", &status)
		packet.WithMetadata("status", status).
			WithMetadata("authority", stream.request.authority)
	}
	p.packetChan <- packet
}
