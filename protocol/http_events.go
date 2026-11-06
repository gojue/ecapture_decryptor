// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package protocol

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"iter"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gojue/ecapture_decryptor/types"
)

const eventChunkSize = 32 << 10
const eventFieldLimit = 64 << 10

var ErrHTTPEventLimit = errors.New("HTTP event resource limit exceeded")

// One output belongs to one connection. The parser serializes its calls and
// blocking sends propagate backpressure all the way to the capture reader.
type eventOutput struct {
	conn         types.ConnectionKey
	ch           chan *types.DecryptedPacket
	limit        int64
	active       map[*eventBody]struct{}
	inflaters    int
	grpcBuffered int
}

func newEventOutput(conn types.ConnectionKey, ch chan *types.DecryptedPacket, limit int64) *eventOutput {
	return &eventOutput{conn: conn, ch: ch, limit: limit, active: make(map[*eventBody]struct{})}
}

type eventBody struct {
	out        *eventOutput
	proto      string
	client     bool
	id, offset uint64
	at         time.Time
	gzip       bool
	decoder    *gzipFeed
	sse        *eventSource
	grpc       *grpcMessages
	done       bool
}

func (o *eventOutput) headers(proto string, id uint64, client bool, at time.Time, h http.Header, meta map[string]any, info bool) (*eventBody, error) {
	b := &eventBody{out: o, proto: proto, id: id, client: client, at: at}
	if meta == nil {
		meta = make(map[string]any)
	}
	if !info {
		if len(o.active) >= 1024 {
			return nil, ErrHTTPEventLimit
		}
		o.active[b] = struct{}{}
		coding := strings.TrimSpace(strings.Join(h.Values("Content-Encoding"), ","))
		b.gzip = o.limit > 0 && strings.EqualFold(coding, "gzip")
		media, _, _ := mime.ParseMediaType(h.Get("Content-Type"))
		if proto == "http/2" && isGRPC(media) {
			if coding != "" && !strings.EqualFold(coding, "identity") {
				delete(o.active, b)
				return nil, errGRPC
			}
			b.grpc = &grpcMessages{encoding: h.Get("Grpc-Encoding")}
			if b.grpc.encoding == "" {
				b.grpc.encoding = "identity"
			}
			meta["grpc"] = true
		}
		if !client && media == "text/event-stream" && (coding == "" || strings.EqualFold(coding, "identity") || b.gzip) {
			b.sse = &eventSource{first: true}
		}
	}
	meta["headers"] = h.Clone()
	if info {
		meta["informational"] = true
	}
	if b.gzip {
		meta["decoded_encoding"] = "gzip"
	}
	b.emit("headers", nil, meta, b.offset)
	return b, nil
}

func (b *eventBody) emit(kind string, data []byte, meta map[string]any, offset uint64) {
	if b.out.ch == nil {
		return
	}
	direction := "response"
	if b.client {
		direction = "request"
	}
	packet := types.NewDecryptedPacket(b.out.conn.Proto, b.proto, direction, bytes.Clone(data), b.at, b.out.conn)
	for k, v := range meta {
		packet.WithMetadata(k, v)
	}
	packet.WithMetadata("kind", kind).WithMetadata("stream_id", b.id).WithMetadata("offset", offset)
	b.out.ch <- packet
}

func (b *eventBody) decoded(data []byte) error {
	for len(data) > 0 {
		part := data[:min(len(data), eventChunkSize)]
		if b.gzip && uint64(len(part)) > uint64(b.out.limit)-b.offset {
			return ErrHTTPEventLimit
		}
		b.emit("body_chunk", part, nil, b.offset)
		start := b.offset
		b.offset += uint64(len(part))
		if b.sse != nil {
			if err := b.sse.feed(b, part, start); err != nil {
				return err
			}
		}
		if b.grpc != nil {
			if err := b.grpc.feed(b, part, start); err != nil {
				return err
			}
		}
		data = data[len(part):]
	}
	return nil
}

func (b *eventBody) write(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if !b.gzip {
		return b.decoded(data)
	}
	if b.decoder == nil {
		if b.out.inflaters >= 16 {
			return ErrHTTPEventLimit
		}
		b.out.inflaters++
		b.decoder = newGzipFeed(b.decoded)
	}
	return b.decoder.feed(data, false)
}

func (b *eventBody) finishCoding() error {
	if b.decoder == nil {
		return nil
	}
	err := b.decoder.feed(nil, true)
	b.stopCoding()
	return err
}
func (b *eventBody) stopCoding() {
	if b.decoder != nil {
		b.decoder.close()
		b.decoder = nil
		b.out.inflaters--
	}
}
func (b *eventBody) trailers(h http.Header) error {
	if err := b.finishCoding(); err != nil {
		return err
	}
	meta := map[string]any{"trailers": h.Clone()}
	if b.grpc != nil && !b.client {
		status, err := b.grpc.trailers(h)
		if err != nil {
			return err
		}
		for k, v := range status {
			meta[k] = v
		}
	}
	b.emit("trailers", nil, meta, b.offset)
	return nil
}
func (b *eventBody) finish(kind string, meta map[string]any) error {
	if b == nil || b.done {
		return nil
	}
	var err error
	if kind == "end" {
		if err = b.finishCoding(); err != nil {
			kind = "partial"
		}
	}
	if b.grpc != nil {
		if kind == "end" {
			err = b.grpc.complete()
			if err == nil && !b.client && b.grpc.status == nil {
				err = errGRPC
			}
			if err != nil {
				kind = "partial"
			}
		}
		if b.grpc.status != nil {
			if meta == nil {
				meta = make(map[string]any)
			}
			for k, v := range b.grpc.status {
				meta[k] = v
			}
		}
		b.grpc.release(b)
		b.grpc = nil
	}
	b.stopCoding()
	b.sse = nil
	b.done = true
	delete(b.out.active, b)
	b.emit(kind, nil, meta, b.offset)
	return err
}
func (o *eventOutput) abort() { o.finishAll("partial") }
func (o *eventOutput) finishAll(kind string) {
	if o != nil {
		for b := range o.active {
			_ = b.finish(kind, nil)
		}
	}
}

// gzip.Reader pulls input while the protocol parser pushes fragments. Suspend
// only when it needs the next fragment. Feed, output, cancellation and close
// thus share one ordered execution path without an asynchronous output queue.
type gzipFeed struct {
	data         []byte
	eof, stopped bool
	needInput    func() bool
	next         func() (error, bool)
	stop         func()
}

func newGzipFeed(write func([]byte) error) *gzipFeed {
	g := &gzipFeed{}
	g.next, g.stop = iter.Pull(func(yield func(error) bool) {
		g.needInput = func() bool { return yield(nil) }
		r, err := gzip.NewReader(g)
		if err == nil {
			defer r.Close()
			buf := make([]byte, eventChunkSize)
			for err == nil {
				var n int
				n, err = r.Read(buf)
				if n > 0 {
					if e := write(buf[:n]); e != nil {
						err = e
						break
					}
				}
			}
			if err == io.EOF {
				err = nil
			}
		}
		if err != nil && !g.stopped {
			yield(err)
		}
	})
	return g
}
func (g *gzipFeed) Read(dst []byte) (int, error) {
	for len(g.data) == 0 {
		if g.stopped {
			return 0, io.ErrClosedPipe
		}
		if g.eof {
			return 0, io.EOF
		}
		if !g.needInput() {
			return 0, io.ErrClosedPipe
		}
	}
	n := copy(dst, g.data)
	g.data = g.data[n:]
	return n, nil
}
func (g *gzipFeed) feed(data []byte, eof bool) error {
	g.data = data
	g.eof = eof
	err, _ := g.next()
	g.data = nil
	return err
}
func (g *gzipFeed) close() { g.stopped = true; g.stop(); g.data = nil }

// EventSource lines may end in CR, LF or CRLF across arbitrary body chunks.
type eventSource struct {
	first, afterCR bool
	line, data     []byte
	name, id       string
	retry          uint64
	haveRetry      bool
}

func (s *eventSource) feed(b *eventBody, data []byte, start uint64) error {
	for i, c := range data {
		if s.afterCR {
			s.afterCR = false
			if c == '\n' {
				continue
			}
		}
		if c != '\r' && c != '\n' {
			if len(s.line) >= eventFieldLimit {
				return ErrHTTPEventLimit
			}
			s.line = append(s.line, c)
			continue
		}
		s.afterCR = c == '\r'
		line := s.line
		s.line = s.line[:0]
		if s.first {
			line = bytes.TrimPrefix(line, []byte{0xef, 0xbb, 0xbf})
			s.first = false
		}
		if len(line) == 0 {
			if len(s.data) > 0 {
				name := s.name
				if name == "" {
					name = "message"
				}
				meta := map[string]any{"event": name, "last_event_id": s.id}
				if s.haveRetry {
					meta["retry_ms"] = s.retry
				}
				b.emit("sse", s.data[:len(s.data)-1], meta, start+uint64(i)+1)
			}
			s.data = s.data[:0]
			s.name = ""
			continue
		}
		field, value, _ := bytes.Cut(line, []byte(":"))
		value = bytes.TrimPrefix(value, []byte(" "))
		switch string(field) {
		case "data":
			value = bytes.ToValidUTF8(value, []byte("\uFFFD"))
			if len(s.data)+len(value)+1 > eventFieldLimit {
				return ErrHTTPEventLimit
			}
			s.data = append(s.data, value...)
			s.data = append(s.data, '\n')
		case "event":
			s.name = strings.ToValidUTF8(string(value), "\uFFFD")
		case "id":
			if !bytes.ContainsRune(value, 0) {
				s.id = strings.ToValidUTF8(string(value), "\uFFFD")
			}
		case "retry":
			if n, err := strconv.ParseUint(string(value), 10, 64); err == nil {
				s.retry = n
				s.haveRetry = true
			}
		}
	}
	return nil
}
