// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package protocol

import (
	"bytes"
	"encoding/base64"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gojue/ecapture_decryptor/types"
)

var errDoH = errors.New("invalid DNS over HTTPS exchange")

// Explicit DoH mode reuses HTTP framing/QPACK and its per-stream lifecycle,
// but emits complete DNS wire messages rather than HTTP body fragments.
type dnsHTTP struct {
	pending   map[uint64][]byte
	responses map[uint64]dohReply
	canceled  map[uint64]bool
	bytes     int // Pending queries and incomplete HTTP bodies share one budget.
}
type dohReply struct {
	data   []byte
	proto  string
	at     time.Time
	status int
}
type dohMessage struct {
	headers      http.Header
	method, path string
	status       int
	data         []byte
}

func newDNSHTTP() *dnsHTTP {
	return &dnsHTTP{pending: make(map[uint64][]byte), responses: make(map[uint64]dohReply), canceled: make(map[uint64]bool)}
}
func (p *HTTPStreamParser) EnableDNSOverHTTP() {
	p.EnableHTTPEvents(0)
	p.events.output.doh = newDNSHTTP()
}
func (p *HTTP2StreamParser) EnableDNSOverHTTP() {
	p.EnableHTTPEvents(0)
	p.events.output.doh = newDNSHTTP()
}
func (p *HTTP3StreamParser) EnableDNSOverHTTP() {
	p.EnableHTTPEvents(0)
	p.events.doh = newDNSHTTP()
}
func (b *eventBody) startDoH(h http.Header, meta map[string]any) error {
	if _, push := meta["push_id"]; push {
		return errDoH
	}
	b.doh = &dohMessage{headers: h.Clone()}
	b.doh.method, _ = meta["method"].(string)
	b.doh.path, _ = meta["path"].(string)
	if b.doh.path == "" {
		b.doh.path, _ = meta["url"].(string)
	}
	b.doh.status, _ = meta["status"].(int)
	coding := strings.TrimSpace(h.Get("Content-Encoding"))
	if coding != "" && !strings.EqualFold(coding, "identity") {
		return errDoH
	}
	return nil
}
func (b *eventBody) writeDoH(data []byte) error {
	if len(data) > 65535-len(b.doh.data) || len(data) > (4<<20)-b.out.doh.bytes {
		return ErrHTTPEventLimit
	}
	b.doh.data = append(b.doh.data, data...)
	b.out.doh.bytes += len(data)
	b.offset += uint64(len(data))
	return nil
}
func dohMedia(h http.Header) bool {
	media, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	return err == nil && media == "application/dns-message" && len(params) == 0 && len(h.Values("Content-Type")) == 1
}
func (b *eventBody) finishDoH(kind string) error {
	d, o := b.doh, b.out.doh
	defer func() { o.bytes -= len(d.data); b.doh = nil }()
	if o.canceled[b.id] {
		return nil
	}
	if kind != "end" {
		o.bytes -= len(o.pending[b.id]) + len(o.responses[b.id].data)
		delete(o.pending, b.id)
		delete(o.responses, b.id)
		return nil
	}
	wire := d.data
	if b.client {
		switch d.method {
		case "GET":
			if len(wire) != 0 {
				return errDoH
			}
			u, err := url.ParseRequestURI(d.path)
			if err != nil {
				return errDoH
			}
			q, err := url.ParseQuery(u.RawQuery)
			if err != nil || len(q["dns"]) != 1 || q.Get("dns") == "" {
				return errDoH
			}
			value := q.Get("dns")
			if len(value) > base64.RawURLEncoding.EncodedLen(65535) {
				return ErrHTTPEventLimit
			}
			wire, err = base64.RawURLEncoding.Strict().DecodeString(value)
			if err != nil || base64.RawURLEncoding.EncodeToString(wire) != value {
				return errDoH
			}
		case "POST":
			if !dohMedia(d.headers) {
				return errDoH
			}
		default:
			return errDoH
		}
	} else if d.status < 200 || d.status >= 300 {
		// Preserve HTTP failures separately; a server-first completion waits for
		// its HTTP request so it cannot leave a stale pending DNS query.
		if _, ok := o.pending[b.id]; !ok {
			if _, exists := o.responses[b.id]; exists {
				return errDoH
			}
			if len(o.responses) >= 1024 {
				return ErrHTTPEventLimit
			}
			o.responses[b.id] = dohReply{proto: b.proto, at: b.at, status: d.status}
			return nil
		}
		o.bytes -= len(o.pending[b.id])
		delete(o.pending, b.id)
		b.emitDoHError(d.status)
		return nil
	} else if !dohMedia(d.headers) {
		return errDoH
	}
	decoded, err := decodeDNS(wire)
	if err != nil {
		return err
	}
	if decoded.opcode != 0 || decoded.zone || b.client && decoded.questions == "" {
		return errDoH
	}
	meta := decoded.meta
	if meta["qr"] == b.client {
		return errDoH
	}
	if b.client {
		if _, exists := o.pending[b.id]; exists {
			return errDoH
		}
		if len(o.pending) >= 1024 || len(wire) > (4<<20)-o.bytes {
			return ErrHTTPEventLimit
		}
		o.pending[b.id] = bytes.Clone(wire)
		o.bytes += len(wire)
	} else {
		query := o.pending[b.id]
		if query == nil {
			if _, exists := o.responses[b.id]; exists {
				return errDoH
			}
			if len(o.responses) >= 1024 || len(wire) > (4<<20)-o.bytes {
				return ErrHTTPEventLimit
			}
			o.responses[b.id] = dohReply{data: bytes.Clone(wire), proto: b.proto, at: b.at, status: d.status}
			o.bytes += len(wire)
			return nil
		}
		if !dnsQuestionsMatch(query, wire) {
			return errDoH
		}
		o.bytes -= len(query)
		delete(o.pending, b.id)
		meta["matched"] = true
	}
	b.emitDNS(wire, meta)
	if b.client {
		if reply, ok := o.responses[b.id]; ok {
			if reply.status >= 200 && reply.status < 300 && !dnsQuestionsMatch(wire, reply.data) {
				return errDoH
			}
			o.bytes -= len(reply.data) + len(o.pending[b.id])
			delete(o.responses, b.id)
			delete(o.pending, b.id)
			response := &eventBody{out: b.out, proto: reply.proto, at: reply.at, id: b.id}
			if reply.status < 200 || reply.status >= 300 {
				response.emitDoHError(reply.status)
				return nil
			}
			meta, err := decodeDNSMessage(reply.data)
			if err != nil {
				return err
			}
			meta["matched"] = true
			response.emitDNS(reply.data, meta)
		}
	}
	return nil
}
func (b *eventBody) emitDNS(wire []byte, meta map[string]any) {
	direction := "response"
	if b.client {
		direction = "request"
	}
	packet := types.NewDecryptedPacket(b.out.conn.Proto, "dns", direction, bytes.Clone(wire), b.at, b.out.conn)
	for k, v := range meta {
		packet.WithMetadata(k, v)
	}
	packet.WithMetadata("kind", "message").WithMetadata("transport", "doh").WithMetadata("http_protocol", b.proto).WithMetadata("stream_id", b.id).WithMetadata("request_id", b.id)
	if b.out.ch != nil {
		b.out.ch <- packet
	}
}

func (o *eventOutput) incompleteDoH() bool {
	return o != nil && o.doh != nil && (len(o.doh.pending) > 0 || len(o.doh.responses) > 0)
}

func (b *eventBody) emitDoHError(status int) {
	packet := types.NewDecryptedPacket(b.out.conn.Proto, "dns", "response", nil, b.at, b.out.conn)
	packet.WithMetadata("transport", "doh").WithMetadata("kind", "http_error").WithMetadata("stream_id", b.id).WithMetadata("request_id", b.id).WithMetadata("http_protocol", b.proto).WithMetadata("status", status)
	if b.out.ch != nil {
		b.out.ch <- packet
	}
}

func (o *eventOutput) resetDoH(id uint64) error {
	if o == nil || o.doh == nil {
		return nil
	}
	d := o.doh
	if !d.canceled[id] && len(d.canceled) >= 1024 {
		return ErrHTTPEventLimit
	}
	d.canceled[id] = true
	d.bytes -= len(d.pending[id]) + len(d.responses[id].data)
	delete(d.pending, id)
	delete(d.responses, id)
	return nil
}
