// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

// protocol_websocket.go - WebSocket 协议解析器
package protocol

import (
	"bufio"
	"bytes"
	"compress/flate"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gojue/ecapture_decryptor/types"
)

const (
	WSOpcodeContinuation = 0x0
	WSOpcodeText         = 0x1
	WSOpcodeBinary       = 0x2
	WSOpcodeClose        = 0x8
	WSOpcodePing         = 0x9
	WSOpcodePong         = 0xA
	wsGUID               = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

var errWebSocket = errors.New("invalid WebSocket stream")

type wsDirection struct {
	buf                           bytes.Buffer
	message                       []byte
	opcode                        byte
	compressed, closed, noContext bool
	dict                          []byte
	at                            time.Time
}

// WebSocketStreamParser validates an HTTP/1 upgrade and emits complete messages
// and control frames. Only the active fragmented message and a 32 KiB DEFLATE
// dictionary are retained per direction; sends apply caller backpressure.
type WebSocketStreamParser struct {
	addr                               types.ConnectionKey
	packetChan                         chan *types.DecryptedPacket
	mu                                 sync.Mutex
	sides                              [2]wsDirection
	handshakeComplete, deflate, closed bool
	request                            *http.Request
	requestRaw                         []byte
	requestTime, packetTime            time.Time
	httpFallback                       *HTTPStreamParser
	parseErr                           error
}

func NewWebSocketStreamParser(addr types.ConnectionKey, ch chan *types.DecryptedPacket) *WebSocketStreamParser {
	return &WebSocketStreamParser{addr: addr, packetChan: ch}
}

func headerToken(h http.Header, name, token string) bool {
	for _, value := range h.Values(name) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func IsWebSocketUpgrade(data []byte) bool {
	n := bytes.Index(data, []byte("\r\n\r\n"))
	if n < 0 || n+4 > eventFieldLimit {
		return false
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data[:n+4])))
	return err == nil && headerToken(req.Header, "Upgrade", "websocket")
}

func (p *WebSocketStreamParser) SetPacketTime(t time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.packetTime = t
	if p.httpFallback != nil {
		p.httpFallback.SetPacketTime(t)
	}
}
func (p *WebSocketStreamParser) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.parseErr == nil && p.httpFallback != nil {
		return p.httpFallback.Err()
	}
	return p.parseErr
}
func (p *WebSocketStreamParser) FeedRequest(data []byte)  { p.feed(data, true) }
func (p *WebSocketStreamParser) FeedResponse(data []byte) { p.feed(data, false) }
func (p *WebSocketStreamParser) feed(data []byte, client bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.parseErr != nil || p.closed {
		return
	}
	if p.httpFallback != nil {
		p.feedFallback(data, client)
		return
	}
	d := &p.sides[http3Side(client)]
	for len(data) > 0 {
		n := min(len(data), eventChunkSize)
		if d.buf.Len()+n > maxHTTPMessageBytes+14 {
			p.fail(ErrHTTPEventLimit)
			return
		}
		d.buf.Write(data[:n])
		data = data[n:]
		if !p.handshakeComplete {
			if err := p.handshake(); err != nil {
				p.fail(err)
				return
			}
			if p.httpFallback != nil {
				p.feedFallback(data, client)
				return
			}
		}
		if p.handshakeComplete {
			for i := range p.sides {
				if err := p.frames(&p.sides[i], i == 0); err != nil {
					p.fail(err)
					return
				}
			}
		}
	}
}
func (p *WebSocketStreamParser) feedFallback(data []byte, client bool) {
	if client {
		p.httpFallback.FeedRequest(data)
	} else {
		p.httpFallback.FeedResponse(data)
	}
}
func (p *WebSocketStreamParser) fallback() {
	p.httpFallback = NewHTTPStreamParser(p.addr, p.packetChan)
	p.httpFallback.SetPacketTime(p.packetTime)
	// This rejected/non-WebSocket request must not recursively upgrade itself.
	p.httpFallback.skipWebSocket = true
	p.httpFallback.FeedRequest(p.requestRaw)
	p.httpFallback.skipWebSocket = false
	p.httpFallback.FeedRequest(p.sides[0].buf.Bytes())
	p.httpFallback.FeedResponse(p.sides[1].buf.Bytes())
	p.requestRaw = nil
	p.request = nil
	p.sides = [2]wsDirection{}
}
func wsHeader(buf *bytes.Buffer) ([]byte, error) {
	n := bytes.Index(buf.Bytes(), []byte("\r\n\r\n"))
	if n < 0 {
		if buf.Len() > eventFieldLimit {
			return nil, ErrHTTPEventLimit
		}
		return nil, nil
	}
	if n+4 > eventFieldLimit {
		return nil, ErrHTTPEventLimit
	}
	return buf.Bytes()[:n+4], nil
}
func (p *WebSocketStreamParser) handshake() error {
	if p.request == nil {
		raw, err := wsHeader(&p.sides[0].buf)
		if err != nil || raw == nil {
			return err
		}
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
		if err != nil {
			return errWebSocket
		}
		p.request = req
		p.requestRaw = bytes.Clone(raw)
		p.requestTime = p.packetTime
		p.sides[0].buf.Next(len(raw))
		if !headerToken(req.Header, "Upgrade", "websocket") {
			p.fallback()
			return nil
		}
		key, err := base64.StdEncoding.DecodeString(req.Header.Get("Sec-WebSocket-Key"))
		if err != nil || len(key) != 16 || len(req.Header.Values("Sec-WebSocket-Key")) != 1 ||
			req.Method != "GET" || req.Proto != "HTTP/1.1" || req.Host == "" ||
			!headerToken(req.Header, "Connection", "upgrade") || req.Header.Get("Sec-WebSocket-Version") != "13" ||
			req.ContentLength != 0 || len(req.TransferEncoding) != 0 {
			return errWebSocket
		}
	}
	raw, err := wsHeader(&p.sides[1].buf)
	if err != nil || raw == nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), p.request)
	if err != nil {
		return errWebSocket
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		p.fallback()
		return nil
	}
	if resp.Proto != "HTTP/1.1" || !headerToken(resp.Header, "Upgrade", "websocket") ||
		!headerToken(resp.Header, "Connection", "upgrade") || len(resp.Header.Values("Sec-WebSocket-Accept")) != 1 ||
		resp.Header.Get("Sec-WebSocket-Accept") != computeWebSocketAccept(p.request.Header.Get("Sec-WebSocket-Key")) {
		return errWebSocket
	}
	if sub := resp.Header.Get("Sec-WebSocket-Protocol"); sub != "" {
		found := false
		for _, v := range p.request.Header.Values("Sec-WebSocket-Protocol") {
			for _, offered := range strings.Split(v, ",") {
				found = found || strings.TrimSpace(offered) == sub
			}
		}
		if !found || len(resp.Header.Values("Sec-WebSocket-Protocol")) != 1 {
			return errWebSocket
		}
	}
	if err := p.negotiateDeflate(resp.Header); err != nil {
		return err
	}
	p.handshakeComplete = true
	p.emit(true, "upgrade", p.requestRaw, p.requestTime, map[string]any{"method": p.request.Method, "url": p.request.URL.String(), "headers": p.request.Header.Clone(), "upgrade": "websocket"})
	p.emit(false, "upgrade", raw, p.packetTime, map[string]any{"status": resp.StatusCode, "headers": resp.Header.Clone(), "upgrade": "websocket"})
	p.sides[1].buf.Next(len(raw))
	p.requestRaw = nil
	p.request = nil
	return nil
}

func computeWebSocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// The agreed response controls dictionaries. A receiver may always use a
// 32 KiB window, including when a smaller sender window was negotiated.
func wsDeflateParams(extension string, offer bool) (map[string]string, error) {
	parts := strings.Split(extension, ";")
	if strings.TrimSpace(parts[0]) != "permessage-deflate" {
		return nil, errWebSocket
	}
	params := make(map[string]string)
	for _, part := range parts[1:] {
		k, v, has := strings.Cut(strings.TrimSpace(part), "=")
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if strings.HasPrefix(v, "\"") || strings.HasSuffix(v, "\"") {
			if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
				return nil, errWebSocket
			}
			v = v[1 : len(v)-1]
		}
		if _, exists := params[k]; exists {
			return nil, errWebSocket
		}
		switch k {
		case "client_no_context_takeover", "server_no_context_takeover":
			if has {
				return nil, errWebSocket
			}
		case "client_max_window_bits", "server_max_window_bits":
			if !has && offer && k == "client_max_window_bits" {
				break
			}
			n, err := strconv.Atoi(v)
			if !has || err != nil || n < 8 || n > 15 || strconv.Itoa(n) != v {
				return nil, errWebSocket
			}
		default:
			return nil, errWebSocket
		}
		params[k] = v
	}
	return params, nil
}
func (p *WebSocketStreamParser) negotiateDeflate(h http.Header) error {
	selected := strings.TrimSpace(strings.Join(h.Values("Sec-WebSocket-Extensions"), ","))
	if selected == "" {
		return nil
	}
	agreed, err := wsDeflateParams(selected, false)
	if err != nil {
		return err
	}
	matched := false
	for _, offer := range strings.Split(strings.Join(p.request.Header.Values("Sec-WebSocket-Extensions"), ","), ",") {
		params, err := wsDeflateParams(offer, true)
		if err != nil {
			continue
		}
		if _, ok := agreed["client_max_window_bits"]; ok {
			if _, ok = params["client_max_window_bits"]; !ok {
				continue
			}
		}
		if v, ok := params["server_max_window_bits"]; ok {
			n, _ := strconv.Atoi(v)
			a, _ := strconv.Atoi(agreed["server_max_window_bits"])
			if a == 0 || a > n {
				continue
			}
		}
		if _, ok := params["server_no_context_takeover"]; ok {
			if _, ok = agreed["server_no_context_takeover"]; !ok {
				continue
			}
		}
		matched = true
		break
	}
	if !matched {
		return errWebSocket
	}
	p.deflate = true
	_, p.sides[0].noContext = agreed["client_no_context_takeover"]
	_, p.sides[1].noContext = agreed["server_no_context_takeover"]
	return nil
}

func (p *WebSocketStreamParser) frames(d *wsDirection, client bool) error {
	for d.buf.Len() >= 2 {
		h := d.buf.Bytes()
		fin := h[0]&0x80 != 0
		compressed := h[0]&0x40 != 0
		op := h[0] & 15
		masked := h[1]&0x80 != 0
		n := uint64(h[1] & 127)
		header := 2
		control := op >= 8
		if d.closed || h[0]&0x30 != 0 || masked != client ||
			(op != 0 && op != 1 && op != 2 && op != 8 && op != 9 && op != 10) ||
			compressed && (!p.deflate || control || op == 0) || control && (!fin || n > 125) {
			return errWebSocket
		}
		if n == 126 {
			if len(h) < 4 {
				return nil
			}
			n = uint64(binary.BigEndian.Uint16(h[2:4]))
			header = 4
			if n < 126 {
				return errWebSocket
			}
		} else if n == 127 {
			if len(h) < 10 {
				return nil
			}
			n = binary.BigEndian.Uint64(h[2:10])
			header = 10
			if n < 65536 || n>>63 != 0 {
				return errWebSocket
			}
		}
		if n > maxHTTPMessageBytes {
			return ErrHTTPEventLimit
		}
		if masked {
			header += 4
		}
		if uint64(len(h)) < uint64(header)+n {
			return nil
		}
		payload := bytes.Clone(h[header : header+int(n)])
		if masked {
			for i := range payload {
				payload[i] ^= h[header-4+i%4]
			}
		}
		d.buf.Next(header + int(n))
		if control {
			meta := map[string]any{"opcode": op, "opcode_name": map[byte]string{8: "close", 9: "ping", 10: "pong"}[op], "is_client": client, "data_length": len(payload)}
			if op == WSOpcodeClose {
				if len(payload) == 1 {
					return errWebSocket
				}
				if len(payload) >= 2 {
					code := binary.BigEndian.Uint16(payload)
					if !validWSClose(code) || !utf8.Valid(payload[2:]) {
						return errWebSocket
					}
					meta["close_code"] = code
					meta["close_reason"] = string(payload[2:])
				}
				d.closed = true
				d.message = nil
				d.opcode = 0
				d.dict = nil
			}
			p.emit(client, "control", payload, p.packetTime, meta)
			continue
		}
		if op == 0 {
			if d.opcode == 0 {
				return errWebSocket
			}
		} else {
			if d.opcode != 0 {
				return errWebSocket
			}
			d.opcode = op
			d.compressed = compressed
			d.at = p.packetTime
		}
		if len(payload) > maxHTTPMessageBytes-len(d.message) {
			return ErrHTTPEventLimit
		}
		d.message = append(d.message, payload...)
		if !fin {
			continue
		}
		data := d.message
		if d.compressed {
			var err error
			data, err = inflateWebSocket(data, d.dict)
			if err != nil {
				return err
			}
			if !d.noContext {
				d.dict = wsDictionary(d.dict, data)
			}
		}
		if d.opcode == WSOpcodeText && !utf8.Valid(data) {
			return errWebSocket
		}
		name := "binary"
		if d.opcode == WSOpcodeText {
			name = "text"
		}
		p.emit(client, "message", data, d.at, map[string]any{"opcode": d.opcode, "opcode_name": name, "is_client": client, "data_length": len(data), "compressed": d.compressed})
		d.message = nil
		d.opcode = 0
	}
	return nil
}
func validWSClose(code uint16) bool {
	return code >= 3000 && code <= 4999 || code >= 1000 && code <= 1014 && code != 1004 && code != 1005 && code != 1006
}
func wsDictionary(dict, data []byte) []byte {
	if len(data) >= 32768 {
		return bytes.Clone(data[len(data)-32768:])
	}
	keep := min(len(dict), 32768-len(data))
	return append(bytes.Clone(dict[len(dict)-keep:]), data...)
}
func inflateWebSocket(data, dict []byte) ([]byte, error) {
	// Restore SYNC_FLUSH and supply a final empty block. A byte reader avoids
	// read-ahead across BFINAL blocks, which RFC 7692 also permits in a message.
	r := bytes.NewReader(append(bytes.Clone(data), 0, 0, 255, 255, 1, 0, 0, 255, 255))
	var out []byte
	for r.Len() > 0 {
		z := flate.NewReaderDict(r, dict)
		part, err := io.ReadAll(io.LimitReader(z, int64(maxHTTPMessageBytes-len(out)+1)))
		_ = z.Close()
		if len(part) > maxHTTPMessageBytes-len(out) {
			return nil, ErrHTTPEventLimit
		}
		if err != nil {
			return nil, errWebSocket
		}
		out = append(out, part...)
		dict = wsDictionary(dict, part)
	}
	return out, nil
}
func (p *WebSocketStreamParser) emit(client bool, kind string, data []byte, at time.Time, meta map[string]any) {
	if p.packetChan == nil {
		return
	}
	direction := "response"
	if client {
		direction = "request"
	}
	packet := types.NewDecryptedPacket(types.TransportProtocolTCP, "websocket", direction, bytes.Clone(data), at, p.addr)
	for k, v := range meta {
		packet.WithMetadata(k, v)
	}
	packet.WithMetadata("kind", kind)
	p.packetChan <- packet
}
func (p *WebSocketStreamParser) fail(err error) {
	p.parseErr = err
	p.sides = [2]wsDirection{}
	p.requestRaw = nil
	p.request = nil
}
func (p *WebSocketStreamParser) Flush() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	if p.httpFallback != nil {
		p.httpFallback.Flush()
		return
	}
	if p.parseErr == nil {
		if !p.handshakeComplete || p.sides[0].buf.Len()+p.sides[1].buf.Len() > 0 || p.sides[0].opcode != 0 || p.sides[1].opcode != 0 {
			p.parseErr = io.ErrUnexpectedEOF
		}
	}
	p.sides = [2]wsDirection{}
	p.request = nil
	p.requestRaw = nil
}
func (p *WebSocketStreamParser) Close() error { p.Flush(); return p.Err() }
func (p *WebSocketStreamParser) IsWebSocket() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.handshakeComplete
}

var _ types.StreamParserInterface = (*WebSocketStreamParser)(nil)
