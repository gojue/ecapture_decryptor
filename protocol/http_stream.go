// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// See LICENSE file for details.

package protocol

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"errors"
	"net/textproto"
	"strconv"

	"github.com/gojue/ecapture_decryptor/types"
)

// HTTPStreamParser assembles complete HTTP/1.x messages on one TLS connection.
// Its request queue keeps responses associated with pipelined requests.
type HTTPStreamParser struct {
	connectionInfo  types.ConnectionKey
	packetChan      chan *types.DecryptedPacket
	mu              sync.Mutex
	packetTime      time.Time
	requestStart    time.Time
	pendingReqs     []*http.Request
	currentReqData  bytes.Buffer
	currentRespData bytes.Buffer
	parseErr        error
	events          *http1Events
}

const maxHTTPMessageBytes = 16 << 20

func (p *HTTPStreamParser) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.parseErr
}

func NewHTTPStreamParser(ci types.ConnectionKey, packetChan chan *types.DecryptedPacket) *HTTPStreamParser {
	return &HTTPStreamParser{connectionInfo: ci, packetChan: packetChan}
}

func (p *HTTPStreamParser) SetPacketTime(t time.Time) {
	p.mu.Lock()
	p.packetTime = t
	p.mu.Unlock()
}

func (p *HTTPStreamParser) FeedRequest(data []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.parseErr != nil {
		return
	}
	if p.events != nil {
		p.parseErr = p.events.feed(true, data, p.packetTime)
		return
	}
	if p.currentReqData.Len()+len(data) > maxHTTPMessageBytes {
		p.parseErr = fmt.Errorf("HTTP/1.1 request exceeds %d-byte limit", maxHTTPMessageBytes)
		p.currentReqData.Reset()
		return
	}
	if p.currentReqData.Len() == 0 {
		p.requestStart = p.packetTime
	}
	p.currentReqData.Write(data)
	p.parseRequests()
}

func (p *HTTPStreamParser) FeedResponse(data []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.parseErr != nil {
		return
	}
	if p.events != nil {
		p.parseErr = p.events.feed(false, data, p.packetTime)
		return
	}
	if p.currentRespData.Len()+len(data) > maxHTTPMessageBytes {
		p.parseErr = fmt.Errorf("HTTP/1.1 response exceeds %d-byte limit", maxHTTPMessageBytes)
		p.currentRespData.Reset()
		return
	}
	p.currentRespData.Write(data)
	p.parseResponses(false)
}

func (p *HTTPStreamParser) parseRequests() {
	for p.currentReqData.Len() > 0 {
		data := p.currentReqData.Bytes()
		reader := bufio.NewReader(bytes.NewReader(data))
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		if _, err := io.ReadAll(req.Body); err != nil {
			_ = req.Body.Close()
			return // A split or chunked body has not finished.
		}
		_ = req.Body.Close()
		consumed := len(data) - reader.Buffered()
		if consumed <= 0 {
			return
		}
		raw := append([]byte(nil), data[:consumed]...)
		p.pendingReqs = append(p.pendingReqs, req)
		at := p.requestStart
		if at.IsZero() {
			at = time.Now()
		}
		if p.packetChan != nil {
			packet := types.NewDecryptedPacket(types.TransportProtocolTCP, strings.ToLower(req.Proto), "request", raw, at, p.connectionInfo)
			packet.WithMetadata("method", req.Method).
				WithMetadata("url", req.URL.String()).
				WithMetadata("host", req.Host).
				WithMetadata("headers", req.Header)
			p.packetChan <- packet
		}
		p.currentReqData.Next(consumed)
		p.requestStart = p.packetTime
	}
	p.parseResponses(false)
}

func (p *HTTPStreamParser) parseResponses(final bool) {
	for p.currentRespData.Len() > 0 && len(p.pendingReqs) > 0 {
		data := p.currentRespData.Bytes()
		reader := bufio.NewReader(bytes.NewReader(data))
		req := p.pendingReqs[0]
		resp, err := http.ReadResponse(reader, req)
		if err != nil {
			return
		}
		if resp.ContentLength < 0 && len(resp.TransferEncoding) == 0 && resp.Body != http.NoBody && !final {
			_ = resp.Body.Close()
			return // A close-delimited body is complete only at stream end.
		}
		if _, err := io.ReadAll(resp.Body); err != nil {
			_ = resp.Body.Close()
			return
		}
		_ = resp.Body.Close()
		consumed := len(data) - reader.Buffered()
		if consumed <= 0 {
			return
		}
		raw := append([]byte(nil), data[:consumed]...)
		at := p.packetTime
		if at.IsZero() {
			at = time.Now()
		}
		if p.packetChan != nil {
			packet := types.NewDecryptedPacket(types.TransportProtocolTCP, strings.ToLower(resp.Proto), "response", raw, at, p.connectionInfo)
			packet.WithMetadata("status", resp.StatusCode).
				WithMetadata("host", req.Host).
				WithMetadata("headers", resp.Header)
			p.packetChan <- packet
		}
		p.pendingReqs = p.pendingReqs[1:]
		p.currentRespData.Next(consumed)
	}
}

func (p *HTTPStreamParser) FinishHTTPEvents(reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.events != nil {
		if p.parseErr != nil {
			reason = "partial"
		}
		err := p.events.close(reason)
		if p.parseErr == nil {
			p.parseErr = err
		}
	}
}

func (p *HTTPStreamParser) Flush() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.events != nil {
		reason := ""
		if p.parseErr != nil {
			reason = "partial"
		}
		err := p.events.close(reason)
		if p.parseErr == nil {
			p.parseErr = err
		}
		return
	}
	if p.parseErr != nil {
		return
	}
	p.parseRequests()
	p.parseResponses(true)
}

type http1Exchange struct {
	id     uint64
	method string
}
type http1Events struct {
	output            *eventOutput
	request, response http1EventDirection
	pending           []http1Exchange
	next              uint64
	closed            bool
}
type http1EventDirection struct {
	buf                          bytes.Buffer
	body                         *eventBody
	remaining                    int64 // -1 for a close-delimited response
	chunked, chunkCRLF, trailers bool
	scan                         int
}

// Scan each header byte once, including a delimiter split across feeds.
func (d *http1EventDirection) block() ([]byte, error) {
	b := d.buf.Bytes()
	i := bytes.Index(b[d.scan:], []byte("\r\n\r\n"))
	if i < 0 {
		if len(b) > eventFieldLimit {
			return nil, ErrHTTPEventLimit
		}
		d.scan = max(0, len(b)-3)
		return nil, nil
	}
	n := d.scan + i + 4
	d.scan = 0
	if n > eventFieldLimit {
		return nil, ErrHTTPEventLimit
	}
	return d.buf.Next(n), nil
}
func (p *HTTPStreamParser) EnableHTTPEvents(limit int64) {
	p.events = &http1Events{output: newEventOutput(p.connectionInfo, p.packetChan, limit)}
}
func (e *http1Events) feed(client bool, data []byte, at time.Time) error {
	if e.closed {
		return io.ErrClosedPipe
	}
	d := &e.response
	if client {
		d = &e.request
	}
	for len(data) > 0 {
		n := min(len(data), eventChunkSize)
		if d.buf.Len()+n > maxHTTPMessageBytes {
			return ErrHTTPEventLimit
		}
		d.buf.Write(data[:n])
		data = data[n:]
		if err := e.parse(d, client, at); err != nil {
			return err
		}
		if client && e.response.buf.Len() > 0 {
			if err := e.parse(&e.response, false, at); err != nil {
				return err
			}
		}
	}
	return nil
}
func (e *http1Events) parse(d *http1EventDirection, client bool, at time.Time) error {
	for d.buf.Len() > 0 {
		if d.body == nil {
			if !client && len(e.pending) == 0 {
				return nil
			}
			head, err := d.block()
			if err != nil || head == nil {
				return err
			}
			if err = e.start(d, client, head, at); err != nil {
				return err
			}
			continue
		}
		d.body.at = at
		if d.chunked {
			if d.trailers {
				var h http.Header
				if bytes.HasPrefix(d.buf.Bytes(), []byte("\r\n")) {
					d.buf.Next(2)
				} else {
					block, err := d.block()
					if err != nil || block == nil {
						return err
					}
					fields, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(block))).ReadMIMEHeader()
					if err != nil {
						return err
					}
					h = http.Header(fields)
					for _, k := range []string{"Content-Length", "Transfer-Encoding", "Trailer"} {
						if _, ok := h[k]; ok {
							return errors.New("invalid HTTP/1 trailer")
						}
					}
				}
				if len(h) > 0 {
					if err := d.body.trailers(h); err != nil {
						return err
					}
				}
				if err := d.end(); err != nil {
					return err
				}
				continue
			}
			if d.chunkCRLF {
				if d.buf.Len() < 2 {
					return nil
				}
				if string(d.buf.Next(2)) != "\r\n" {
					return errors.New("invalid HTTP/1 chunk delimiter")
				}
				d.chunkCRLF = false
			}
			if d.remaining == 0 {
				b := d.buf.Bytes()
				i := bytes.Index(b, []byte("\r\n"))
				if i > 4096 || i < 0 && len(b) > 4096 {
					return ErrHTTPEventLimit
				}
				if i < 0 {
					return nil
				}
				line := d.buf.Next(i + 2)[:i]
				size, _, _ := bytes.Cut(line, []byte(";"))
				size = bytes.TrimRight(size, " \t")
				n, err := strconv.ParseUint(string(size), 16, 63)
				if err != nil {
					return errors.New("invalid HTTP/1 chunk size")
				}
				d.remaining = int64(n)
				if n == 0 {
					d.trailers = true
					continue
				}
			}
		}
		n := d.buf.Len()
		if d.remaining >= 0 {
			n = int(min(int64(n), d.remaining))
		}
		if err := d.body.write(d.buf.Next(n)); err != nil {
			return err
		}
		if d.remaining >= 0 {
			d.remaining -= int64(n)
		}
		if d.remaining == 0 {
			if d.chunked {
				d.chunkCRLF = true
			} else if err := d.end(); err != nil {
				return err
			}
		}
	}
	return nil
}
func (e *http1Events) start(d *http1EventDirection, client bool, head []byte, at time.Time) error {
	r := bufio.NewReader(bytes.NewReader(head))
	var proto string
	var h http.Header
	var id uint64
	var info bool
	meta := make(map[string]any)
	if client {
		req, err := http.ReadRequest(r)
		if err != nil {
			return err
		}
		if len(e.pending) >= 1024 {
			return ErrHTTPEventLimit
		}
		e.next++
		id = e.next
		e.pending = append(e.pending, http1Exchange{id, req.Method})
		proto = req.Proto
		h = req.Header
		d.chunked = len(req.TransferEncoding) > 0
		d.remaining = req.ContentLength
		meta["method"] = req.Method
		meta["url"] = req.URL.String()
		meta["host"] = req.Host
	} else {
		req := e.pending[0]
		id = req.id
		res, err := http.ReadResponse(r, &http.Request{Method: req.method})
		if err != nil {
			return err
		}
		proto = res.Proto
		h = res.Header
		d.chunked = len(res.TransferEncoding) > 0
		d.remaining = res.ContentLength
		if res.Body == http.NoBody {
			d.remaining = 0
			d.chunked = false
		}
		if res.StatusCode == 101 || req.method == "CONNECT" && res.StatusCode/100 == 2 {
			return errors.New("unsupported HTTP/1 protocol switch")
		}
		info = res.StatusCode/100 == 1
		meta["status"] = res.StatusCode
		if !info {
			e.pending = e.pending[1:]
		}
	}
	if d.chunked {
		d.remaining = 0
	}
	body, err := e.output.headers(strings.ToLower(proto), id, client, at, h, meta, info)
	if err != nil {
		return err
	}
	if info {
		return nil
	}
	d.body = body
	if !d.chunked && d.remaining == 0 {
		return d.end()
	}
	return nil
}
func (d *http1EventDirection) end() error {
	err := d.body.finish("end", nil)
	d.body = nil
	d.chunked = false
	d.trailers = false
	d.chunkCRLF = false
	d.remaining = 0
	d.scan = 0
	return err
}
func (e *http1Events) close(reason string) error {
	if e.closed {
		return nil
	}
	e.closed = true
	defer e.output.abort()
	defer func() { e.request = http1EventDirection{}; e.response = http1EventDirection{}; e.pending = nil }()
	if reason == "reset" {
		e.output.finishAll("reset")
		return nil
	}
	if reason == "partial" {
		return nil
	}
	if e.response.body != nil && !e.response.chunked && e.response.remaining < 0 {
		if reason == "capture_eof" {
			return io.ErrUnexpectedEOF
		}
		if err := e.response.end(); err != nil {
			return err
		}
	}
	if e.request.body != nil || e.response.body != nil || e.request.buf.Len() > 0 || e.response.buf.Len() > 0 {
		return io.ErrUnexpectedEOF
	}
	return nil
}
