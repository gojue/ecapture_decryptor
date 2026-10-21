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

func (p *HTTPStreamParser) Flush() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.parseErr != nil {
		return
	}
	p.parseRequests()
	p.parseResponses(true)
}
