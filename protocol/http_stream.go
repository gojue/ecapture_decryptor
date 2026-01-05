// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

// http_stream.go - HTTP/1.x stream parser
package protocol

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/cfc4n/ecapture_decryptor/types"
)

// HTTPStreamParser parses HTTP request/response streams
type HTTPStreamParser struct {
	connectionInfo types.ConnectionKey
	clientIP       string
	clientPort     uint32
	serverIP       string
	serverPort     uint32
	packetChan     chan *types.DecryptedPacket // 解密包输出通道
	mu             sync.Mutex
	pendingReq     *http.Request
	pendingReqRaw  []byte
	startTime      time.Time
	packetTime     time.Time // Time from pcap packet

	// For accumulating complete request/response data
	currentReqData  bytes.Buffer
	currentRespData bytes.Buffer
}

// NewHTTPStreamParser creates a new HTTP stream parser
func NewHTTPStreamParser(ci types.ConnectionKey, packetChan chan *types.DecryptedPacket) *HTTPStreamParser {
	return newHTTPStreamParserInternal(ci, packetChan)
}

// newHTTPStreamParserInternal 内部构造函数
func newHTTPStreamParserInternal(ci types.ConnectionKey, packetChan chan *types.DecryptedPacket) *HTTPStreamParser {

	return &HTTPStreamParser{
		connectionInfo: ci,
		clientIP:       ci.SrcIP.String(),
		clientPort:     uint32(ci.SrcPort),
		serverIP:       ci.DstIP.String(),
		serverPort:     uint32(ci.DstPort),
		packetChan:     packetChan,
		startTime:      time.Time{}, // Will be set on first request packet
		packetTime:     time.Time{}, // Will be set by SetPacketTime
	}
}

// SetPacketTime sets the packet timestamp from pcap
func (p *HTTPStreamParser) SetPacketTime(t time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.packetTime = t
}

// FeedRequest feeds request data
func (p *HTTPStreamParser) FeedRequest(data []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Accumulate request data
	p.currentReqData.Write(data)

	// Try to parse when we have enough data
	p.tryParseRequest()
}

// FeedResponse feeds response data
func (p *HTTPStreamParser) FeedResponse(data []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Accumulate response data
	p.currentRespData.Write(data)

	// Try to parse when we have enough data
	p.tryParseResponse()
}

// tryParseRequest tries to parse a complete HTTP request
func (p *HTTPStreamParser) tryParseRequest() {
	if p.currentReqData.Len() == 0 {
		return
	}

	data := p.currentReqData.Bytes()
	reader := bufio.NewReader(bytes.NewReader(data))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return // Not enough data or invalid
	}

	// Read request body
	bodyBytes := []byte{}
	if req.ContentLength > 0 {
		bodyBytes = make([]byte, req.ContentLength)
		n, err := io.ReadFull(req.Body, bodyBytes)
		if err != nil || n < int(req.ContentLength) {
			_ = req.Body.Close()
			return // Not enough body data
		}
	}
	_ = req.Body.Close()

	// Store the request
	p.pendingReq = req
	p.pendingReqRaw = bodyBytes
	// Use packet time from pcap, fallback to current time if not set
	if !p.packetTime.IsZero() {
		p.startTime = p.packetTime
	} else {
		p.startTime = time.Now()
	}

	// Output request packet
	if p.packetChan != nil {
		// Reconstruct the raw HTTP request
		var reqBuf bytes.Buffer
		fmt.Fprintf(&reqBuf, "%s %s %s\r\n", req.Method, req.URL.String(), req.Proto)
		_ = req.Header.Write(&reqBuf)
		reqBuf.WriteString("\r\n")
		reqBuf.Write(bodyBytes)

		packet := types.NewDecryptedPacket(types.TransportProtocolTCP, "http/1.1", "request", reqBuf.Bytes(), p.startTime, p.connectionInfo)
		packet.WithMetadata("method", req.Method).
			WithMetadata("url", req.URL.String()).
			WithMetadata("headers", req.Header)

		select {
		case p.packetChan <- packet:
		default:
			// Channel full, skip
		}
	}

	// Clear the request buffer - we've consumed this request
	remainingBytes := reader.Buffered()
	if remainingBytes > 0 {
		remaining := make([]byte, remainingBytes)
		_, _ = reader.Read(remaining)
		p.currentReqData.Reset()
		p.currentReqData.Write(remaining)
	} else {
		p.currentReqData.Reset()
	}
}

// tryParseResponse tries to parse a complete HTTP response
func (p *HTTPStreamParser) tryParseResponse() {
	if p.currentRespData.Len() == 0 || p.pendingReq == nil {
		return
	}

	data := p.currentRespData.Bytes()
	reader := bufio.NewReader(bytes.NewReader(data))
	resp, err := http.ReadResponse(reader, p.pendingReq)
	if err != nil {
		return // Not enough data or invalid
	}

	// Try to read the complete body
	// For chunked transfer encoding, we need to make sure all chunks are received
	bodyBytes, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// Check if we have all the data we need
	if readErr != nil {
		// For chunked encoding, io.ReadAll might return error if data is incomplete
		// Check if we have Content-Length or chunked transfer encoding
		if resp.ContentLength > 0 && int64(len(bodyBytes)) < resp.ContentLength {
			return // Not enough body data yet
		}
		// For chunked encoding without proper termination, we might have partial data
		// If error is unexpected EOF, wait for more data
		if readErr == io.ErrUnexpectedEOF {
			return
		}
		// Other errors - proceed with what we have if any
		if len(bodyBytes) == 0 {
			return
		}
	}

	// Additional check: for Content-Length responses, verify complete body
	if resp.ContentLength > 0 && int64(len(bodyBytes)) < resp.ContentLength {
		return // Still waiting for more data
	}

	// Store the response time from packet
	respTime := p.packetTime
	if respTime.IsZero() {
		respTime = time.Now()
	}

	// Output response packet
	if p.packetChan != nil {
		// Reconstruct the raw HTTP response
		var respBuf bytes.Buffer
		fmt.Fprintf(&respBuf, "%s %s\r\n", resp.Proto, resp.Status)
		_ = resp.Header.Write(&respBuf)
		respBuf.WriteString("\r\n")
		respBuf.Write(bodyBytes)

		packet := types.NewDecryptedPacket(types.TransportProtocolTCP, "http/1.1", "response", respBuf.Bytes(), respTime, p.connectionInfo)
		packet.WithMetadata("status", resp.StatusCode).
			WithMetadata("headers", resp.Header)

		select {
		case p.packetChan <- packet:
		default:
			// Channel full, skip
		}
	}

	// Clear for next request/response pair
	p.pendingReq = nil
	p.pendingReqRaw = nil

	// Clear the response buffer - we've consumed this response
	remainingBytes := reader.Buffered()
	if remainingBytes > 0 {
		remaining := make([]byte, remainingBytes)
		_, _ = reader.Read(remaining)
		p.currentRespData.Reset()
		p.currentRespData.Write(remaining)
	} else {
		p.currentRespData.Reset()
	}

	// Try to parse next request if we have data
	p.tryParseRequest()
}

// Flush processes any remaining data
func (p *HTTPStreamParser) Flush() {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Try to parse any remaining data
	p.tryParseRequest()
	p.tryParseResponse()
}
