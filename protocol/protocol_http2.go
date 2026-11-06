// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

// protocol_http2.go - HTTP/2 协议解析器
package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"errors"
	"strconv"

	"github.com/gojue/ecapture_decryptor/types"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// HTTP/2 连接前言
var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

const maxHTTP2BufferedBytes = 16 << 20

// HTTP2StreamParser HTTP/2 流解析器
type HTTP2StreamParser struct {
	addr       types.ConnectionKey
	clientIP   string
	clientPort uint32
	serverIP   string
	serverPort uint32
	packetChan chan *types.DecryptedPacket // 解密包输出通道
	mu         sync.Mutex

	// HPACK 解码器 - 每个方向独立
	clientDecoder *hpack.Decoder
	serverDecoder *hpack.Decoder

	// 流状态
	streams map[uint32]*http2Stream

	// 时间戳
	packetTime time.Time

	// 跳过连接前言
	clientPrefaceReceived bool
	serverPrefaceReceived bool

	// 数据缓冲
	clientBuffer bytes.Buffer
	serverBuffer bytes.Buffer

	// 标记是否为HTTP/2连接
	events   *http2Events
	isHTTP2  bool
	parseErr error
}

func (p *HTTP2StreamParser) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.parseErr
}

// http2Stream HTTP/2 流
type http2Stream struct {
	id           uint32
	request      *http2Request
	response     *http2Response
	startTime    time.Time
	responseTime time.Time
}

// http2Request HTTP/2 请求
type http2Request struct {
	method      string
	path        string
	scheme      string
	authority   string
	headers     http.Header
	body        bytes.Buffer
	endStream   bool
	headersDone bool
	outputted   bool // 标记是否已经输出，避免重复
	headerBlock bytes.Buffer
}

// http2Response HTTP/2 响应
type http2Response struct {
	status      int
	headers     http.Header
	body        bytes.Buffer
	endStream   bool
	headersDone bool
	headerBlock bytes.Buffer
}

// NewHTTP2StreamParser 创建 HTTP/2 流解析器
func NewHTTP2StreamParser(ci types.ConnectionKey, packetChan chan *types.DecryptedPacket) *HTTP2StreamParser {
	return newHTTP2StreamParserInternal(ci, packetChan)
}

// newHTTP2StreamParserInternal 内部构造函数
func newHTTP2StreamParserInternal(ci types.ConnectionKey, packetChan chan *types.DecryptedPacket) *HTTP2StreamParser {

	return &HTTP2StreamParser{
		addr:          ci,
		clientIP:      ci.SrcIP.String(),
		clientPort:    uint32(ci.SrcPort),
		serverIP:      ci.DstIP.String(),
		serverPort:    uint32(ci.DstPort),
		packetChan:    packetChan,
		clientDecoder: hpack.NewDecoder(4096, nil),
		serverDecoder: hpack.NewDecoder(4096, nil),
		streams:       make(map[uint32]*http2Stream),
	}
}

// IsHTTP2 检测数据是否为HTTP/2
func IsHTTP2(data []byte) bool {
	return len(data) >= len(http2Preface) && bytes.HasPrefix(data, http2Preface)
}

// SetPacketTime 设置数据包时间戳
func (p *HTTP2StreamParser) SetPacketTime(t time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.packetTime = t
}

// FeedRequest 处理客户端数据（请求）
func (p *HTTP2StreamParser) FeedRequest(data []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.parseErr != nil {
		return
	}
	if p.events != nil {
		p.parseErr = p.feedHTTPEvents(data, true)
		return
	}
	if p.clientBuffer.Len()+len(data) > maxHTTP2BufferedBytes {
		p.parseErr = fmt.Errorf("HTTP/2 client frame buffer exceeds %d-byte limit", maxHTTP2BufferedBytes)
		p.clientBuffer.Reset()
		return
	}

	// 检测HTTP/2连接前言
	if !p.clientPrefaceReceived {
		p.clientBuffer.Write(data)
		bufData := p.clientBuffer.Bytes()

		if len(bufData) >= len(http2Preface) {
			if bytes.HasPrefix(bufData, http2Preface) {
				p.isHTTP2 = true
				p.clientPrefaceReceived = true
				// 跳过连接前言
				remaining := bufData[len(http2Preface):]
				p.clientBuffer.Reset()
				p.clientBuffer.Write(remaining)
			} else {
				// 不是HTTP/2
				return
			}
		} else {
			// 数据不足，等待更多
			return
		}
	} else {
		p.clientBuffer.Write(data)
	}

	if !p.isHTTP2 {
		return
	}

	// 解析客户端帧
	p.parseFrames(&p.clientBuffer, true)
}

// FeedResponse 处理服务端数据（响应）
func (p *HTTP2StreamParser) FeedResponse(data []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.parseErr != nil {
		return
	}
	if p.events != nil {
		p.parseErr = p.feedHTTPEvents(data, false)
		return
	}
	if p.serverBuffer.Len()+len(data) > maxHTTP2BufferedBytes {
		p.parseErr = fmt.Errorf("HTTP/2 server frame buffer exceeds %d-byte limit", maxHTTP2BufferedBytes)
		p.serverBuffer.Reset()
		return
	}

	if !p.isHTTP2 {
		return
	}

	p.serverBuffer.Write(data)

	// 服务端可能发送SETTINGS帧作为连接前言的一部分
	if !p.serverPrefaceReceived {
		// HTTP/2服务端前言是一个SETTINGS帧
		// 但我们直接开始解析帧即可
		p.serverPrefaceReceived = true
	}

	// 解析服务端帧
	p.parseFrames(&p.serverBuffer, false)
}

// parseFrames 解析HTTP/2帧
func (p *HTTP2StreamParser) parseFrames(buf *bytes.Buffer, isClient bool) {
	for {
		// HTTP/2帧头部: 9字节
		// Length (3 bytes) + Type (1 byte) + Flags (1 byte) + Reserved (1 bit) + Stream ID (31 bits)
		if buf.Len() < 9 {
			return
		}

		header := buf.Bytes()[:9]
		length := (int(header[0]) << 16) | (int(header[1]) << 8) | int(header[2])
		frameType := http2.FrameType(header[3])
		flags := http2.Flags(header[4])
		streamID := binary.BigEndian.Uint32(header[5:9]) & 0x7FFFFFFF

		// 检查是否有完整的帧
		totalLen := 9 + length
		if buf.Len() < totalLen {
			return
		}

		// 读取完整帧
		frameData := make([]byte, totalLen)
		_, _ = buf.Read(frameData)
		payload := frameData[9:]

		// 处理帧
		p.handleFrame(frameType, flags, streamID, payload, isClient)
	}
}

// handleFrame 处理单个HTTP/2帧
func (p *HTTP2StreamParser) handleFrame(frameType http2.FrameType, flags http2.Flags, streamID uint32, payload []byte, isClient bool) {
	switch frameType {
	case http2.FrameHeaders:
		p.handleHeadersFrame(streamID, flags, payload, isClient)
	case http2.FrameContinuation:
		p.handleContinuationFrame(streamID, flags, payload, isClient)
	case http2.FrameData:
		p.handleDataFrame(streamID, flags, payload, isClient)
	case http2.FrameSettings:
		// SETTINGS帧 - 可能更新HPACK表大小
		p.handleSettingsFrame(flags, payload, isClient)
	case http2.FrameWindowUpdate:
		// 流量控制，忽略
	case http2.FramePing:
		// Ping帧，忽略
	case http2.FrameGoAway:
		// 连接关闭
	case http2.FrameRSTStream:
		// 流重置
	case http2.FramePriority:
		// 优先级，忽略
	case http2.FramePushPromise:
		// 服务端推送
	}
}

// handleSettingsFrame 处理SETTINGS帧
func (p *HTTP2StreamParser) handleSettingsFrame(flags http2.Flags, payload []byte, isClient bool) {
	if flags&http2.FlagSettingsAck != 0 {
		// ACK帧，忽略
		return
	}

	// 解析设置参数
	for len(payload) >= 6 {
		id := binary.BigEndian.Uint16(payload[:2])
		value := binary.BigEndian.Uint32(payload[2:6])
		payload = payload[6:]

		// SETTINGS_HEADER_TABLE_SIZE (0x1)
		if id == 0x1 {
			if isClient {
				p.serverDecoder.SetMaxDynamicTableSize(value)
			} else {
				p.clientDecoder.SetMaxDynamicTableSize(value)
			}
		}
	}
}

// handleHeadersFrame 处理HEADERS帧
func (p *HTTP2StreamParser) handleHeadersFrame(streamID uint32, flags http2.Flags, payload []byte, isClient bool) {
	if streamID == 0 {
		return
	}

	// 检查是否有填充
	var headerBlock []byte
	if flags&http2.FlagHeadersPadded != 0 && len(payload) > 0 {
		padLen := int(payload[0])
		if len(payload) < 1+padLen {
			return
		}
		payload = payload[1 : len(payload)-padLen]
	}

	// 检查是否有优先级
	if flags&http2.FlagHeadersPriority != 0 && len(payload) >= 5 {
		payload = payload[5:]
	}

	headerBlock = payload

	// 获取或创建流
	stream, ok := p.streams[streamID]
	if !ok {
		stream = &http2Stream{
			id:        streamID,
			startTime: p.packetTime,
		}
		p.streams[streamID] = stream
	}

	if isClient {
		if stream.request == nil {
			stream.request = &http2Request{
				headers: make(http.Header),
			}
		}
		if stream.request.headerBlock.Len()+len(headerBlock) > maxHTTP2BufferedBytes {
			p.parseErr = fmt.Errorf("HTTP/2 request headers exceed %d-byte limit", maxHTTP2BufferedBytes)
			return
		}
		stream.request.headerBlock.Write(headerBlock)
		if flags&http2.FlagHeadersEndHeaders != 0 {
			p.decodeHeaders(stream.request.headerBlock.Bytes(), stream.request.headers, true)
			stream.request.headerBlock.Reset()
			stream.request.headersDone = true
			p.extractRequestPseudoHeaders(stream.request)
		}
		if flags&http2.FlagHeadersEndStream != 0 {
			stream.request.endStream = true
			// 如果 headers 也完成了，尝试输出 request
			if stream.request.headersDone {
				p.tryOutputRequest(stream)
			}
		}
	} else {
		if stream.response == nil {
			stream.response = &http2Response{
				headers: make(http.Header),
			}
			stream.responseTime = p.packetTime
		}
		if stream.response.headerBlock.Len()+len(headerBlock) > maxHTTP2BufferedBytes {
			p.parseErr = fmt.Errorf("HTTP/2 response headers exceed %d-byte limit", maxHTTP2BufferedBytes)
			return
		}
		stream.response.headerBlock.Write(headerBlock)
		if flags&http2.FlagHeadersEndHeaders != 0 {
			p.decodeHeaders(stream.response.headerBlock.Bytes(), stream.response.headers, false)
			stream.response.headerBlock.Reset()
			stream.response.headersDone = true
			p.extractResponsePseudoHeaders(stream.response)
		}
		if flags&http2.FlagHeadersEndStream != 0 {
			stream.response.endStream = true
			p.completeStream(stream)
		}
	}
}

// handleContinuationFrame 处理CONTINUATION帧
func (p *HTTP2StreamParser) handleContinuationFrame(streamID uint32, flags http2.Flags, payload []byte, isClient bool) {
	stream, ok := p.streams[streamID]
	if !ok {
		return
	}

	if isClient && stream.request != nil {
		if stream.request.headerBlock.Len()+len(payload) > maxHTTP2BufferedBytes {
			p.parseErr = fmt.Errorf("HTTP/2 request headers exceed %d-byte limit", maxHTTP2BufferedBytes)
			return
		}
		stream.request.headerBlock.Write(payload)
		if flags&http2.FlagContinuationEndHeaders != 0 {
			p.decodeHeaders(stream.request.headerBlock.Bytes(), stream.request.headers, true)
			stream.request.headerBlock.Reset()
			stream.request.headersDone = true
			p.extractRequestPseudoHeaders(stream.request)
			if stream.request.endStream {
				p.tryOutputRequest(stream)
			}
		}
	} else if !isClient && stream.response != nil {
		if stream.response.headerBlock.Len()+len(payload) > maxHTTP2BufferedBytes {
			p.parseErr = fmt.Errorf("HTTP/2 response headers exceed %d-byte limit", maxHTTP2BufferedBytes)
			return
		}
		stream.response.headerBlock.Write(payload)
		if flags&http2.FlagContinuationEndHeaders != 0 {
			p.decodeHeaders(stream.response.headerBlock.Bytes(), stream.response.headers, false)
			stream.response.headerBlock.Reset()
			stream.response.headersDone = true
			p.extractResponsePseudoHeaders(stream.response)
			if stream.response.endStream {
				p.completeStream(stream)
			}
		}
	}
}

// handleDataFrame 处理DATA帧
func (p *HTTP2StreamParser) handleDataFrame(streamID uint32, flags http2.Flags, payload []byte, isClient bool) {
	if streamID == 0 {
		return
	}

	stream, ok := p.streams[streamID]
	if !ok {
		return
	}

	// 处理填充
	data := payload
	if flags&http2.FlagDataPadded != 0 && len(payload) > 0 {
		padLen := int(payload[0])
		if len(payload) < 1+padLen {
			return
		}
		data = payload[1 : len(payload)-padLen]
	}

	if isClient && stream.request != nil {
		if stream.request.body.Len()+len(data) > maxHTTP2BufferedBytes {
			p.parseErr = fmt.Errorf("HTTP/2 request body exceeds %d-byte limit", maxHTTP2BufferedBytes)
			return
		}
		stream.request.body.Write(data)
		if flags&http2.FlagDataEndStream != 0 {
			stream.request.endStream = true
			// 如果 request 已经完整（headers + body 都结束了），尝试输出
			if stream.request.headersDone {
				p.tryOutputRequest(stream)
			}
		}
	} else if !isClient && stream.response != nil {
		if stream.response.body.Len()+len(data) > maxHTTP2BufferedBytes {
			p.parseErr = fmt.Errorf("HTTP/2 response body exceeds %d-byte limit", maxHTTP2BufferedBytes)
			return
		}
		stream.response.body.Write(data)
		if flags&http2.FlagDataEndStream != 0 {
			stream.response.endStream = true
			p.completeStream(stream)
		}
	}
}

// decodeHeaders 使用HPACK解码头部
func (p *HTTP2StreamParser) decodeHeaders(headerBlock []byte, headers http.Header, isClient bool) {
	var decoder *hpack.Decoder
	if isClient {
		decoder = p.clientDecoder
	} else {
		decoder = p.serverDecoder
	}

	hf, err := decoder.DecodeFull(headerBlock)
	if err != nil {
		return
	}

	for _, f := range hf {
		if f.Name == "" {
			continue
		}
		if strings.HasPrefix(f.Name, ":") {
			// 伪头部，存储到普通头部中（带前缀）
			headers.Add(f.Name, f.Value)
		} else {
			headers.Add(f.Name, f.Value)
		}
	}
}

// extractRequestPseudoHeaders 从头部提取伪头部到请求字段
func (p *HTTP2StreamParser) extractRequestPseudoHeaders(req *http2Request) {
	if v := req.headers.Get(":method"); v != "" {
		req.method = v
		req.headers.Del(":method")
	}
	if v := req.headers.Get(":path"); v != "" {
		req.path = v
		req.headers.Del(":path")
	}
	if v := req.headers.Get(":scheme"); v != "" {
		req.scheme = v
		req.headers.Del(":scheme")
	}
	if v := req.headers.Get(":authority"); v != "" {
		req.authority = v
		req.headers.Del(":authority")
	}
}

// extractResponsePseudoHeaders 从头部提取伪头部到响应字段
func (p *HTTP2StreamParser) extractResponsePseudoHeaders(resp *http2Response) {
	if v := resp.headers.Get(":status"); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &resp.status)
		resp.headers.Del(":status")
	}
}

// completeStream 完成一个HTTP/2流，输出解密包
func (p *HTTP2StreamParser) completeStream(stream *http2Stream) {
	if stream.request == nil || stream.response == nil || !stream.response.headersDone || !stream.response.endStream {
		return
	}

	// Output request packet (if not already output)
	if p.packetChan != nil && stream.request != nil && !stream.request.outputted {
		p.outputRequest(stream)
	}

	// Output response packet
	if p.packetChan != nil {
		// Build HTTP/2 response data
		var respBuf bytes.Buffer
		fmt.Fprintf(&respBuf, "HTTP/2.0 %d\r\n", stream.response.status)
		for name, values := range stream.response.headers {
			for _, value := range values {
				fmt.Fprintf(&respBuf, "%s: %s\r\n", name, value)
			}
		}
		respBuf.WriteString("\r\n")
		respBuf.Write(stream.response.body.Bytes())

		respPacket := types.NewDecryptedPacket(types.TransportProtocolTCP, "http/2", "response", respBuf.Bytes(), stream.responseTime, p.addr)
		respPacket.WithMetadata("status", stream.response.status).
			WithMetadata("stream_id", stream.id).
			WithMetadata("authority", stream.request.authority).
			WithMetadata("headers", stream.response.headers)

		p.packetChan <- respPacket
	}

	// 清理流
	delete(p.streams, stream.id)
}

// tryOutputRequest 尝试输出已完成的 request（当 headers 和 body 都结束时）
func (p *HTTP2StreamParser) tryOutputRequest(stream *http2Stream) {
	if stream.request == nil || !stream.request.headersDone || !stream.request.endStream {
		return
	}

	// 避免重复输出
	if stream.request.outputted {
		return
	}

	p.outputRequest(stream)
}

// outputRequest 输出 HTTP/2 请求包
func (p *HTTP2StreamParser) outputRequest(stream *http2Stream) {
	if stream.request == nil || stream.request.outputted {
		return
	}

	stream.request.outputted = true

	if p.packetChan == nil {
		return
	}

	// Build HTTP/2 request data
	var reqBuf bytes.Buffer
	fmt.Fprintf(&reqBuf, "%s %s HTTP/2.0\r\n", stream.request.method, stream.request.path)
	for name, values := range stream.request.headers {
		for _, value := range values {
			fmt.Fprintf(&reqBuf, "%s: %s\r\n", name, value)
		}
	}
	reqBuf.WriteString("\r\n")
	reqBuf.Write(stream.request.body.Bytes())

	reqPacket := types.NewDecryptedPacket(types.TransportProtocolTCP, "http/2", "request", reqBuf.Bytes(), stream.startTime, p.addr)
	reqPacket.WithMetadata("method", stream.request.method).
		WithMetadata("path", stream.request.path).
		WithMetadata("scheme", stream.request.scheme).
		WithMetadata("authority", stream.request.authority).
		WithMetadata("stream_id", stream.id).
		WithMetadata("headers", stream.request.headers)

	p.packetChan <- reqPacket
}

// Flush 刷新所有未完成的流
func (p *HTTP2StreamParser) Flush() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.events != nil {
		p.finishEvents("")
		return
	}
	if p.parseErr != nil {
		return
	}

	// 解析剩余数据
	p.parseFrames(&p.clientBuffer, true)
	p.parseFrames(&p.serverBuffer, false)

	// 完成所有有响应的流
	// Complete any pending streams
	for _, stream := range p.streams {
		if stream.request != nil && stream.response != nil && stream.response.headersDone && stream.response.endStream {
			p.completeStream(stream)
		}
	}
}

// IsHTTP2Connection 检查是否是HTTP/2连接
func (p *HTTP2StreamParser) IsHTTP2Connection() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.isHTTP2
}

// Ensure interfaces are implemented
var _ types.StreamParserInterface = (*HTTP2StreamParser)(nil)
var _ types.StreamParserInterface = (*HTTPStreamParser)(nil)
var _ io.Closer = (*HTTP2StreamParser)(nil)

// Close 关闭解析器
func (p *HTTP2StreamParser) Close() error {
	p.Flush()
	return nil
}

type h2EventHalf struct {
	body            *eventBody
	ended, trailers bool
}
type h2EventStream [2]h2EventHalf
type h2EventInput struct {
	headerID           uint32
	headerBlock        []byte
	headerFin          bool
	dataID             uint32
	remaining, padding int
	padded, dataFin    bool
}
type http2Events struct {
	output  *eventOutput
	streams map[uint32]*h2EventStream
	reset   map[uint32]bool
	input   [2]h2EventInput
	closed  bool
}

var errHTTP2Event = errors.New("invalid HTTP/2 event stream")

func (p *HTTP2StreamParser) EnableHTTPEvents(limit int64) {
	p.events = &http2Events{output: newEventOutput(p.addr, p.packetChan, limit), streams: make(map[uint32]*h2EventStream), reset: make(map[uint32]bool)}
	p.clientDecoder.SetMaxStringLength(eventFieldLimit)
	p.serverDecoder.SetMaxStringLength(eventFieldLimit)
}

func (p *HTTP2StreamParser) feedHTTPEvents(data []byte, client bool) error {
	if p.events.closed {
		return io.ErrClosedPipe
	}
	buf := &p.serverBuffer
	if client {
		buf = &p.clientBuffer
	}
	for len(data) > 0 {
		n := min(len(data), eventChunkSize)
		if buf.Len()+n > maxHTTP2BufferedBytes+eventChunkSize {
			return ErrHTTPEventLimit
		}
		buf.Write(data[:n])
		data = data[n:]
		if !p.clientPrefaceReceived {
			if !client {
				continue
			}
			size := min(buf.Len(), len(http2Preface))
			if !bytes.Equal(buf.Bytes()[:size], http2Preface[:size]) {
				return errHTTP2Event
			}
			if size < len(http2Preface) {
				continue
			}
			buf.Next(size)
			p.clientPrefaceReceived = true
			p.isHTTP2 = true
		}
		if err := p.parseEventFrames(buf, client); err != nil {
			return err
		}
		if client && p.serverBuffer.Len() > 0 {
			if err := p.parseEventFrames(&p.serverBuffer, false); err != nil {
				return err
			}
		}
	}
	return nil
}
func (p *HTTP2StreamParser) parseEventFrames(buf *bytes.Buffer, client bool) error {
	e := p.events
	side := http3Side(client)
	in := &e.input[side]
	if e.closed {
		return io.ErrClosedPipe
	}
	for {
		if in.dataID != 0 {
			stream := e.streams[in.dataID]
			if in.padded {
				if buf.Len() == 0 {
					return nil
				}
				in.padding = int(buf.Next(1)[0])
				in.remaining--
				in.padded = false
				if in.remaining < in.padding {
					return errHTTP2Event
				}
			}
			n := min(in.remaining-in.padding, buf.Len())
			part := buf.Next(n)
			// An opposite-direction RST can arrive between fragments of this DATA.
			if stream != nil {
				body := stream[side].body
				body.at = p.packetTime
				if err := body.write(part); err != nil {
					return err
				}
			}
			in.remaining -= n
			if in.remaining > in.padding {
				return nil
			}
			skipped := min(in.padding, buf.Len())
			buf.Next(skipped)
			in.padding -= skipped
			in.remaining -= skipped
			if in.remaining != 0 {
				return nil
			}
			id := in.dataID
			in.dataID = 0
			if in.dataFin && stream != nil {
				if err := e.end(id, side); err != nil {
					return err
				}
			}
		}
		if buf.Len() < 9 {
			return nil
		}
		head := buf.Bytes()
		length := int(head[0])<<16 | int(head[1])<<8 | int(head[2])
		typ := http2.FrameType(head[3])
		flags := http2.Flags(head[4])
		id := binary.BigEndian.Uint32(head[5:9]) & 0x7fffffff
		if in.headerID != 0 && (typ != http2.FrameContinuation || id != in.headerID) {
			return errHTTP2Event
		}
		if typ == http2.FrameData {
			s := e.streams[id]
			if id == 0 || !e.reset[id] && (s == nil || s[side].body == nil || s[side].ended || s[side].trailers) {
				return errHTTP2Event
			}
			buf.Next(9)
			in.dataID = id
			in.remaining = length
			in.padding = 0
			in.padded = flags.Has(http2.FlagDataPadded)
			in.dataFin = flags.Has(http2.FlagDataEndStream)
			if in.padded && length == 0 {
				return errHTTP2Event
			}
			continue
		}
		if (typ == http2.FrameHeaders || typ == http2.FrameContinuation || typ == http2.FrameSettings) && length > eventFieldLimit {
			return ErrHTTPEventLimit
		}
		if buf.Len() < 9+length {
			return nil
		}
		buf.Next(9)
		payload := buf.Next(length)
		switch typ {
		case http2.FrameHeaders:
			if id == 0 {
				return errHTTP2Event
			}
			if flags.Has(http2.FlagHeadersPadded) {
				if len(payload) == 0 || int(payload[0]) >= len(payload) {
					return errHTTP2Event
				}
				payload = payload[1 : len(payload)-int(payload[0])]
			}
			if flags.Has(http2.FlagHeadersPriority) {
				if len(payload) < 5 {
					return errHTTP2Event
				}
				payload = payload[5:]
			}
			in.headerID = id
			in.headerFin = flags.Has(http2.FlagHeadersEndStream)
			fallthrough
		case http2.FrameContinuation:
			if in.headerID == 0 || in.headerID != id {
				return errHTTP2Event
			}
			if len(in.headerBlock)+len(payload) > eventFieldLimit {
				return ErrHTTPEventLimit
			}
			in.headerBlock = append(in.headerBlock, payload...)
			if flags.Has(http2.FlagHeadersEndHeaders) {
				if err := p.eventHeaders(id, client, in.headerBlock, in.headerFin); err != nil {
					return err
				}
				in.headerBlock = nil
				in.headerID = 0
			}
		case http2.FrameRSTStream:
			if id == 0 || length != 4 {
				return errHTTP2Event
			}
			if !e.reset[id] && len(e.reset) >= 1024 {
				return ErrHTTPEventLimit
			}
			e.reset[id] = true
			if s := e.streams[id]; s != nil {
				for i := range s {
					if s[i].body != nil {
						s[i].body.at = p.packetTime
						_ = s[i].body.finish("reset", map[string]any{"error_code": uint64(binary.BigEndian.Uint32(payload))})
					}
				}
				delete(e.streams, id)
			}
		case http2.FrameSettings:
			if id != 0 || len(payload)%6 != 0 || flags.Has(http2.FlagSettingsAck) && len(payload) != 0 {
				return errHTTP2Event
			}
			for len(payload) > 0 {
				if binary.BigEndian.Uint16(payload) == 1 {
					dec := p.clientDecoder
					if client {
						dec = p.serverDecoder
					}
					dec.SetAllowedMaxDynamicTableSize(min(binary.BigEndian.Uint32(payload[2:]), uint32(eventFieldLimit)))
				}
				payload = payload[6:]
			}
		case http2.FramePushPromise:
			return errors.New("HTTP/2 PUSH_PROMISE is unsupported in HTTP event mode")
		}
	}
}

func (p *HTTP2StreamParser) eventHeaders(id uint32, client bool, block []byte, fin bool) error {
	dec := p.serverDecoder
	if client {
		dec = p.clientDecoder
	}
	fields := make([]qpackField, 0, 8)
	size := 0
	dec.SetEmitFunc(func(f hpack.HeaderField) {
		size += len(f.Name) + len(f.Value) + 32
		if size <= eventFieldLimit && len(fields) <= maxHTTP3Fields {
			fields = append(fields, qpackField{f.Name, f.Value})
		}
	})
	_, err := dec.Write(block)
	dec.SetEmitFunc(nil)
	if err != nil {
		return err
	}
	if err = dec.Close(); err != nil {
		return err
	}
	if size > eventFieldLimit || len(fields) > maxHTTP3Fields {
		return ErrHTTPEventLimit
	}
	e := p.events
	if e.reset[id] {
		return nil
	} // HPACK above still advances for in-flight headers.
	s := e.streams[id]
	if s == nil {
		if len(e.streams) >= 1024 {
			return ErrHTTPEventLimit
		}
		s = &h2EventStream{}
		e.streams[id] = s
	}
	side := http3Side(client)
	half := &s[side]
	trailer := half.body != nil
	if half.ended || half.trailers {
		return errHTTP2Event
	}
	h, err := parseHTTP3Headers(fields, client, trailer)
	if err != nil {
		return errHTTP2Event
	}
	if trailer {
		if !fin {
			return errHTTP2Event
		}
		half.body.at = p.packetTime
		if err := half.body.trailers(h.headers); err != nil {
			return err
		}
		half.trailers = true
	} else {
		info := !client && h.status[0] == '1'
		if info && fin {
			return errHTTP2Event
		}
		meta := map[string]any{}
		if client {
			meta["method"] = h.method
			meta["path"] = h.path
			meta["scheme"] = h.scheme
			meta["authority"] = h.authority
		} else {
			meta["status"], _ = strconv.Atoi(h.status)
		}
		body, err := e.output.headers("http/2", uint64(id), client, p.packetTime, h.headers, meta, info)
		if err != nil {
			return err
		}
		if !info {
			half.body = body
			if body.grpc != nil && client && h.method != "POST" {
				return errGRPC
			}
			if body.grpc != nil && !client && h.headers.Get("Grpc-Status") != "" {
				if !fin {
					return errGRPC
				}
				if err := body.trailers(h.headers); err != nil {
					return err
				}
			}
		}
	}
	if fin {
		return e.end(id, side)
	}
	return nil
}
func (e *http2Events) end(id uint32, side int) error {
	s := e.streams[id]
	s[side].ended = true
	err := s[side].body.finish("end", nil)
	if s[1-side].ended {
		delete(e.streams, id)
	}
	return err
}
func (p *HTTP2StreamParser) FinishHTTPEvents(reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.finishEvents(reason)
}
func (p *HTTP2StreamParser) finishEvents(reason string) {
	e := p.events
	if e == nil || e.closed {
		return
	}
	e.closed = true
	incomplete := len(e.output.active) > 0 || p.clientBuffer.Len()+p.serverBuffer.Len() > 0
	for _, in := range e.input {
		incomplete = incomplete || in.headerID != 0 || in.dataID != 0
	}
	if reason != "reset" && reason != "partial" && p.parseErr == nil && incomplete {
		p.parseErr = io.ErrUnexpectedEOF
	}
	if reason == "reset" {
		e.output.finishAll("reset")
	} else {
		e.output.abort()
	}
	e.streams = nil
	e.reset = nil
	e.input = [2]h2EventInput{}
	p.clientBuffer = bytes.Buffer{}
	p.serverBuffer = bytes.Buffer{}
}
