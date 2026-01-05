// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

// protocol_http3.go - HTTP/3 协议解析器
package protocol

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cfc4n/ecapture_decryptor/types"
)

// HTTP/3 帧类型
const (
	HTTP3FrameData         = 0x00
	HTTP3FrameHeaders      = 0x01
	HTTP3FrameCancelPush   = 0x03
	HTTP3FrameSettings     = 0x04
	HTTP3FramePushPromise  = 0x05
	HTTP3FrameGoAway       = 0x07
	HTTP3FrameMaxPushID    = 0x0D
	HTTP3FrameReservedMask = 0x1F // 保留帧类型
)

// HTTP/3 设置参数
const (
	HTTP3SettingsQPackMaxTableCapacity = 0x01
	HTTP3SettingsMaxFieldSectionSize   = 0x06
	HTTP3SettingsQPackBlockedStreams   = 0x07
)

// QPACK 静态表 (RFC 9204)
var qpackStaticTable = []struct {
	name  string
	value string
}{
	{":authority", ""},
	{":path", "/"},
	{":age", "0"},
	{"content-disposition", ""},
	{"content-length", "0"},
	{"cookie", ""},
	{"date", ""},
	{"etag", ""},
	{"if-modified-since", ""},
	{"if-none-match", ""},
	{"last-modified", ""},
	{"link", ""},
	{"location", ""},
	{"referer", ""},
	{"set-cookie", ""},
	{":method", "CONNECT"},
	{":method", "DELETE"},
	{":method", "GET"},
	{":method", "HEAD"},
	{":method", "OPTIONS"},
	{":method", "POST"},
	{":method", "PUT"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "103"},
	{":status", "200"},
	{":status", "304"},
	{":status", "404"},
	{":status", "503"},
	{"accept", "*/*"},
	{"accept", "application/dns-message"},
	{"accept-encoding", "gzip, deflate, br"},
	{"accept-ranges", "bytes"},
	{"access-control-allow-headers", "cache-control"},
	{"access-control-allow-headers", "content-type"},
	{"access-control-allow-origin", "*"},
	{"cache-control", "max-age=0"},
	{"cache-control", "max-age=2592000"},
	{"cache-control", "max-age=604800"},
	{"cache-control", "no-cache"},
	{"cache-control", "no-store"},
	{"cache-control", "public, max-age=31536000"},
	{"content-encoding", "br"},
	{"content-encoding", "gzip"},
	{"content-type", "application/dns-message"},
	{"content-type", "application/javascript"},
	{"content-type", "application/json"},
	{"content-type", "application/x-www-form-urlencoded"},
	{"content-type", "image/gif"},
	{"content-type", "image/jpeg"},
	{"content-type", "image/png"},
	{"content-type", "text/css"},
	{"content-type", "text/html; charset=utf-8"},
	{"content-type", "text/plain"},
	{"content-type", "text/plain;charset=utf-8"},
	{"range", "bytes=0-"},
	{"strict-transport-security", "max-age=31536000"},
	{"strict-transport-security", "max-age=31536000; includesubdomains"},
	{"strict-transport-security", "max-age=31536000; includesubdomains; preload"},
	{"vary", "accept-encoding"},
	{"vary", "origin"},
	{"x-content-type-options", "nosniff"},
	{"x-xss-protection", "1; mode=block"},
	{":status", "100"},
	{":status", "204"},
	{":status", "206"},
	{":status", "302"},
	{":status", "400"},
	{":status", "403"},
	{":status", "421"},
	{":status", "425"},
	{":status", "500"},
	{"accept-language", ""},
	{"access-control-allow-credentials", "FALSE"},
	{"access-control-allow-credentials", "TRUE"},
	{"access-control-allow-headers", "*"},
	{"access-control-allow-methods", "get"},
	{"access-control-allow-methods", "get, post, options"},
	{"access-control-allow-methods", "options"},
	{"access-control-expose-headers", "content-length"},
	{"access-control-request-headers", "content-type"},
	{"access-control-request-method", "get"},
	{"access-control-request-method", "post"},
	{"alt-svc", "clear"},
	{"authorization", ""},
	{"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"},
	{"early-data", "1"},
	{"expect-ct", ""},
	{"forwarded", ""},
	{"if-range", ""},
	{"origin", ""},
	{"purpose", "prefetch"},
	{"server", ""},
	{"timing-allow-origin", "*"},
	{"upgrade-insecure-requests", "1"},
	{"user-agent", ""},
	{"x-forwarded-for", ""},
	{"x-frame-options", "deny"},
	{"x-frame-options", "sameorigin"},
}

// HTTP3StreamParser HTTP/3 流解析器
type HTTP3StreamParser struct {
	addr       types.ConnectionKey
	clientIP   string
	clientPort string
	serverIP   string
	serverPort string
	packetChan chan *types.DecryptedPacket // 解密包输出通道
	mu         sync.Mutex

	// QPACK 动态表
	clientDynamicTable []qpackEntry
	serverDynamicTable []qpackEntry
	maxTableCapacity   uint64

	// 流状态
	streams map[uint64]*http3Stream

	// 时间戳
	packetTime time.Time

	// 数据缓冲
	clientBuffer bytes.Buffer
	serverBuffer bytes.Buffer
}

// qpackEntry QPACK 动态表条目
type qpackEntry struct {
	// Reserved for future use
}

// http3Stream HTTP/3 流
type http3Stream struct {
	id           uint64
	request      *http3Request
	response     *http3Response
	startTime    time.Time
	responseTime time.Time
}

// http3Request HTTP/3 请求
type http3Request struct {
	method      string
	path        string
	scheme      string
	authority   string
	headers     http.Header
	body        bytes.Buffer
	headersDone bool
	outputted   bool // 标记是否已经输出，避免重复
}

// http3Response HTTP/3 响应
type http3Response struct {
	status      int
	headers     http.Header
	body        bytes.Buffer
	headersDone bool
}

// NewHTTP3StreamParser 创建 HTTP/3 流解析器
func NewHTTP3StreamParser(ci types.ConnectionKey, packetChan chan *types.DecryptedPacket) *HTTP3StreamParser {
	return newHTTP3StreamParserInternal(ci, packetChan)
}

// newHTTP3StreamParserInternal 内部构造函数
func newHTTP3StreamParserInternal(ci types.ConnectionKey, packetChan chan *types.DecryptedPacket) *HTTP3StreamParser {

	return &HTTP3StreamParser{
		addr:               ci,
		clientIP:           ci.SrcIP.String(),
		clientPort:         strconv.Itoa(int(ci.SrcPort)),
		serverIP:           ci.DstIP.String(),
		serverPort:         strconv.Itoa(int(ci.DstPort)),
		packetChan:         packetChan,
		clientDynamicTable: make([]qpackEntry, 0),
		serverDynamicTable: make([]qpackEntry, 0),
		maxTableCapacity:   4096,
		streams:            make(map[uint64]*http3Stream),
	}
}

// SetPacketTime 设置数据包时间戳
func (p *HTTP3StreamParser) SetPacketTime(t time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.packetTime = t
}

// FeedRequest 处理客户端数据（请求）
func (p *HTTP3StreamParser) FeedRequest(data []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.clientBuffer.Write(data)
	p.parseFrames(&p.clientBuffer, true)
}

// FeedResponse 处理服务端数据（响应）
func (p *HTTP3StreamParser) FeedResponse(data []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.serverBuffer.Write(data)
	p.parseFrames(&p.serverBuffer, false)
}

// parseFrames 解析 HTTP/3 帧
func (p *HTTP3StreamParser) parseFrames(buf *bytes.Buffer, isClient bool) {
	for {
		if buf.Len() == 0 {
			return
		}

		data := buf.Bytes()

		// 读取帧类型（变长整数）
		frameType, typeLen := readVarInt(data)
		if typeLen == 0 {
			return
		}

		// 读取帧长度（变长整数）
		if len(data) < typeLen {
			return
		}
		frameLen, lenLen := readVarInt(data[typeLen:])
		if lenLen == 0 {
			return
		}

		headerLen := typeLen + lenLen
		totalLen := headerLen + int(frameLen)

		// 检查是否有完整的帧
		if buf.Len() < totalLen {
			return
		}

		// 读取完整帧
		frameData := make([]byte, totalLen)
		_, _ = buf.Read(frameData)
		payload := frameData[headerLen:]

		// 处理帧
		p.handleFrame(frameType, payload, isClient)
	}
}

// readVarInt 读取 QUIC 变长整数
func readVarInt(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}

	firstByte := data[0]
	length := 1 << (firstByte >> 6)

	if len(data) < length {
		return 0, 0
	}

	var value uint64
	switch length {
	case 1:
		value = uint64(firstByte & 0x3F)
	case 2:
		value = uint64(firstByte&0x3F)<<8 | uint64(data[1])
	case 4:
		value = uint64(firstByte&0x3F)<<24 | uint64(data[1])<<16 |
			uint64(data[2])<<8 | uint64(data[3])
	case 8:
		value = uint64(firstByte&0x3F)<<56 | uint64(data[1])<<48 |
			uint64(data[2])<<40 | uint64(data[3])<<32 |
			uint64(data[4])<<24 | uint64(data[5])<<16 |
			uint64(data[6])<<8 | uint64(data[7])
	}

	return value, length
}

// handleFrame 处理单个 HTTP/3 帧
func (p *HTTP3StreamParser) handleFrame(frameType uint64, payload []byte, isClient bool) {
	switch frameType {
	case HTTP3FrameHeaders:
		p.handleHeadersFrame(payload, isClient)
	case HTTP3FrameData:
		p.handleDataFrame(payload, isClient)
	case HTTP3FrameSettings:
		p.handleSettingsFrame(payload)
	case HTTP3FrameCancelPush, HTTP3FramePushPromise, HTTP3FrameGoAway, HTTP3FrameMaxPushID:
		// 控制帧，忽略
	default:
		// 可能是保留帧或扩展帧
	}
}

// handleSettingsFrame 处理 SETTINGS 帧
func (p *HTTP3StreamParser) handleSettingsFrame(payload []byte) {
	for len(payload) > 0 {
		id, idLen := readVarInt(payload)
		if idLen == 0 {
			return
		}
		payload = payload[idLen:]

		value, valueLen := readVarInt(payload)
		if valueLen == 0 {
			return
		}
		payload = payload[valueLen:]

		if id == HTTP3SettingsQPackMaxTableCapacity {
			p.maxTableCapacity = value
		}
	}
}

// handleHeadersFrame 处理 HEADERS 帧
func (p *HTTP3StreamParser) handleHeadersFrame(payload []byte, isClient bool) {
	// 简化处理：使用流ID 1 作为默认
	streamID := uint64(1)

	stream, ok := p.streams[streamID]
	if !ok {
		stream = &http3Stream{
			id:        streamID,
			startTime: p.packetTime,
		}
		p.streams[streamID] = stream
	}

	headers := p.decodeQPACKHeaders(payload, isClient)

	if isClient {
		if stream.request == nil {
			stream.request = &http3Request{
				headers: make(http.Header),
			}
		}
		for name, value := range headers {
			if strings.HasPrefix(name, ":") {
				switch name {
				case ":method":
					stream.request.method = value
				case ":path":
					stream.request.path = value
				case ":scheme":
					stream.request.scheme = value
				case ":authority":
					stream.request.authority = value
				}
			} else {
				stream.request.headers.Add(name, value)
			}
		}
		stream.request.headersDone = true
		// 尝试输出 request（如果是没有 body 的请求，如 GET）
		p.tryOutputRequest(stream)
	} else {
		if stream.response == nil {
			stream.response = &http3Response{
				headers: make(http.Header),
			}
			stream.responseTime = p.packetTime
		}
		for name, value := range headers {
			if name == ":status" {
				_, _ = fmt.Sscanf(value, "%d", &stream.response.status)
			} else if !strings.HasPrefix(name, ":") {
				stream.response.headers.Add(name, value)
			}
		}
		stream.response.headersDone = true
	}
}

// handleDataFrame 处理 DATA 帧
func (p *HTTP3StreamParser) handleDataFrame(payload []byte, isClient bool) {
	streamID := uint64(1)
	stream, ok := p.streams[streamID]
	if !ok {
		return
	}

	if isClient && stream.request != nil {
		stream.request.body.Write(payload)
		// 如果 headers 已完成，尝试输出 request
		if stream.request.headersDone {
			p.tryOutputRequest(stream)
		}
	} else if !isClient && stream.response != nil {
		stream.response.body.Write(payload)
		// 简化处理：收到数据后尝试完成流
		p.tryCompleteStream(stream)
	}
}

// decodeQPACKHeaders 解码 QPACK 头部
func (p *HTTP3StreamParser) decodeQPACKHeaders(data []byte, isClient bool) map[string]string {
	headers := make(map[string]string)

	if len(data) < 2 {
		return headers
	}

	// 跳过 QPACK 编码前缀（Required Insert Count 和 Delta Base）
	_, ricLen := readVarInt(data)
	if ricLen == 0 || len(data) < ricLen {
		return headers
	}
	data = data[ricLen:]

	_, dbLen := readVarInt(data)
	if dbLen == 0 || len(data) < dbLen {
		return headers
	}
	data = data[dbLen:]

	// 解码头部字段
	for len(data) > 0 {
		firstByte := data[0]

		if firstByte&0x80 != 0 {
			// 索引字段行
			index := int(firstByte & 0x3F)
			if firstByte&0x40 != 0 {
				// 静态表
				if index < len(qpackStaticTable) {
					entry := qpackStaticTable[index]
					headers[entry.name] = entry.value
				}
			}
			data = data[1:]
		} else if firstByte&0x40 != 0 {
			// 带名称引用的字面头部字段
			nameIndex := int(firstByte & 0x0F)
			var name string
			if firstByte&0x10 != 0 {
				// 静态表
				if nameIndex < len(qpackStaticTable) {
					name = qpackStaticTable[nameIndex].name
				}
			}
			data = data[1:]

			// 读取值
			if len(data) == 0 {
				break
			}
			valueLen := int(data[0] & 0x7F)
			_ = data[0]&0x80 != 0 // huffman flag (not used in simplified implementation)
			data = data[1:]

			if len(data) < valueLen {
				break
			}
			value := string(data[:valueLen])
			data = data[valueLen:]

			if name != "" {
				headers[name] = value
			}
		} else if firstByte&0x20 != 0 {
			// 带字面名称的字面头部字段
			data = data[1:]

			// 读取名称
			if len(data) == 0 {
				break
			}
			nameLen := int(data[0] & 0x07)
			data = data[1:]

			if len(data) < nameLen {
				break
			}
			name := string(data[:nameLen])
			data = data[nameLen:]

			// 读取值
			if len(data) == 0 {
				break
			}
			valueLen := int(data[0] & 0x7F)
			data = data[1:]

			if len(data) < valueLen {
				break
			}
			value := string(data[:valueLen])
			data = data[valueLen:]

			headers[name] = value
		} else {
			// 未知格式，跳过
			data = data[1:]
		}
	}

	return headers
}

// tryCompleteStream 尝试完成流并输出解密包
func (p *HTTP3StreamParser) tryCompleteStream(stream *http3Stream) {
	if stream.request == nil || stream.response == nil {
		return
	}

	if !stream.request.headersDone || !stream.response.headersDone {
		return
	}

	// Output request packet (if not already output)
	if p.packetChan != nil && !stream.request.outputted {
		p.outputRequest(stream)
	}

	// Output response packet
	if p.packetChan != nil {
		var respBuf bytes.Buffer
		fmt.Fprintf(&respBuf, "HTTP/3.0 %d\r\n", stream.response.status)
		for name, values := range stream.response.headers {
			for _, value := range values {
				fmt.Fprintf(&respBuf, "%s: %s\r\n", name, value)
			}
		}
		respBuf.WriteString("\r\n")
		respBuf.Write(stream.response.body.Bytes())

		respPacket := types.NewDecryptedPacket(types.TransportProtocolUDP, "http/3", "response", respBuf.Bytes(), stream.responseTime, p.addr)
		respPacket.WithMetadata("status", stream.response.status).
			WithMetadata("stream_id", stream.id).
			WithMetadata("headers", stream.response.headers)

		select {
		case p.packetChan <- respPacket:
		default:
		}
	}

	// 清理流
	delete(p.streams, stream.id)
}

// tryOutputRequest 尝试输出已完成的 request（当 headers 完成时）
func (p *HTTP3StreamParser) tryOutputRequest(stream *http3Stream) {
	if stream.request == nil || !stream.request.headersDone {
		return
	}

	// 避免重复输出
	if stream.request.outputted {
		return
	}

	p.outputRequest(stream)
}

// outputRequest 输出 HTTP/3 请求包
func (p *HTTP3StreamParser) outputRequest(stream *http3Stream) {
	if stream.request == nil || stream.request.outputted {
		return
	}

	stream.request.outputted = true

	if p.packetChan == nil {
		return
	}

	var reqBuf bytes.Buffer
	fmt.Fprintf(&reqBuf, "%s %s HTTP/3.0\r\n", stream.request.method, stream.request.path)
	for name, values := range stream.request.headers {
		for _, value := range values {
			fmt.Fprintf(&reqBuf, "%s: %s\r\n", name, value)
		}
	}
	reqBuf.WriteString("\r\n")
	reqBuf.Write(stream.request.body.Bytes())

	reqPacket := types.NewDecryptedPacket(types.TransportProtocolUDP, "http/3", "request", reqBuf.Bytes(), stream.startTime, p.addr)
	reqPacket.WithMetadata("method", stream.request.method).
		WithMetadata("path", stream.request.path).
		WithMetadata("scheme", stream.request.scheme).
		WithMetadata("authority", stream.request.authority).
		WithMetadata("stream_id", stream.id).
		WithMetadata("headers", stream.request.headers)

	select {
	case p.packetChan <- reqPacket:
	default:
	}
}

// Flush 刷新所有未完成的流
func (p *HTTP3StreamParser) Flush() {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 解析剩余数据
	p.parseFrames(&p.clientBuffer, true)
	p.parseFrames(&p.serverBuffer, false)

	// 完成所有有响应的流
	for _, stream := range p.streams {
		if stream.request != nil && stream.response != nil {
			p.tryCompleteStream(stream)
		}
	}
}

// Close 关闭解析器
func (p *HTTP3StreamParser) Close() error {
	p.Flush()
	return nil
}

// Ensure interface is implemented
var _ types.StreamParserInterface = (*HTTP3StreamParser)(nil)
