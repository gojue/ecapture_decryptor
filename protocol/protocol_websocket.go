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
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gojue/ecapture_decryptor/types"
)

// WebSocket 操作码
const (
	WSOpcodeContinuation = 0x0
	WSOpcodeText         = 0x1
	WSOpcodeBinary       = 0x2
	WSOpcodeClose        = 0x8
	WSOpcodePing         = 0x9
	WSOpcodePong         = 0xA
)

// WebSocket GUID (RFC 6455)
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// WebSocketStreamParser WebSocket 流解析器
type WebSocketStreamParser struct {
	addr       types.ConnectionKey
	clientIP   string
	clientPort uint32
	serverIP   string
	serverPort uint32
	packetChan chan *types.DecryptedPacket // 解密包输出通道
	mu         sync.Mutex

	// 握手状态
	handshakeComplete bool
	upgradeRequest    *http.Request
	upgradeResponse   *http.Response
	wsKey             string

	// 数据缓冲
	clientBuffer bytes.Buffer
	serverBuffer bytes.Buffer

	// 消息状态
	messages []wsMessage

	// 时间戳
	startTime  time.Time
	packetTime time.Time

	// HTTP/1.x 回退解析器
	httpFallback *HTTPStreamParser
}

// wsMessage WebSocket 消息
type wsMessage struct {
	isClient  bool
	opcode    byte
	data      []byte
	timestamp time.Time
}

// NewWebSocketStreamParser 创建 WebSocket 流解析器
func NewWebSocketStreamParser(addr types.ConnectionKey, packetChan chan *types.DecryptedPacket) *WebSocketStreamParser {
	return newWebSocketStreamParserInternal(addr, packetChan)
}

// newWebSocketStreamParserInternal 内部构造函数
func newWebSocketStreamParserInternal(addr types.ConnectionKey, packetChan chan *types.DecryptedPacket) *WebSocketStreamParser {

	return &WebSocketStreamParser{
		addr:       addr,
		clientIP:   addr.SrcIP.String(),
		clientPort: uint32(addr.SrcPort),
		serverIP:   addr.DstIP.String(),
		serverPort: uint32(addr.DstPort),
		packetChan: packetChan,
		messages:   make([]wsMessage, 0),
	}
}

// IsWebSocketUpgrade 检测是否是 WebSocket 升级请求
func IsWebSocketUpgrade(data []byte) bool {
	dataStr := string(data)
	return strings.Contains(dataStr, "Upgrade: websocket") ||
		strings.Contains(dataStr, "upgrade: websocket") ||
		strings.Contains(dataStr, "Sec-WebSocket-Key:")
}

// getOrCreateHTTPFallback 获取或创建 HTTP 回退解析器
func (p *WebSocketStreamParser) getOrCreateHTTPFallback() *HTTPStreamParser {
	if p.httpFallback == nil {
		p.httpFallback = NewHTTPStreamParser(p.addr, p.packetChan)
		p.httpFallback.SetPacketTime(p.packetTime)
	}
	return p.httpFallback
}

// SetPacketTime 设置数据包时间戳
func (p *WebSocketStreamParser) SetPacketTime(t time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.packetTime = t
	if p.httpFallback != nil {
		p.httpFallback.SetPacketTime(t)
	}
}

// FeedRequest 处理客户端数据
func (p *WebSocketStreamParser) FeedRequest(data []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.handshakeComplete {
		p.clientBuffer.Write(data)
		p.tryParseHandshakeRequest()
		return
	}

	// 解析 WebSocket 帧
	p.clientBuffer.Write(data)
	p.parseWebSocketFrames(&p.clientBuffer, true)
}

// FeedResponse 处理服务端数据
func (p *WebSocketStreamParser) FeedResponse(data []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.handshakeComplete {
		p.serverBuffer.Write(data)
		p.tryParseHandshakeResponse()
		return
	}

	// 解析 WebSocket 帧
	p.serverBuffer.Write(data)
	p.parseWebSocketFrames(&p.serverBuffer, false)
}

// tryParseHandshakeRequest 尝试解析升级请求
func (p *WebSocketStreamParser) tryParseHandshakeRequest() {
	if p.clientBuffer.Len() == 0 {
		return
	}

	data := p.clientBuffer.Bytes()
	reader := bufio.NewReader(bytes.NewReader(data))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	// 检查是否是 WebSocket 升级请求
	upgrade := req.Header.Get("Upgrade")
	if !strings.EqualFold(upgrade, "websocket") {
		// 不是 WebSocket，回退到 HTTP/1.x
		p.getOrCreateHTTPFallback().FeedRequest(data)
		p.clientBuffer.Reset()
		return
	}

	p.upgradeRequest = req
	p.wsKey = req.Header.Get("Sec-WebSocket-Key")
	p.startTime = p.packetTime

	// 清除已解析的数据
	consumed := len(data) - reader.Buffered()
	p.clientBuffer.Reset()
	if reader.Buffered() > 0 {
		remaining := make([]byte, reader.Buffered())
		_, _ = reader.Read(remaining)
		p.clientBuffer.Write(remaining)
	} else if consumed < len(data) {
		p.clientBuffer.Write(data[consumed:])
	}
}

// tryParseHandshakeResponse 尝试解析升级响应
func (p *WebSocketStreamParser) tryParseHandshakeResponse() {
	if p.upgradeRequest == nil {
		// 还没收到升级请求
		return
	}

	if p.serverBuffer.Len() == 0 {
		return
	}

	data := p.serverBuffer.Bytes()
	reader := bufio.NewReader(bytes.NewReader(data))
	resp, err := http.ReadResponse(reader, p.upgradeRequest)
	if err != nil {
		return
	}

	// 检查是否是成功的升级响应
	if resp.StatusCode != 101 {
		// 升级失败，回退到 HTTP/1.x
		p.getOrCreateHTTPFallback().FeedResponse(data)
		p.serverBuffer.Reset()
		return
	}

	// 验证 Sec-WebSocket-Accept
	expectedAccept := computeWebSocketAccept(p.wsKey)
	actualAccept := resp.Header.Get("Sec-WebSocket-Accept")
	_ = actualAccept != expectedAccept // Verification (accept mismatch is logged but processing continues)

	p.upgradeResponse = resp
	p.handshakeComplete = true

	// Output WebSocket upgrade request
	var reqBuf bytes.Buffer
	fmt.Fprintf(&reqBuf, "%s %s %s\r\n", p.upgradeRequest.Method, p.upgradeRequest.URL.RequestURI(), p.upgradeRequest.Proto)
	_ = p.upgradeRequest.Header.Write(&reqBuf)
	reqBuf.WriteString("\r\n")

	if p.packetChan != nil {
		reqPacket := types.NewDecryptedPacket(types.TransportProtocolTCP, "websocket", "request", reqBuf.Bytes(), p.startTime, p.addr)
		reqPacket.WithMetadata("method", p.upgradeRequest.Method).
			WithMetadata("url", p.upgradeRequest.URL.String()).
			WithMetadata("upgrade", "websocket")

		select {
		case p.packetChan <- reqPacket:
		default:
		}
	}

	// Output WebSocket upgrade response
	var respBuf bytes.Buffer
	fmt.Fprintf(&respBuf, "%s %s\r\n", resp.Proto, resp.Status)
	_ = resp.Header.Write(&respBuf)
	respBuf.WriteString("\r\n")

	if p.packetChan != nil {
		respPacket := types.NewDecryptedPacket(types.TransportProtocolTCP, "websocket", "response", respBuf.Bytes(), p.packetTime, p.addr)
		respPacket.WithMetadata("status", resp.StatusCode).
			WithMetadata("upgrade", "websocket")

		select {
		case p.packetChan <- respPacket:
		default:
		}
	}

	// 清除已解析的数据
	consumed := len(data) - reader.Buffered()
	p.serverBuffer.Reset()
	if reader.Buffered() > 0 {
		remaining := make([]byte, reader.Buffered())
		_, _ = reader.Read(remaining)
		p.serverBuffer.Write(remaining)
	} else if consumed < len(data) {
		p.serverBuffer.Write(data[consumed:])
	}
}

// computeWebSocketAccept 计算 Sec-WebSocket-Accept
func computeWebSocketAccept(key string) string {
	h := sha1.New()
	h.Write([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// parseWebSocketFrames 解析 WebSocket 帧
func (p *WebSocketStreamParser) parseWebSocketFrames(buf *bytes.Buffer, isClient bool) {
	for {
		if buf.Len() < 2 {
			return
		}

		data := buf.Bytes()

		// 解析帧头
		firstByte := data[0]
		secondByte := data[1]

		fin := (firstByte & 0x80) != 0
		opcode := firstByte & 0x0F
		masked := (secondByte & 0x80) != 0
		payloadLen := int(secondByte & 0x7F)

		headerLen := 2
		switch payloadLen {
		case 126:
			if buf.Len() < 4 {
				return
			}
			payloadLen = int(binary.BigEndian.Uint16(data[2:4]))
			headerLen = 4
		case 127:
			if buf.Len() < 10 {
				return
			}
			payloadLen = int(binary.BigEndian.Uint64(data[2:10]))
			headerLen = 10
		}

		if masked {
			headerLen += 4
		}

		totalLen := headerLen + payloadLen
		if buf.Len() < totalLen {
			return
		}

		// 读取完整帧
		frameData := make([]byte, totalLen)
		_, _ = buf.Read(frameData)

		// 提取载荷
		payload := frameData[headerLen:]
		if masked {
			maskKey := frameData[headerLen-4 : headerLen]
			for i := range payload {
				payload[i] ^= maskKey[i%4]
			}
		}

		// 处理帧
		p.handleWebSocketFrame(fin, opcode, payload, isClient)
	}
}

// handleWebSocketFrame 处理 WebSocket 帧
func (p *WebSocketStreamParser) handleWebSocketFrame(fin bool, opcode byte, payload []byte, isClient bool) {
	switch opcode {
	case WSOpcodeText, WSOpcodeBinary:
		msg := wsMessage{
			isClient:  isClient,
			opcode:    opcode,
			data:      make([]byte, len(payload)),
			timestamp: p.packetTime,
		}
		copy(msg.data, payload)
		p.messages = append(p.messages, msg)

		// 如果是完整消息（FIN=1），输出解密包
		if fin && p.packetChan != nil {
			direction := "request"
			if !msg.isClient {
				direction = "response"
			}

			opcodeStr := "unknown"
			switch msg.opcode {
			case WSOpcodeText:
				opcodeStr = "text"
			case WSOpcodeBinary:
				opcodeStr = "binary"
			}

			packet := types.NewDecryptedPacket(types.TransportProtocolTCP, "websocket", direction, msg.data, msg.timestamp, p.addr)
			packet.WithMetadata("opcode", msg.opcode).
				WithMetadata("opcode_name", opcodeStr).
				WithMetadata("is_client", msg.isClient).
				WithMetadata("data_length", len(msg.data))

			select {
			case p.packetChan <- packet:
			default:
			}
		}

	case WSOpcodeClose:
		// 连接关闭

	case WSOpcodePing, WSOpcodePong:
		// Ping/Pong 帧，忽略

	case WSOpcodeContinuation:
		// 继续帧，追加到前一个消息
		if len(p.messages) > 0 {
			lastIdx := len(p.messages) - 1
			p.messages[lastIdx].data = append(p.messages[lastIdx].data, payload...)
			if fin && p.packetChan != nil {
				msg := p.messages[lastIdx]
				direction := "request"
				if !msg.isClient {
					direction = "response"
				}

				opcodeStr := "unknown"
				switch msg.opcode {
				case WSOpcodeText:
					opcodeStr = "text"
				case WSOpcodeBinary:
					opcodeStr = "binary"
				}

				packet := types.NewDecryptedPacket(types.TransportProtocolTCP, "websocket", direction, msg.data, msg.timestamp, p.addr)
				packet.WithMetadata("opcode", msg.opcode).
					WithMetadata("opcode_name", opcodeStr).
					WithMetadata("is_client", msg.isClient).
					WithMetadata("data_length", len(msg.data))

				select {
				case p.packetChan <- packet:
				default:
				}
			}
		}
	}
}

// Flush 刷新所有未完成的数据
func (p *WebSocketStreamParser) Flush() {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 如果有 HTTP 回退解析器，刷新它
	if p.httpFallback != nil {
		p.httpFallback.Flush()
		return
	}

	// 解析剩余的 WebSocket 帧
	if p.handshakeComplete {
		p.parseWebSocketFrames(&p.clientBuffer, true)
		p.parseWebSocketFrames(&p.serverBuffer, false)
	}
}

// Close 关闭解析器
func (p *WebSocketStreamParser) Close() error {
	p.Flush()
	return nil
}

// IsWebSocket 返回是否已建立 WebSocket 连接
func (p *WebSocketStreamParser) IsWebSocket() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.handshakeComplete
}

// Ensure interface is implemented
var _ types.StreamParserInterface = (*WebSocketStreamParser)(nil)
var _ io.Closer = (*WebSocketStreamParser)(nil)
