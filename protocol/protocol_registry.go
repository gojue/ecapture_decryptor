// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

// protocol_registry.go - 协议解析器注册机制
package protocol

import (
	"sync"

	"github.com/cfc4n/ecapture_decryptor/types"
)

// protocolRegistry 全局协议注册表
var (
	protocolRegistry   []types.ProtocolDetector
	protocolRegistryMu sync.RWMutex
)

// RegisterProtocol 注册一个协议检测器
func RegisterProtocol(detector types.ProtocolDetector) {
	protocolRegistryMu.Lock()
	defer protocolRegistryMu.Unlock()
	protocolRegistry = append(protocolRegistry, detector)
}

// DetectProtocol 检测数据对应的协议，返回最佳匹配的解析器
func DetectProtocol(data []byte, ci types.ConnectionKey, packetChan chan *types.DecryptedPacket) (types.StreamParserInterface, string) {
	protocolRegistryMu.RLock()
	defer protocolRegistryMu.RUnlock()

	var bestDetector types.ProtocolDetector
	bestScore := 0

	for _, detector := range protocolRegistry {
		score := detector.Detect(data)
		if score > bestScore {
			bestScore = score
			bestDetector = detector
		}
	}

	if bestDetector != nil && bestScore > 0 {
		return bestDetector.CreateParser(ci, packetChan), bestDetector.Name()
	}

	return nil, ""
}

// HTTP1Detector HTTP/1.x 协议检测器
type HTTP1Detector struct{}

func (d *HTTP1Detector) Name() string {
	return "HTTP/1.x"
}

func (d *HTTP1Detector) Detect(data []byte) int {
	if len(data) < 4 {
		return 0
	}

	methods := []string{"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI", "CONN", "TRAC"}
	dataPrefix := string(data[:4])
	for _, method := range methods {
		if dataPrefix == method {
			return 50
		}
	}

	return 0
}

func (d *HTTP1Detector) CreateParser(ci types.ConnectionKey, packetChan chan *types.DecryptedPacket) types.StreamParserInterface {
	return NewHTTPStreamParser(ci, packetChan)
}

// HTTP2Detector HTTP/2 协议检测器
type HTTP2Detector struct{}

func (d *HTTP2Detector) Name() string {
	return "HTTP/2"
}

func (d *HTTP2Detector) Detect(data []byte) int {
	if IsHTTP2(data) {
		return 100
	}
	return 0
}

func (d *HTTP2Detector) CreateParser(ci types.ConnectionKey, packetChan chan *types.DecryptedPacket) types.StreamParserInterface {
	return NewHTTP2StreamParser(ci, packetChan)
}

// WebSocketDetector WebSocket 协议检测器
type WebSocketDetector struct{}

func (d *WebSocketDetector) Name() string {
	return "WebSocket"
}

func (d *WebSocketDetector) Detect(data []byte) int {
	if IsWebSocketUpgrade(data) {
		return 90
	}
	return 0
}

func (d *WebSocketDetector) CreateParser(addr types.ConnectionKey, packetChan chan *types.DecryptedPacket) types.StreamParserInterface {
	return NewWebSocketStreamParser(addr, packetChan)
}

// init 自动注册所有内置协议检测器
func init() {
	RegisterProtocol(&HTTP2Detector{})
	RegisterProtocol(&WebSocketDetector{})
	RegisterProtocol(&HTTP1Detector{})
}
