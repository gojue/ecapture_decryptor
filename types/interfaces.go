// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

// Package types defines common types and interfaces used across all packages
package types

import (
	"fmt"
	"net"
	"time"
)

const (
	TransportProtocolTCP = "tcp"
	TransportProtocolUDP = "udp"
)

// TransportLayer 传输层抽象接口
type TransportLayer interface {
	GetSrcPort() uint16
	GetDstPort() uint16
	GetPayload() []byte
	IsSYN() bool      // TCP: SYN flag; UDP/QUIC: Initial packet
	IsFIN() bool      // TCP: FIN/RST; UDP/QUIC: Connection close
	Protocol() string // "tcp" or "udp"
}

// Decryptor 解密器抽象接口
type Decryptor interface {
	Decrypt() error
	FeedClient(data []byte) error
	FeedServer(data []byte) error
	SetPacketTime(t time.Time)
	CloseClient() error
	CloseServer() error
	Close() error
	GetAddr() ConnectionKey
}

// IPLayer IP层抽象接口
type IPLayer interface {
	GetSrcIP() net.IP
	GetDstIP() net.IP
}

// ConnectionKey 连接标识
type ConnectionKey struct {
	SrcIP       net.IP
	DstIP       net.IP
	SrcPort     uint16
	DstPort     uint16
	Proto       string
	Pid         int
	FD          int
	ProcessName string
	Generation  uint64
}

func (k ConnectionKey) String() string {
	return fmt.Sprintf("%d-%d-%s/%s:%d--%s:%d/%s#%d", k.Pid, k.FD, k.ProcessName, k.SrcIP, k.SrcPort, k.DstIP, k.DstPort, k.Proto, k.Generation)
}

func (k ConnectionKey) Reverse() ConnectionKey {
	return ConnectionKey{
		SrcIP:       k.DstIP,
		DstIP:       k.SrcIP,
		SrcPort:     k.DstPort,
		DstPort:     k.SrcPort,
		Proto:       k.Proto,
		Pid:         k.Pid,
		FD:          k.FD,
		ProcessName: k.ProcessName,
		Generation:  k.Generation,
	}
}

// StreamParserInterface 流解析器接口
type StreamParserInterface interface {
	FeedRequest(data []byte)
	FeedResponse(data []byte)
	SetPacketTime(t time.Time)
	Flush()
}

// ProtocolDetector 协议检测接口
type ProtocolDetector interface {
	Name() string
	Detect(data []byte) int
	CreateParser(addr ConnectionKey, packetChan chan *DecryptedPacket) StreamParserInterface
}
