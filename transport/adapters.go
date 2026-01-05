// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

// adapters.go - 传输层适配器
package transport

import (
	"net"

	"github.com/google/gopacket/layers"
)

// TCPAdapter 适配 TCP 层
type TCPAdapter struct {
	*layers.TCP
}

func (a *TCPAdapter) GetSrcPort() uint16 { return uint16(a.SrcPort) }
func (a *TCPAdapter) GetDstPort() uint16 { return uint16(a.DstPort) }
func (a *TCPAdapter) GetPayload() []byte { return a.LayerPayload() }
func (a *TCPAdapter) IsSYN() bool        { return a.SYN && !a.ACK }
func (a *TCPAdapter) IsFIN() bool        { return a.FIN || a.RST }
func (a *TCPAdapter) Protocol() string   { return "tcp" }

// NewTCPAdapter 创建 TCP 适配器
func NewTCPAdapter(tcp *layers.TCP) *TCPAdapter {
	return &TCPAdapter{TCP: tcp}
}

// UDPAdapter 适配 UDP 层
type UDPAdapter struct {
	*layers.UDP
	isInitial bool // QUIC Initial packet
	isClose   bool // QUIC Connection close
}

func (a *UDPAdapter) GetSrcPort() uint16 { return uint16(a.SrcPort) }
func (a *UDPAdapter) GetDstPort() uint16 { return uint16(a.DstPort) }
func (a *UDPAdapter) GetPayload() []byte { return a.LayerPayload() }
func (a *UDPAdapter) IsSYN() bool        { return a.isInitial }
func (a *UDPAdapter) IsFIN() bool        { return a.isClose }
func (a *UDPAdapter) Protocol() string   { return "udp" }

// NewUDPAdapter 创建 UDP 适配器
func NewUDPAdapter(udp *layers.UDP) *UDPAdapter {
	payload := udp.LayerPayload()
	return &UDPAdapter{
		UDP:       udp,
		isInitial: IsQUICInitialPacket(payload),
	}
}

// IsQUICInitialPacket 检测 QUIC Initial 包
func IsQUICInitialPacket(payload []byte) bool {
	if len(payload) < 5 {
		return false
	}
	// QUIC long header: first bit is 1, second bit is 1 for long header
	// Initial packet type: 0x00 in bits 4-5
	headerByte := payload[0]
	isLongHeader := (headerByte & 0x80) != 0
	packetType := (headerByte & 0x30) >> 4
	return isLongHeader && packetType == 0x00
}

// IPv4Adapter 适配 IPv4 层
type IPv4Adapter struct {
	*layers.IPv4
}

func (a *IPv4Adapter) GetSrcIP() net.IP { return a.SrcIP }
func (a *IPv4Adapter) GetDstIP() net.IP { return a.DstIP }

// NewIPv4Adapter 创建 IPv4 适配器
func NewIPv4Adapter(ip *layers.IPv4) *IPv4Adapter {
	return &IPv4Adapter{IPv4: ip}
}

// IPv6Adapter 适配 IPv6 层
type IPv6Adapter struct {
	*layers.IPv6
}

func (a *IPv6Adapter) GetSrcIP() net.IP { return a.SrcIP }
func (a *IPv6Adapter) GetDstIP() net.IP { return a.DstIP }

// NewIPv6Adapter 创建 IPv6 适配器
func NewIPv6Adapter(ip *layers.IPv6) *IPv6Adapter {
	return &IPv6Adapter{IPv6: ip}
}
