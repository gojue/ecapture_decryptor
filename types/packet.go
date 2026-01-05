// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

// Package types - Decrypted packet types
package types

import (
	"encoding/json"
	"time"
)

// DecryptedPacket represents a decrypted application layer packet
type DecryptedPacket struct {
	// ConnectionKey uniquely identifies the connection
	uuid ConnectionKey

	// Transport indicates the transport layer protocol (tcp/udp)
	Transport string `json:"transport"`

	// Protocol identifies the application layer protocol (http/1.1, http/2, websocket, http/3, etc.)
	Protocol string `json:"protocol"`

	// Direction indicates the packet direction: "request" (client->server) or "response" (server->client)
	Direction string `json:"direction"`

	// Data contains the decrypted application layer data
	Data []byte `json:"-"`

	// Timestamp is the packet capture time
	Timestamp time.Time `json:"timestamp"`

	// Metadata contains protocol-specific metadata
	Metadata map[string]interface{} `json:"metadata"`

	// SrcIP is the source IP address from the packet
	SrcIP string `json:"srcIP"`

	// SrcPort is the source port from the packet
	SrcPort uint32 `json:"srcPort"`

	// DstIP is the destination IP address from the packet
	DstIP string `json:"dstIP"`

	// DstPort is the destination port from the packet
	DstPort uint32 `json:"dstPort"`

	// PID is the process ID associated with the connection
	PID int64 `json:"PID"`

	// PName is the process name associated with the connection
	PName string `json:"PName"`

	// DataLength is the length of the decrypted data
	DataLength uint32 `json:"dataLength"`
}

// NewDecryptedPacket creates a new decrypted packet
func NewDecryptedPacket(tProtocol, protocol, direction string, data []byte, timestamp time.Time, ci ConnectionKey) *DecryptedPacket {
	return &DecryptedPacket{
		uuid:       ci,
		Transport:  tProtocol,
		Protocol:   protocol,
		Direction:  direction,
		Data:       data,
		Timestamp:  timestamp,
		SrcIP:      ci.SrcIP.String(),
		SrcPort:    uint32(ci.SrcPort),
		DstIP:      ci.DstIP.String(),
		DstPort:    uint32(ci.DstPort),
		PID:        int64(ci.Pid),
		PName:      ci.ProcessName,
		Metadata:   make(map[string]interface{}),
		DataLength: uint32(len(data)),
	}
}

// WithMetadata adds metadata to the packet
func (p *DecryptedPacket) WithMetadata(key string, value interface{}) *DecryptedPacket {
	p.Metadata[key] = value
	return p
}

// IsRequest returns true if this is a request packet
func (p *DecryptedPacket) IsRequest() bool {
	return p.Direction == "request"
}

// IsResponse returns true if this is a response packet
func (p *DecryptedPacket) IsResponse() bool {
	return p.Direction == "response"
}

func (p *DecryptedPacket) Meta() string {
	s, e := json.Marshal(p)
	if e != nil {
		return "{}"
	}
	return string(s)
}

func (p *DecryptedPacket) ConnectionID() string {
	return p.uuid.String()
}
