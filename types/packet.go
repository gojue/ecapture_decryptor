// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

// Package types - Decrypted packet types
package types

import (
	"bytes"
	"encoding/json"
	"sync"
	"time"
)

// ProcessArgs preserves argv bytes from the capture side, including NUL separators.
// Truncated means Data contains only the first 256 bytes and may end mid-argument.
// JSON encodes Data as base64 so even non-UTF-8 arguments survive unchanged.
type ProcessArgs struct {
	Data      []byte `json:"data"`
	Truncated bool   `json:"truncated"`
}

func (a *ProcessArgs) clone() *ProcessArgs {
	if a == nil {
		return nil
	}
	return &ProcessArgs{Data: bytes.Clone(a.Data), Truncated: a.Truncated}
}

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

	// ProcessArgs is a capture-time argv snapshot. Nil means unavailable.
	ProcessArgs *ProcessArgs `json:"processArgs,omitempty"`

	// DataLength is the length of the decrypted data
	DataLength uint32 `json:"dataLength"`
}

// NewDecryptedPacket creates a new decrypted packet
func NewDecryptedPacket(tProtocol, protocol, direction string, data []byte, timestamp time.Time, ci ConnectionKey) *DecryptedPacket {
	p := &DecryptedPacket{
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
	if ci.Process != nil {
		p.PID, p.PName, p.ProcessArgs = ci.Process.identity(direction)
	}
	if metadata := ci.TLS.Snapshot(); len(metadata) > 0 {
		p.Metadata["tls"] = metadata
	}
	if direction == "response" {
		p.SrcIP, p.DstIP = p.DstIP, p.SrcIP
		p.SrcPort, p.DstPort = p.DstPort, p.SrcPort
	}
	return p
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

// ConnectionProcess records capture-side endpoint ownership, independently of
// the immutable connection key. One instance belongs to one connection generation.
// Source/destination mean client/server in this state, not the current packet.
type ConnectionProcess struct {
	mu     sync.RWMutex
	owners [3]processOwner // client, server, legacy unspecified endpoint
}

type processOwner struct {
	pid      uint32
	name     string
	args     *ProcessArgs
	conflict bool
}

// Observe adds a capture observation: endpoint 1 = source, 2 = destination,
// 0 = legacy unspecified. Conflicting owners remain unknown for this generation.
func (p *ConnectionProcess) Observe(pid uint32, name string, endpoint uint32) {
	p.ObserveWithArgs(pid, name, endpoint, nil)
}

// ObserveWithArgs adds the optional argv snapshot to a process observation.
func (p *ConnectionProcess) ObserveWithArgs(pid uint32, name string, endpoint uint32, args *ProcessArgs) {
	if p == nil || pid == 0 || endpoint > 2 {
		return
	}
	index := 2
	if endpoint != 0 {
		index = int(endpoint) - 1
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	o := &p.owners[index]
	if o.pid != 0 && o.pid != pid {
		o.conflict = true
	}
	if !o.conflict {
		o.pid, o.name = pid, name
		if args != nil && len(args.Data) > 0 && len(args.Data) <= 256 && ((!args.Truncated && args.Data[len(args.Data)-1] == 0) || (args.Truncated && len(args.Data) == 256)) {
			o.args = args.clone()
		}
	}
}

// Merge maps a packet's source/destination observations into connection direction.
func (p *ConnectionProcess) Merge(packet *ConnectionProcess, reverse bool) {
	if p == nil || packet == nil || p == packet {
		return
	}
	packet.mu.RLock()
	owners := packet.owners
	packet.mu.RUnlock()
	if reverse {
		owners[0], owners[1] = owners[1], owners[0]
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, n := range owners {
		o := &p.owners[i]
		if n.conflict || (o.pid != 0 && n.pid != 0 && o.pid != n.pid) {
			o.conflict = true
		}
		if !o.conflict && n.pid != 0 {
			o.pid, o.name = n.pid, n.name
			if n.args != nil {
				o.args = n.args
			} // immutable snapshot
		}
	}
}

// Identity selects the emitting endpoint when both endpoints are local. With
// one observed local endpoint, both directions belong to that local process.
// Legacy trailers cannot disambiguate two owners, so conflicting legacy data
// remains unknown. No PID is inferred from a tuple or opaque connection ID.
func (p *ConnectionProcess) Identity(direction string) (int64, string) {
	pid, name, _ := p.identity(direction)
	return pid, name
}

func (p *ConnectionProcess) identity(direction string) (int64, string, *ProcessArgs) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	src, dst := p.owners[0], p.owners[1]
	if direction == "response" {
		src, dst = dst, src
	}
	if src.conflict {
		return 0, "", nil
	}
	if src.pid != 0 {
		return int64(src.pid), src.name, src.args.clone()
	}
	if dst.conflict {
		return 0, "", nil
	}
	if dst.pid != 0 {
		return int64(dst.pid), dst.name, dst.args.clone()
	}
	old := p.owners[2]
	if old.conflict {
		return 0, "", nil
	}
	return int64(old.pid), old.name, old.args.clone()
}

// ConnectionTLS holds non-secret handshake observations. Application callbacks
// receive independent snapshots; later observations never mutate emitted events.
type ConnectionTLS struct {
	mu     sync.RWMutex
	fields map[string]string
}

func (c *ConnectionTLS) Observe(fields map[string]string) {
	if c == nil || len(fields) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fields == nil {
		c.fields = make(map[string]string)
	}
	for key, value := range fields {
		if value != "" {
			c.fields[key] = value
		}
	}
}
func (c *ConnectionTLS) Snapshot() map[string]string {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.fields) == 0 {
		return nil
	}
	result := make(map[string]string, len(c.fields))
	for key, value := range c.fields {
		result[key] = value
	}
	return result
}
