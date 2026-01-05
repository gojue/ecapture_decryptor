// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

// api.go - Public API for TLS/QUIC traffic decryption library
package ecapture_decryptor

import (
	"io"
	"log"
	"sync"
	"time"

	"github.com/cfc4n/ecapture_decryptor/crypto"
	"github.com/cfc4n/ecapture_decryptor/transport"
	"github.com/cfc4n/ecapture_decryptor/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// DecryptorConfig 解密器配置
type DecryptorConfig struct {
	sslKeyLogger io.Reader
	pcapReader   io.Reader
	packetChan   chan *types.DecryptedPacket
	logger       *log.Logger
}

// NewDecryptorConfig 创建默认配置
func NewDecryptorConfig() *DecryptorConfig {
	return &DecryptorConfig{}
}

// WithSSLKeyLog 设置 SSL keylog 读取器
func (c *DecryptorConfig) WithSSLKeyLog(reader io.Reader) *DecryptorConfig {
	c.sslKeyLogger = reader
	return c
}

// WithPcapReader 设置 pcap 数据源
func (c *DecryptorConfig) WithPcapReader(reader io.Reader) *DecryptorConfig {
	c.pcapReader = reader
	return c
}

// WithPacketChan 设置解密包输出通道
func (c *DecryptorConfig) WithPacketChan(ch chan *types.DecryptedPacket) *DecryptorConfig {
	c.packetChan = ch
	return c
}

// WithLogger 设置日志记录器
func (c *DecryptorConfig) WithLogger(logger *log.Logger) *DecryptorConfig {
	c.logger = logger
	return c
}

// DecryptLiveTraffic 解密实时流量
func DecryptLiveTraffic(keylogReader io.Reader, pcapHandle io.Reader, packetChan chan *types.DecryptedPacket) error {
	config := NewDecryptorConfig().
		WithSSLKeyLog(keylogReader).
		WithPcapReader(pcapHandle).
		WithPacketChan(packetChan)

	return DecryptWithConfig(config)
}

// DecryptPcapFile 解密 pcapng 文件
func DecryptPcapFile(keylogReader io.Reader, pcapFileHandle io.Reader, packetChan chan *types.DecryptedPacket) error {
	config := NewDecryptorConfig().
		WithSSLKeyLog(keylogReader).
		WithPcapReader(pcapFileHandle).
		WithPacketChan(packetChan)

	return DecryptWithConfig(config)
}

// DecryptWithConfig 使用配置解密流量
func DecryptWithConfig(config *DecryptorConfig) error {
	if config.logger == nil {
		config.logger = log.New(io.Discard, "", 0)
	}

	keyLog, err := crypto.NewKeyLogStore(config.sslKeyLogger)
	if err != nil {
		return err
	}

	engine := &DecryptorEngine{
		config:    config,
		keyLog:    keyLog,
		factory:   NewDecryptorFactory(keyLog, config.logger, config.packetChan),
		conntrack: make(map[string]types.Decryptor),
		logger:    config.logger,
	}

	return engine.Run()
}

// DecryptorEngine 解密引擎
type DecryptorEngine struct {
	config    *DecryptorConfig
	keyLog    *crypto.KeyLogStore
	factory   *DecryptorFactory
	conntrack map[string]types.Decryptor
	mu        sync.RWMutex // protects conntrack
	logger    *log.Logger
}

// Run 运行解密引擎
func (e *DecryptorEngine) Run() error {
	rd, err := pcapgo.NewReader(e.config.pcapReader)
	if err != nil {
		return err
	}

	packetSource := gopacket.NewPacketSource(rd, rd.LinkType())
	packetSource.NoCopy = true

	for packet := range packetSource.Packets() {
		e.processPacket(packet)
	}

	e.closeAllConnections()
	return nil
}

// processPacket processes a single packet
func (e *DecryptorEngine) processPacket(packet gopacket.Packet) {
	var tl types.TransportLayer
	var ipLayer types.IPLayer

	if ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		ipLayer = transport.NewIPv4Adapter(ip)
	} else if ip6, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		ipLayer = transport.NewIPv6Adapter(ip6)
	} else {
		return
	}

	packetTime := packet.Metadata().Timestamp

	if l := packet.Layer(layers.LayerTypeTCP); l != nil {
		tcp, _ := l.(*layers.TCP)
		tl = transport.NewTCPAdapter(tcp)
		e.handlePacket(ipLayer, tl, packetTime)
	}

	if l := packet.Layer(layers.LayerTypeUDP); l != nil {
		udp, _ := l.(*layers.UDP)
		tl = transport.NewUDPAdapter(udp)
		e.handlePacket(ipLayer, tl, packetTime)
	}
}

// handlePacket handles a packet
func (e *DecryptorEngine) handlePacket(ip types.IPLayer, transport types.TransportLayer, packetTime time.Time) {
	key := types.ConnectionKey{
		SrcIP:       ip.GetSrcIP(),
		DstIP:       ip.GetDstIP(),
		SrcPort:     transport.GetSrcPort(),
		DstPort:     transport.GetDstPort(),
		Proto:       transport.Protocol(),
		Pid:         0,
		FD:          0,
		ProcessName: "decryptor",
	}
	rkey := key.Reverse()

	var ct types.Decryptor
	var isReverse bool

	// Check if connection exists (read lock)
	e.mu.RLock()
	if existingCt, ok := e.conntrack[key.String()]; ok {
		ct = existingCt
	} else if existingRct, ok := e.conntrack[rkey.String()]; ok {
		ct = existingRct
		isReverse = true
	}
	e.mu.RUnlock()

	if transport.IsSYN() && ct == nil {
		ct = e.factory.Create(key)
		if ct == nil {
			return
		}

		// Store new connection (write lock)
		e.mu.Lock()
		e.conntrack[key.String()] = ct
		e.mu.Unlock()

		go func() {
			e.logger.Println("START Decrypt", ct.GetAddr())
			if err := ct.Decrypt(); err != nil {
				e.logger.Println("ERROR Decrypt", key.String(), err)
			}
			e.logger.Println("DONE Decrypt", ct.GetAddr())

			// Delete connection (write lock)
			e.mu.Lock()
			delete(e.conntrack, key.String())
			e.mu.Unlock()
		}()
		return
	}

	if transport.IsFIN() {
		if ct != nil {
			if isReverse {
				_ = ct.CloseServer()
			} else {
				_ = ct.CloseClient()
			}
		}
		return
	}

	payload := transport.GetPayload()
	if len(payload) == 0 || ct == nil {
		return
	}

	ct.SetPacketTime(packetTime)

	if isReverse {
		if err := ct.FeedServer(payload); err != nil {
			e.logger.Println("ERROR FeedServer", key.String(), err)
		}
	} else {
		if err := ct.FeedClient(payload); err != nil {
			e.logger.Println("ERROR FeedClient", key.String(), err)
		}
	}
}

// closeAllConnections closes all tracked connections
func (e *DecryptorEngine) closeAllConnections() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, dec := range e.conntrack {
		dec.Close()
	}
}
