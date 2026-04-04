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
	"os"
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
		config.logger = log.New(os.Stdout, "", 0)
	}

	keyLog, err := crypto.NewKeyLogStoreFromReader(config.sslKeyLogger)
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
	e.logger.Println("DecryptorEngine.Run() started")

	// 首先尝试使用 pcapng reader（它也支持提取解密密钥）
	e.logger.Println("Attempting to open as pcapng format...")
	options := pcapgo.DefaultNgReaderOptions
	options.SkipUnknownVersion = true
	ngReader, err := pcapgo.NewNgReader(e.config.pcapReader, options)
	if err != nil || ngReader == nil {
		e.logger.Println("Failed to open as pcapng format, falling back to legacy Pcap:", err)
		// Fall back to legacy pcap format
		return e.processLegacyPcap()
	}
	return e.processPcapng(ngReader)
}

// processPcapng 处理 pcapng 格式，支持流式和文件两种模式
func (e *DecryptorEngine) processPcapng(ngReader *pcapgo.NgReader) error {
	// 检查是否可以 seek（文件模式 vs 流式模式）
	canSeek := false
	if seeker, ok := e.config.pcapReader.(io.Seeker); ok {
		// 测试是否真的可以 seek
		currentPos, err := seeker.Seek(0, io.SeekCurrent)
		if err == nil {
			canSeek = true
			e.logger.Printf("File mode detected (can seek), current position: %d", currentPos)
		}
	}

	if canSeek {
		// 文件模式：两次遍历，第一次提取 DSB，第二次处理包
		return e.processPcapngFileMode(ngReader)
	} else {
		// 流式模式：一次遍历，边读取边处理
		return e.processPcapngStreamMode(ngReader)
	}
}

// processPcapngFileMode 文件模式：先提取 DSB，再重新读取处理包
func (e *DecryptorEngine) processPcapngFileMode(ngReader *pcapgo.NgReader) error {
	e.logger.Println("Using file mode for pcapng processing")

	// 第一遍：读取所有包以触发 DSB 收集
	e.logger.Println("First pass: collecting Decryption Secrets Blocks...")
	packetCount := 0
	for {
		_, _, err := ngReader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			e.logger.Printf("Warning: error reading packet data: %v", err)
			continue
		}
		packetCount++
	}
	e.logger.Printf("First pass completed, scanned %d packets", packetCount)

	// 提取并加载 DSB
	dsbs := ngReader.GetDecryptionSecretsBlocks()
	e.logger.Printf("Found %d Decryption Secrets Blocks in pcapng", len(dsbs))
	for i, dsb := range dsbs {
		payload := dsb.Payload()
		n, writeErr := e.keyLog.Write(payload)
		if writeErr != nil {
			e.logger.Printf("Warning: failed to write DSB #%d: %v", i, writeErr)
		} else {
			e.logger.Printf("Loaded DSB #%d: %d bytes written to keylog", i+1, n)
		}
	}

	// Seek 回到文件开头
	seeker := e.config.pcapReader.(io.Seeker)
	_, err := seeker.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}
	e.logger.Println("Seeked back to start of file for second pass")

	// 重新创建 reader 进行第二遍读取
	options := pcapgo.DefaultNgReaderOptions
	options.SkipUnknownVersion = true
	ngReader2, err := pcapgo.NewNgReader(e.config.pcapReader, options)
	if err != nil {
		return err
	}

	// 第二遍：处理包
	e.logger.Println("Second pass: processing packets...")
	packetSource := gopacket.NewPacketSource(ngReader2, ngReader2.LinkType())
	packetSource.NoCopy = true

	packetCount = 0
	for packet := range packetSource.Packets() {
		packetCount++
		if packetCount%100 == 0 {
			e.logger.Printf("Processed %d packets so far...", packetCount)
		}
		e.processPacket(packet)
	}
	e.logger.Printf("Finished processing %d packets", packetCount)

	// 等待所有解密 goroutine 完成
	e.waitForAllConnections()
	e.logger.Println("DecryptorEngine.Run() completed successfully")
	return nil
}

// processPcapngStreamMode 流式模式：一次遍历，边处理边提取 DSB
func (e *DecryptorEngine) processPcapngStreamMode(ngReader *pcapgo.NgReader) error {
	e.logger.Println("Using stream mode for pcapng processing")
	e.logger.Println("Note: DSB blocks will be loaded incrementally as they are encountered")

	packetSource := gopacket.NewPacketSource(ngReader, ngReader.LinkType())
	packetSource.NoCopy = true

	e.logger.Println("Processing packets in streaming mode...")
	packetCount := 0
	lastDSBCount := 0

	for packet := range packetSource.Packets() {

		packetCount++
		if packetCount%100 == 0 {
			e.logger.Printf("Processed %d packets so far...", packetCount)
		}
		e.processPacket(packet)
	}

	// 最后再检查一次是否有遗漏的 DSB
	finalDSBs := ngReader.GetDecryptionSecretsBlocks()
	if len(finalDSBs) > lastDSBCount {
		e.logger.Printf("Found additional DSB blocks at end: %d -> %d", lastDSBCount, len(finalDSBs))
		for i := lastDSBCount; i < len(finalDSBs); i++ {
			dsb := finalDSBs[i]
			payload := dsb.Payload()
			n, writeErr := e.keyLog.Write(payload)
			if writeErr != nil {
				e.logger.Printf("Warning: failed to write DSB #%d: %v", i, writeErr)
			} else {
				e.logger.Printf("Loaded DSB #%d: %d bytes written to keylog", i+1, n)
			}
		}
	}

	e.logger.Printf("Finished processing %d packets in streaming mode", packetCount)

	// 等待所有解密 goroutine 完成
	e.waitForAllConnections()
	e.logger.Println("DecryptorEngine.Run() completed successfully")
	return nil
}

// processLegacyPcap 处理传统 pcap 格式文件
func (e *DecryptorEngine) processLegacyPcap() error {
	e.logger.Println("Using legacy pcap format")

	// 如果 reader 支持 seek，需要先回到文件开头
	if seeker, ok := e.config.pcapReader.(io.Seeker); ok {
		_, err := seeker.Seek(0, io.SeekStart)
		if err != nil {
			e.logger.Printf("Warning: failed to seek to start: %v", err)
		} else {
			e.logger.Println("Seeked back to start of file for legacy pcap format")
		}
	}

	// 尝试打开为传统 pcap 格式
	pcapReader, err := pcapgo.NewReader(e.config.pcapReader)
	if err != nil {
		e.logger.Printf("Failed to open as legacy pcap format: %v", err)
		return err
	}

	e.logger.Printf("Successfully opened legacy pcap format, link type: %v", pcapReader.LinkType())

	packetSource := gopacket.NewPacketSource(pcapReader, pcapReader.LinkType())
	packetSource.NoCopy = true

	e.logger.Println("Processing packets from legacy pcap...")
	packetCount := 0
	for packet := range packetSource.Packets() {
		packetCount++
		if packetCount%100 == 0 {
			e.logger.Printf("Processed %d packets so far...", packetCount)
		}
		e.processPacket(packet)
	}
	e.logger.Printf("Finished processing %d packets from legacy pcap", packetCount)

	// 等待所有解密 goroutine 完成
	e.waitForAllConnections()
	e.logger.Println("DecryptorEngine.Run() completed successfully")
	return nil
}

// waitForAllConnections 等待所有连接处理完成，带超时保护
func (e *DecryptorEngine) waitForAllConnections() {
	e.logger.Println("Waiting for all connections to finish...")

	// 首先关闭所有连接
	e.closeAllConnections()

	// 等待最多 5 秒，让 goroutine 完成
	done := make(chan struct{})
	go func() {
		for {
			e.mu.RLock()
			count := len(e.conntrack)
			e.mu.RUnlock()

			if count == 0 {
				close(done)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	select {
	case <-done:
		e.logger.Println("All connections finished")
	case <-time.After(5 * time.Second):
		e.logger.Println("Warning: timeout waiting for connections to finish")
	}
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
		_ = dec.Close()
	}
}
