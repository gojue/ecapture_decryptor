// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

// api.go - Public API for TLS/QUIC traffic decryption library
package ecapture_decryptor

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/gojue/ecapture_decryptor/crypto"
	"github.com/gojue/ecapture_decryptor/transport"
	"github.com/gojue/ecapture_decryptor/types"
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
	strictPcapng bool
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

// DecryptPcapFile 解密 pcapng 文件。keylogReader 可为 nil，此时使用文件内
// DSB 中的 SSLKEYLOG；提供外部读取器时，两个来源的密钥都会加载。
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
	// A non-seekable pcapng source cannot be scanned twice. Observe DSB blocks
	// while the packet reader advances, including a DSB after the last packet.
	if _, seekable := config.pcapReader.(io.Seeker); !seekable && config.pcapReader != nil {
		buffered := bufio.NewReader(config.pcapReader)
		config.pcapReader = buffered
		if magic, err := buffered.Peek(4); err == nil && bytes.Equal(magic, []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
			config.pcapReader = &pcapngBlockReader{source: buffered, onTLSSecrets: func(payload []byte) error {
				_, err := keyLog.Write(payload)
				return err
			}}
		}
	}

	engine := &DecryptorEngine{
		config:    config,
		keyLog:    keyLog,
		factory:   NewDecryptorFactory(keyLog, config.logger, config.packetChan),
		conntrack: make(map[string]types.Decryptor),
		tcpFlows:  make(map[string]*tcpConnection),
		logger:    config.logger,
	}

	return engine.Run()
}

// DecryptorEngine 解密引擎
type DecryptorEngine struct {
	config         *DecryptorConfig
	keyLog         *crypto.KeyLogStore
	factory        *DecryptorFactory
	conntrack      map[string]types.Decryptor
	tcpFlows       map[string]*tcpConnection
	nextGeneration uint64
	connections    sync.WaitGroup
	mu             sync.RWMutex // protects conntrack
	logger         *log.Logger
	errMu          sync.Mutex
	connectionErrs []error
}

func (e *DecryptorEngine) recordConnectionError(err error) {
	if err == nil {
		return
	}
	e.errMu.Lock()
	defer e.errMu.Unlock()
	if len(e.connectionErrs) < 16 {
		e.connectionErrs = append(e.connectionErrs, err)
	}
}

func (e *DecryptorEngine) connectionError() error {
	e.errMu.Lock()
	defer e.errMu.Unlock()
	return errors.Join(e.connectionErrs...)
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
		if e.config.strictPcapng {
			if err == nil {
				err = fmt.Errorf("pcapng reader is nil")
			}
			return fmt.Errorf("open pcapng stream: %w", err)
		}
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
func (e *DecryptorEngine) processPcapngFileMode(_ *pcapgo.NgReader) error {
	e.logger.Println("Using file mode for pcapng processing")
	seeker := e.config.pcapReader.(io.Seeker)
	if _, err := seeker.Seek(0, io.SeekStart); err != nil {
		return err
	}
	blocks := &pcapngBlockReader{source: e.config.pcapReader, onTLSSecrets: func(payload []byte) error {
		_, err := e.keyLog.Write(payload)
		return err
	}}
	if _, err := io.Copy(io.Discard, blocks); err != nil {
		return fmt.Errorf("scan pcapng secrets: %w", err)
	}
	if _, err := seeker.Seek(0, io.SeekStart); err != nil {
		return err
	}

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

	packetCount := 0
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
	return e.connectionError()
}

// processPcapngStreamMode 流式模式：一次遍历，边处理边提取 DSB
func (e *DecryptorEngine) processPcapngStreamMode(ngReader *pcapgo.NgReader) (result error) {
	e.logger.Println("Using stream mode for pcapng processing")
	e.logger.Println("Note: DSB blocks will be loaded incrementally as they are encountered")
	defer func() {
		e.waitForAllConnections()
		result = errors.Join(result, e.connectionError())
	}()

	e.logger.Println("Processing packets in streaming mode...")
	packetCount := 0
	// DecryptPcapngStream observes DSB blocks before NgReader consumes them.
	for {
		data, ci, err := ngReader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		packet := gopacket.NewPacket(data, ngReader.LinkType(), gopacket.Default)
		packet.Metadata().Timestamp = ci.Timestamp
		packetCount++
		if packetCount%100 == 0 {
			e.logger.Printf("Processed %d packets so far...", packetCount)
		}
		e.processPacket(packet)
	}

	e.logger.Printf("Finished processing %d packets in streaming mode", packetCount)

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
	return e.connectionError()
}

// waitForAllConnections 等待所有连接处理完成，带超时保护
func (e *DecryptorEngine) waitForAllConnections() {
	e.logger.Println("Waiting for all connections to finish...")
	e.closeAllConnections()
	e.connections.Wait()
	e.logger.Println("All connections finished")
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
func (e *DecryptorEngine) handlePacket(ip types.IPLayer, transportLayer types.TransportLayer, packetTime time.Time) {
	key := types.ConnectionKey{
		SrcIP:       ip.GetSrcIP(),
		DstIP:       ip.GetDstIP(),
		SrcPort:     transportLayer.GetSrcPort(),
		DstPort:     transportLayer.GetDstPort(),
		Proto:       transportLayer.Protocol(),
		Pid:         0,
		FD:          0,
		ProcessName: "decryptor",
	}
	rkey := key.Reverse()
	baseKey := key.String()
	reverseKey := rkey.String()

	var ct types.Decryptor
	var isReverse bool
	var flow *tcpConnection
	var connectionMapKey string

	e.mu.RLock()
	if existingCt, ok := e.conntrack[baseKey]; ok {
		ct = existingCt
		connectionMapKey = baseKey
	} else if existingRct, ok := e.conntrack[reverseKey]; ok {
		ct = existingRct
		isReverse = true
		connectionMapKey = reverseKey
	}
	flow = e.tcpFlows[connectionMapKey]
	e.mu.RUnlock()

	newConnection := transportLayer.IsSYN()
	if tcp, ok := transportLayer.(*transport.TCPAdapter); ok {
		newConnection = tcp.SYN && !tcp.ACK
		if newConnection && ct != nil && flow != nil && flow.hasClientSYN && flow.clientSYNSeq == tcp.Seq {
			return // A duplicated loopback SYN belongs to the existing TCP flow.
		}
	} else if key.Proto == types.TransportProtocolUDP {
		// QUIC retransmits Initial packets in both directions. They belong to
		// the existing flow rather than starting a new TCP-style generation.
		newConnection = newConnection && ct == nil
	}
	if newConnection {
		if ct != nil {
			_ = ct.Close() // A fresh SYN starts a new generation of this tuple.
		}
		e.mu.Lock()
		e.nextGeneration++
		key.Generation = e.nextGeneration
		e.mu.Unlock()
		ct = e.factory.Create(key)
		if ct == nil {
			return
		}
		flow = &tcpConnection{}
		if tcp, ok := transportLayer.(*transport.TCPAdapter); ok {
			flow.client.Start(tcp.Seq + 1)
			flow.clientSYNSeq = tcp.Seq
			flow.hasClientSYN = true
		}
		e.mu.Lock()
		e.conntrack[baseKey] = ct
		e.tcpFlows[baseKey] = flow
		e.connections.Add(1)
		e.mu.Unlock()
		go func() {
			defer e.connections.Done()
			e.logger.Println("START Decrypt", ct.GetAddr())
			if err := ct.Decrypt(); err != nil {
				e.logger.Println("ERROR Decrypt", ct.GetAddr(), err)
				e.recordConnectionError(fmt.Errorf("decrypt TLS connection %s: %w", ct.GetAddr(), err))
			}
			e.logger.Println("DONE Decrypt", ct.GetAddr())
			e.mu.Lock()
			if e.conntrack[baseKey] == ct {
				delete(e.conntrack, baseKey)
				delete(e.tcpFlows, baseKey)
			}
			e.mu.Unlock()
		}()
		// Unlike a TCP SYN, a QUIC Initial datagram carries encrypted handshake
		// data. The decryptor must receive the packet that created the flow.
		if key.Proto == types.TransportProtocolUDP && len(transportLayer.GetPayload()) > 0 {
			ct.SetPacketTime(packetTime)
			if err := ct.FeedClient(transportLayer.GetPayload()); err != nil {
				e.recordConnectionError(fmt.Errorf("feed QUIC connection %s: %w", ct.GetAddr(), err))
				_ = ct.Close()
			}
		}
		return
	}
	if ct == nil {
		return
	}
	payload := transportLayer.GetPayload()
	var chunks [][]byte
	if tcp, ok := transportLayer.(*transport.TCPAdapter); ok {
		if flow == nil {
			return
		}
		direction := &flow.client
		if isReverse {
			direction = &flow.server
		}
		if tcp.SYN && !direction.started {
			direction.Start(tcp.Seq + 1)
		}
		seq := tcp.Seq
		if tcp.SYN {
			seq++
		}
		var err error
		chunks, err = direction.Push(seq, payload)
		if err != nil {
			e.logger.Printf("TCP reassembly failed for %s: %v", ct.GetAddr(), err)
			e.recordConnectionError(fmt.Errorf("reassemble TCP connection %s: %w", ct.GetAddr(), err))
			_ = ct.Close()
			return
		}
	} else if len(payload) > 0 {
		chunks = [][]byte{payload}
	}
	for _, chunk := range chunks {
		ct.SetPacketTime(packetTime)
		var err error
		if isReverse {
			err = ct.FeedServer(chunk)
		} else {
			err = ct.FeedClient(chunk)
		}
		if err != nil {
			e.logger.Printf("feed TLS connection %s: %v", ct.GetAddr(), err)
			e.recordConnectionError(fmt.Errorf("feed TLS connection %s: %w", ct.GetAddr(), err))
			_ = ct.Close()
			return
		}
	}
	if transportLayer.IsFIN() {
		if isReverse {
			_ = ct.CloseServer()
		} else {
			_ = ct.CloseClient()
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
