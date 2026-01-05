// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

package transport

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/cfc4n/ecapture_decryptor/crypto"
	"github.com/cfc4n/ecapture_decryptor/protocol"
	"github.com/cfc4n/ecapture_decryptor/types"
)

// DecryptedData represents decrypted application data with direction
type DecryptedData struct {
	//Direction string
	Data      []byte
	SeqNum    uint64 // Sequence number for ordering
	IsRequest bool   // true for client->server (request), false for server->client (response)
}

// TLSDecryptor decrypts TLS traffic using standard crypto/tls
type TLSDecryptor struct {
	ConnectionInfo           types.ConnectionKey
	keyLog                   *crypto.KeyLogStore
	clientIn                 *crypto.StreamBuffer
	serverIn                 *crypto.StreamBuffer
	clientOut                io.Writer
	serverOut                io.Writer
	logger                   *log.Logger
	clientDecryptor          *crypto.RecordDecryptor
	serverDecryptor          *crypto.RecordDecryptor
	clientHandshakeDecryptor *crypto.RecordDecryptor // TLS 1.3 only
	serverHandshakeDecryptor *crypto.RecordDecryptor // TLS 1.3 only
	handshakeComplete        bool
	version                  uint16
	cipherSuite              uint16
	outputMu                 sync.Mutex   // Mutex for synchronized output
	handshakeMu              sync.RWMutex // Protects handshake-related fields

	// For ordered output - separate queues for requests and responses
	requestQueue  []*DecryptedData // Queue for client requests
	responseQueue []*DecryptedData // Queue for server responses
	seqNum        uint64           // Global sequence number
	outputDone    chan struct{}
	queueMu       sync.Mutex // Mutex for queue operations

	// Client state for inline decryption
	clientEncryptionStarted bool
	clientInHandshakePhase  bool
	clientCurrentDecryptor  *crypto.RecordDecryptor

	// Server state for inline decryption
	serverEncryptionStarted bool
	serverInHandshakePhase  bool
	serverCurrentDecryptor  *crypto.RecordDecryptor

	// Close protection
	closeOnce sync.Once
	isClosed  bool // Track if connection is closed to suppress spurious errors

	// Track if we've seen a request before outputting responses
	hasSeenRequest bool

	// Protocol stream parser for HAR output (HTTP/1.x, HTTP/2, or WebSocket)
	parser types.StreamParserInterface

	// Protocol detection
	protocolDetected bool
	protocolMu       sync.RWMutex                // Protects parser and protocolDetected
	packetChan       chan *types.DecryptedPacket // 解密包输出通道

	// Packet timestamp from pcap
	packetTime time.Time
}

// NewTLSDecryptor 创建 TLS 解密器
func NewTLSDecryptor(ci types.ConnectionKey, keyLog *crypto.KeyLogStore, clientOut, serverOut io.Writer, logger *log.Logger, packetChan chan *types.DecryptedPacket) *TLSDecryptor {
	td := &TLSDecryptor{
		ConnectionInfo: ci,
		keyLog:         keyLog,
		clientIn:       crypto.NewStreamBuffer(),
		serverIn:       crypto.NewStreamBuffer(),
		clientOut:      clientOut,
		serverOut:      serverOut,
		logger:         logger,
		requestQueue:   make([]*DecryptedData, 0),
		responseQueue:  make([]*DecryptedData, 0),
		outputDone:     make(chan struct{}),
		packetChan:     packetChan,
	}

	return td
}

// SetPacketTime sets the packet timestamp from pcap
func (td *TLSDecryptor) SetPacketTime(t time.Time) {
	td.packetTime = t
	if td.parser != nil {
		td.parser.SetPacketTime(t)
	}
}

// queueRequest adds a request to the queue and flushes if possible
func (td *TLSDecryptor) queueRequest(data []byte) {
	if len(data) == 0 {
		return
	}

	// Detect protocol on first data
	td.protocolMu.RLock()
	detected := td.protocolDetected
	td.protocolMu.RUnlock()

	if !detected && td.packetChan != nil {
		td.detectProtocol(data)
	}

	// Feed data to parser for HAR output
	td.protocolMu.RLock()
	parser := td.parser
	td.protocolMu.RUnlock()

	if parser != nil {
		parser.FeedRequest(data)
	}

	td.queueMu.Lock()
	defer td.queueMu.Unlock()

	td.seqNum++
	td.requestQueue = append(td.requestQueue, &DecryptedData{
		Data:      data,
		SeqNum:    td.seqNum,
		IsRequest: true,
	})
	td.hasSeenRequest = true

	// Flush output
	td.flushOutput()
}

// queueResponse adds a response to the queue and flushes if possible
func (td *TLSDecryptor) queueResponse(data []byte) {
	if len(data) == 0 {
		return
	}

	// Feed data to parser for HAR output
	td.protocolMu.RLock()
	parser := td.parser
	td.protocolMu.RUnlock()

	if parser != nil {
		parser.FeedResponse(data)
	}

	td.queueMu.Lock()
	defer td.queueMu.Unlock()

	td.seqNum++
	td.responseQueue = append(td.responseQueue, &DecryptedData{
		Data:      data,
		SeqNum:    td.seqNum,
		IsRequest: false,
	})

	// Flush output
	td.flushOutput()
}

// flushOutput outputs data in the correct order: requests before responses
// Must be called with queueMu held
func (td *TLSDecryptor) flushOutput() {
	// First, output all pending requests
	for len(td.requestQueue) > 0 {
		req := td.requestQueue[0]
		td.requestQueue = td.requestQueue[1:]
		td.writeOutput(req)
	}

	// Only output responses if we've seen at least one request
	if !td.hasSeenRequest {
		return
	}

	// Then output all pending responses
	for len(td.responseQueue) > 0 {
		resp := td.responseQueue[0]
		td.responseQueue = td.responseQueue[1:]
		td.writeOutput(resp)
	}
}

// writeOutput writes a single decrypted data item to output
func (td *TLSDecryptor) writeOutput(data *DecryptedData) {
	if len(data.Data) == 0 {
		return
	}

	// If packetChan is set, we're in library mode - data is output through protocol parser
	// Don't output raw data to stdout to avoid duplication and bypassing the parser
	if td.packetChan != nil {
		return
	}

	// Command-line mode: output raw decrypted data to stdout
	// 检查数据是否主要是可打印字符
	isPrintable := true
	nonPrintableCount := 0
	sampleSize := len(data.Data)
	if sampleSize > 1024 {
		sampleSize = 1024 // 只检查前1024字节
	}

	for i := 0; i < sampleSize; i++ {
		b := data.Data[i]
		if (b < 32 && b != '\n' && b != '\r' && b != '\t') || b == 127 {
			nonPrintableCount++
		}
	}
	// 如果超过10%是不可打印字符，认为是二进制数据
	if float64(nonPrintableCount)/float64(sampleSize) > 0.1 && nonPrintableCount > 10 {
		isPrintable = false
	}

	fmt.Fprintf(td.clientOut, "\nSeq:%d %s, len:%d\n", data.SeqNum, td.ConnectionInfo, len(data.Data))

	if isPrintable {
		// 可打印数据，直接输出
		td.clientOut.Write(data.Data)
	} else {
		// 二进制数据，只显示摘要信息
		previewLen := 64
		if len(data.Data) < previewLen {
			previewLen = len(data.Data)
		}
		fmt.Fprintf(td.clientOut, "[Binary data, showing first %d bytes in hex]\n", previewLen)
		for i := 0; i < previewLen; i++ {
			if i > 0 && i%16 == 0 {
				fmt.Fprintln(td.clientOut)
			}
			fmt.Fprintf(td.clientOut, "%02x ", data.Data[i])
		}
		if len(data.Data) > previewLen {
			fmt.Fprintf(td.clientOut, "\n... (%d more bytes)\n", len(data.Data)-previewLen)
		}
	}

	fmt.Fprintln(td.clientOut)
}

func (td *TLSDecryptor) FeedClient(data []byte) error {
	if td.isClosed {
		return nil // Silently ignore data after connection is closed
	}
	if err := td.clientIn.Write(data); err != nil {
		if errors.Is(err, io.ErrClosedPipe) {
			return nil // Silently ignore write to closed pipe (connection already closed)
		}
		return err
	}
	// Try to decrypt available records inline
	td.handshakeMu.RLock()
	complete := td.handshakeComplete
	td.handshakeMu.RUnlock()

	if complete {
		td.processClientRecords()
	}
	return nil
}

func (td *TLSDecryptor) FeedServer(data []byte) error {
	if td.isClosed {
		return nil // Silently ignore data after connection is closed
	}
	if err := td.serverIn.Write(data); err != nil {
		if errors.Is(err, io.ErrClosedPipe) {
			return nil // Silently ignore write to closed pipe (connection already closed)
		}
		return err
	}
	// Try to decrypt available records inline
	td.handshakeMu.RLock()
	complete := td.handshakeComplete
	td.handshakeMu.RUnlock()

	if complete {
		td.processServerRecords()
	}
	return nil
}

// processClientRecords processes all available client records synchronously
func (td *TLSDecryptor) processClientRecords() {
	for {
		record := td.clientIn.TryReadRecord()
		if record == nil {
			return
		}

		if len(record) < 5 {
			continue
		}

		recordType := record[0]

		// ChangeCipherSpec (0x14) marks the start of encrypted communication for TLS 1.2
		if recordType == 0x14 {
			td.handshakeMu.RLock()
			ver := td.version
			td.handshakeMu.RUnlock()
			if ver != tls.VersionTLS13 {
				td.handshakeMu.Lock()
				td.clientEncryptionStarted = true
				td.handshakeMu.Unlock()
			}
			continue
		}

		// Before ChangeCipherSpec (TLS 1.2), skip all records
		td.handshakeMu.RLock()
		encStarted := td.clientEncryptionStarted
		td.handshakeMu.RUnlock()
		if !encStarted {
			continue
		}

		// Decrypt the record
		td.handshakeMu.RLock()
		decryptor := td.clientCurrentDecryptor
		inHandshake := td.clientInHandshakePhase
		td.handshakeMu.RUnlock()

		plaintext, actualContentType, err := decryptor.Decrypt(record)
		if err != nil {
			td.logger.Printf("Decrypt error (client): %v", err)
			continue
		}

		// For TLS 1.3, check if we've finished the handshake phase
		if inHandshake && actualContentType == 0x16 && len(plaintext) > 0 && plaintext[0] == 0x14 {
			td.handshakeMu.Lock()
			td.clientInHandshakePhase = false
			td.clientCurrentDecryptor = td.clientDecryptor
			td.handshakeMu.Unlock()
			continue
		}

		// Only output application data records
		if actualContentType != 0x17 {
			continue
		}

		if len(plaintext) > 0 {
			td.queueRequest(plaintext)
		}
	}
}

// processServerRecords processes all available server records synchronously
func (td *TLSDecryptor) processServerRecords() {
	for {
		record := td.serverIn.TryReadRecord()
		if record == nil {
			return
		}

		if len(record) < 5 {
			continue
		}

		recordType := record[0]

		// ChangeCipherSpec (0x14) marks the start of encrypted communication for TLS 1.2
		if recordType == 0x14 {
			td.handshakeMu.RLock()
			ver := td.version
			td.handshakeMu.RUnlock()
			if ver != tls.VersionTLS13 {
				td.handshakeMu.Lock()
				td.serverEncryptionStarted = true
				td.handshakeMu.Unlock()
			}
			continue
		}

		// Before ChangeCipherSpec (TLS 1.2), skip all records
		td.handshakeMu.RLock()
		encStarted := td.serverEncryptionStarted
		td.handshakeMu.RUnlock()
		if !encStarted {
			continue
		}

		// Decrypt the record
		td.handshakeMu.RLock()
		decryptor := td.serverCurrentDecryptor
		inHandshake := td.serverInHandshakePhase
		td.handshakeMu.RUnlock()

		plaintext, actualContentType, err := decryptor.Decrypt(record)
		if err != nil {
			td.logger.Printf("Decrypt error (server): %v", err)
			continue
		}

		// For TLS 1.3, check if we've finished the handshake phase
		if inHandshake && actualContentType == 0x16 && len(plaintext) > 0 && plaintext[0] == 0x14 {
			td.handshakeMu.Lock()
			td.serverInHandshakePhase = false
			td.serverCurrentDecryptor = td.serverDecryptor
			td.handshakeMu.Unlock()
			continue
		}

		// Only output application data records
		if actualContentType != 0x17 {
			continue
		}

		if len(plaintext) > 0 {
			td.queueResponse(plaintext)
		}
	}
}

func (td *TLSDecryptor) CloseClient() error {
	td.clientIn.Close()
	// Process any remaining records
	td.handshakeMu.RLock()
	complete := td.handshakeComplete
	td.handshakeMu.RUnlock()

	if complete {
		td.processClientRecords()
	}
	return nil
}

func (td *TLSDecryptor) CloseServer() error {
	td.serverIn.Close()
	// Process any remaining records
	td.handshakeMu.RLock()
	complete := td.handshakeComplete
	td.handshakeMu.RUnlock()

	if complete {
		td.processServerRecords()
	}
	return nil
}

func (td *TLSDecryptor) Close() error {
	td.closeOnce.Do(func() {
		td.isClosed = true // Mark as closed before closing streams
		td.clientIn.Close()
		td.serverIn.Close()
		// Process any remaining records
		if td.handshakeComplete {
			td.processClientRecords()
			td.processServerRecords()
		}
		// Flush parser to create any remaining HAR entries
		td.protocolMu.RLock()
		parser := td.parser
		td.protocolMu.RUnlock()

		if parser != nil {
			parser.Flush()
		}
		// Final flush of any remaining queued data
		td.queueMu.Lock()
		td.flushOutput()
		td.queueMu.Unlock()
		close(td.outputDone)
	})
	return nil
}

func (td *TLSDecryptor) Decrypt() error {
	defer td.Close()

	// Parse handshake to get cipher suite and secrets
	if err := td.parseHandshake(); err != nil {
		// If handshake fails (e.g. no secrets), we just stop processing this connection.
		// The error is already logged inside parseHandshake if verbose.
		if strings.Contains(err.Error(), "no secrets found") {
			td.logger.Printf("ERROR Decrypt %s %s", td.ConnectionInfo, err)
			return nil
		}
		return fmt.Errorf("parse handshake: %w", err)
	}

	// After handshake is complete, data will be processed inline via FeedClient/FeedServer
	// The inline processing ensures the correct order of decryption output
	// We just need to wait for both streams to close

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()
		td.waitForClientClose()
	}()

	go func() {
		defer wg.Done()
		td.waitForServerClose()
	}()

	wg.Wait()

	return nil
}

// waitForClientClose waits for client stream to close and processes remaining records
func (td *TLSDecryptor) waitForClientClose() {
	<-td.clientIn.Closed
}

// waitForServerClose waits for server stream to close and processes remaining records
func (td *TLSDecryptor) waitForServerClose() {
	<-td.serverIn.Closed
}

func (td *TLSDecryptor) parseHandshake() error {
	// Read Client Hello and extract client random
	clientRandom, err := crypto.ExtractClientRandom(td.clientIn)
	if err != nil {
		return fmt.Errorf("extract client random: %w", err)
	}

	td.logger.Printf("Client Random: %s", hex.EncodeToString(clientRandom))

	// Read Server Hello and determine TLS version and cipher suite
	version, cipherSuite, serverHelloHandshake, err := crypto.ParseServerHello(td.serverIn)
	if err != nil {
		return fmt.Errorf("parse server hello: %w", err)
	}

	td.logger.Printf("TLS Version: 0x%04x, Cipher Suite: 0x%04x", version, cipherSuite)

	// Get secrets from key log
	secrets := td.keyLog.GetSecrets(clientRandom)
	if secrets == nil {
		return fmt.Errorf("no secrets found for client random")
	}

	// Create decryptors based on TLS version
	if version == tls.VersionTLS13 {
		if secrets.ClientTrafficSecret == nil || secrets.ServerTrafficSecret == nil {
			return fmt.Errorf("missing TLS 1.3 traffic secrets")
		}

		// Create handshake decryptors for TLS 1.3
		if secrets.ClientHandshakeTrafficSecret != nil {
			td.clientHandshakeDecryptor, err = crypto.NewRecordDecryptor(version, cipherSuite, secrets.ClientHandshakeTrafficSecret)
			if err != nil {
				return fmt.Errorf("create client handshake decryptor: %w", err)
			}
		}
		if secrets.ServerHandshakeTrafficSecret != nil {
			td.serverHandshakeDecryptor, err = crypto.NewRecordDecryptor(version, cipherSuite, secrets.ServerHandshakeTrafficSecret)
			if err != nil {
				return fmt.Errorf("create server handshake decryptor: %w", err)
			}
		}

		// Create application data decryptors
		td.clientDecryptor, err = crypto.NewRecordDecryptor(version, cipherSuite, secrets.ClientTrafficSecret)
		if err != nil {
			return fmt.Errorf("create client decryptor: %w", err)
		}

		td.serverDecryptor, err = crypto.NewRecordDecryptor(version, cipherSuite, secrets.ServerTrafficSecret)
		if err != nil {
			return fmt.Errorf("create server decryptor: %w", err)
		}

		td.handshakeMu.Lock()
		td.version = version
		td.cipherSuite = cipherSuite
		td.handshakeMu.Unlock()
	} else {
		// TLS 1.2 and earlier
		if secrets.MasterSecret == nil {
			return fmt.Errorf("missing master secret")
		}

		// Extract server random from server hello
		serverRandom, err := crypto.ExtractServerRandom(serverHelloHandshake)
		if err != nil {
			return fmt.Errorf("extract server random: %w", err)
		}

		td.clientDecryptor, err = crypto.NewRecordDecryptorTLS12(version, cipherSuite, secrets.MasterSecret, clientRandom, serverRandom, false)
		if err != nil {
			return fmt.Errorf("create client decryptor: %w", err)
		}

		td.serverDecryptor, err = crypto.NewRecordDecryptorTLS12(version, cipherSuite, secrets.MasterSecret, clientRandom, serverRandom, true)
		if err != nil {
			return fmt.Errorf("create server decryptor: %w", err)
		}

		td.handshakeMu.Lock()
		td.version = version
		td.cipherSuite = cipherSuite
		td.handshakeMu.Unlock()
	}

	// Initialize inline decryption state
	td.handshakeMu.Lock()
	if td.version == tls.VersionTLS13 {
		// For TLS 1.3, encryption starts immediately after ServerHello
		td.clientEncryptionStarted = true
		td.serverEncryptionStarted = true

		// Start with handshake secrets if available
		if td.clientHandshakeDecryptor != nil {
			td.clientInHandshakePhase = true
			td.clientCurrentDecryptor = td.clientHandshakeDecryptor
		} else {
			td.clientCurrentDecryptor = td.clientDecryptor
		}
		if td.serverHandshakeDecryptor != nil {
			td.serverInHandshakePhase = true
			td.serverCurrentDecryptor = td.serverHandshakeDecryptor
		} else {
			td.serverCurrentDecryptor = td.serverDecryptor
		}
	} else {
		// For TLS 1.2, encryption starts after ChangeCipherSpec
		td.clientEncryptionStarted = false
		td.serverEncryptionStarted = false
		td.clientCurrentDecryptor = td.clientDecryptor
		td.serverCurrentDecryptor = td.serverDecryptor
	}

	td.handshakeComplete = true
	td.handshakeMu.Unlock()
	return nil
}

// detectProtocol detects the application layer protocol (HTTP/1.x, HTTP/2, or WebSocket)
func (td *TLSDecryptor) detectProtocol(data []byte) {
	td.protocolMu.Lock()
	defer td.protocolMu.Unlock()

	// Double-check after acquiring lock
	if td.protocolDetected {
		return
	}

	td.protocolDetected = true

	// Use protocol registry to detect and create the appropriate parser
	parser, protocolName := protocol.DetectProtocol(data, td.ConnectionInfo, td.packetChan)
	if parser != nil {
		td.parser = parser
		td.parser.SetPacketTime(td.packetTime)
		td.logger.Printf("Detected %s protocol for %s", protocolName, td.ConnectionInfo)
	}
}
