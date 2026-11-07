// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gojue/ecapture_decryptor/crypto"
	"github.com/gojue/ecapture_decryptor/protocol"
	"github.com/gojue/ecapture_decryptor/types"
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
	serverEnded, tcpReset    atomic.Bool
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
	handshakeMu              sync.RWMutex // Protects handshake-related fields

	// For ordered output - separate queues for requests and responses
	requestQueue       []*DecryptedData // Queue for client requests
	responseQueue      []*DecryptedData // Queue for server responses
	responseQueueBytes int
	seqNum             uint64 // Global sequence number
	outputDone         chan struct{}
	queueMu            sync.Mutex // Mutex for queue operations

	// Client state for inline decryption
	clientEncryptionStarted bool
	clientApplicationSeen   bool // Protected by clientProcessMu.
	clientProbeErr          error

	// Server state for inline decryption
	serverEncryptionStarted bool
	serverApplicationSeen   bool // Protected by serverProcessMu.
	serverProbeErr          error

	// Close protection
	closeOnce       sync.Once
	stopInputOnce   sync.Once
	isClosed        atomic.Bool // Track if connection is closed to suppress spurious errors
	aborted         atomic.Bool // Resource/deadline failure must not be drained as a clean EOF.
	closeSignal     chan struct{}
	clientProcessMu sync.Mutex
	serverProcessMu sync.Mutex

	// Track if we've seen a request before outputting responses
	hasSeenRequest bool

	// Protocol stream parser for HAR output (HTTP/1.x, HTTP/2, or WebSocket)
	parser types.StreamParserInterface

	// Protocol detection
	protocolDetected     bool
	sniffBuffer          []byte
	pendingResponses     [][]byte
	pendingResponseBytes int
	protocolMu           sync.RWMutex                // Serializes parser feeds and protects detection state.
	packetChan           chan *types.DecryptedPacket // 解密包输出通道

	// Packet timestamp from pcap
	packetTime time.Time
	options    types.DecryptOptions
	rawOffsets [2]uint64 // Protected by protocolMu.
	rawEnded   bool
	errMu      sync.Mutex
	decryptErr error

	// Internal tunnel hooks run only on authenticated application bytes. The
	// sink is serialized by protocolMu and never feeds this same TLS instance.
	plaintextSink  func([]byte, bool, time.Time) error
	handshakeReady func()
	rawMetadata    map[string]any

	clientRandom             []byte // Selected ClientHello (inner for authenticated ECH).
	tls13                    [2]tls13Direction
	earlyOffered             bool
	earlyMu                  sync.Mutex // Serializes early-status resolution and client output.
	earlyStatus              string
	earlyHandshakeWithoutEnd bool // earlyMu; accepted 0-RTT requires EndOfEarlyData.
	earlyPending             []tlsEarlyChunk
	earlyBytes               int
	earlyRawOffset           uint64 // protocolMu; rejected/unknown early data has its own space.
	helloRetry               bool
	retryEarlyRecords        [][]byte // Client process lock after handshake; strictly before CH2.
	retryEarlyBytes          int
	tls13Finalizing          atomic.Bool
	tls13Wake                chan struct{}
	echOuterCandidate        bool
	echOuterReported         bool // handshakeMu; report only after an outer record authenticates.
}

const (
	tlsPendingResponseLimit = 8 << 20
	tlsPendingResponseCount = 64 << 10
)

// SetOptions must be called before feeding or decrypting the connection.
func (td *TLSDecryptor) SetOptions(options types.DecryptOptions) { td.options = options }

func (td *TLSDecryptor) recordFailure(stage, code string, err error) {
	td.errMu.Lock()
	first := td.decryptErr == nil
	if first {
		td.decryptErr = err
	}
	td.errMu.Unlock()
	if first {
		td.options.Report(td.ConnectionInfo, stage, code)
	}
}

// emitRawLocked preserves bytes and per-direction offsets without interpreting
// record boundaries as application messages. protocolMu must be held.
func (td *TLSDecryptor) emitRawLocked(data []byte, direction string, end bool, earlyStatus ...string) {
	index := 0
	if direction == "response" {
		index = 1
	}
	packet := types.NewDecryptedPacket("tcp", "tls", direction, bytes.Clone(data), td.packetTime, td.ConnectionInfo)
	packet.Metadata["kind"] = "stream_chunk"
	if end {
		packet.Metadata["kind"] = "stream_end"
	}
	packet.Metadata["offset"] = td.rawOffsets[index]
	separateEarly := len(earlyStatus) > 0 && earlyStatus[0] != "" && earlyStatus[0] != "accepted"
	if td.earlyOffered {
		packet.Metadata["encryption_level"] = "1rtt"
	}
	if len(earlyStatus) > 0 && earlyStatus[0] != "" {
		packet.Metadata["encryption_level"] = "0rtt"
		packet.Metadata["early_data"] = earlyStatus[0]
		if separateEarly {
			packet.Metadata["offset"] = td.earlyRawOffset
		}
	}
	packet.Metadata["end"] = end
	for key, value := range td.rawMetadata {
		packet.Metadata[key] = value
	}
	if separateEarly {
		td.earlyRawOffset += uint64(len(data))
	} else {
		td.rawOffsets[index] += uint64(len(data))
	}
	td.packetChan <- packet
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
		closeSignal:    make(chan struct{}),
		packetChan:     packetChan,
		tls13Wake:      make(chan struct{}, 1),
	}

	return td
}

// SetPacketTime sets the packet timestamp from pcap
func (td *TLSDecryptor) SetPacketTime(t time.Time) {
	td.protocolMu.Lock()
	defer td.protocolMu.Unlock()
	td.packetTime = t
	if td.parser != nil {
		td.parser.SetPacketTime(t)
	}
}

// queueRequest adds a request to the queue and flushes if possible
func (td *TLSDecryptor) queueRequest(data []byte) {
	td.queueRequestEarly(data, "")
}

func (td *TLSDecryptor) queueRequestEarly(data []byte, earlyStatus string) {
	if len(data) == 0 {
		return
	}

	td.protocolMu.Lock()
	if earlyStatus != "" && earlyStatus != "accepted" {
		if td.options.RawChunks && td.packetChan != nil {
			td.emitRawLocked(data, "request", false, earlyStatus)
		}
		td.protocolMu.Unlock()
		return
	}
	if td.plaintextSink != nil {
		td.forwardPlaintextLocked(data, true, earlyStatus)
		td.protocolMu.Unlock()
		return
	}
	if td.options.RawChunks && td.packetChan != nil {
		td.emitRawLocked(data, "request", false, earlyStatus)
		td.protocolMu.Unlock()
		return
	}
	if !td.protocolDetected && td.packetChan != nil {
		td.sniffBuffer = append(td.sniffBuffer, data...)
		preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
		if (td.options.ApplicationProtocol == "" || td.options.ApplicationProtocol == "doh") && (len(td.sniffBuffer) < 4 || (len(td.sniffBuffer) < len(preface) && bytes.HasPrefix(preface, td.sniffBuffer))) {
			td.protocolMu.Unlock()
			return
		}
		data = td.sniffBuffer
		td.sniffBuffer = nil
		td.detectProtocolLocked(data)
	}

	if td.parser != nil {
		td.parser.FeedRequest(data)
		for _, response := range td.pendingResponses {
			td.parser.FeedResponse(response)
		}
		td.checkEventParser()
	}
	if td.protocolDetected {
		td.pendingResponses = nil
		td.pendingResponseBytes = 0
	}
	td.protocolMu.Unlock()
	if td.packetChan != nil {
		return // Library output is owned by the parser, not the stdout queues.
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

	td.protocolMu.Lock()
	if td.plaintextSink != nil {
		td.forwardPlaintextLocked(data, false)
		td.protocolMu.Unlock()
		return
	}
	if td.options.RawChunks && td.packetChan != nil {
		td.emitRawLocked(data, "response", false)
		td.protocolMu.Unlock()
		return
	}
	if td.parser != nil {
		td.parser.FeedResponse(data)
		td.checkEventParser()
	} else if !td.protocolDetected && td.packetChan != nil {
		// Decryption can finish on the server side before the client request
		// selects a protocol parser. Preserve these bytes in record order.
		if len(data) > tlsPendingResponseLimit-td.pendingResponseBytes || len(td.pendingResponses) >= tlsPendingResponseCount {
			td.protocolMu.Unlock()
			td.recordFailure("input", "resource_limit", errors.New("TLS pending response buffer limit exceeded"))
			td.abortInput()
			return
		}
		td.pendingResponses = append(td.pendingResponses, bytes.Clone(data))
		td.pendingResponseBytes += len(data)
	}
	td.protocolMu.Unlock()
	if td.packetChan != nil {
		return
	}

	td.queueMu.Lock()
	defer td.queueMu.Unlock()
	if !td.hasSeenRequest && (len(data) > tlsPendingResponseLimit-td.responseQueueBytes || len(td.responseQueue) >= tlsPendingResponseCount) {
		td.recordFailure("input", "resource_limit", errors.New("TLS response output queue limit exceeded"))
		td.abortInput()
		return
	}

	td.seqNum++
	td.responseQueue = append(td.responseQueue, &DecryptedData{
		Data:      data,
		SeqNum:    td.seqNum,
		IsRequest: false,
	})
	td.responseQueueBytes += len(data)

	// Flush output
	td.flushOutput()
}

func (td *TLSDecryptor) forwardPlaintextLocked(data []byte, client bool, earlyStatus ...string) {
	if td.options.RawChunks && td.packetChan != nil {
		direction := "response"
		if client {
			direction = "request"
		}
		td.emitRawLocked(data, direction, false, earlyStatus...)
	}
	if err := td.plaintextSink(data, client, td.packetTime); err != nil {
		td.recordParserFailure(err)
		td.abortInput()
	}
}

// flushOutput outputs data in the correct order: requests before responses
// Must be called with queueMu held
func (td *TLSDecryptor) flushOutput() {
	// First, output all pending requests
	for len(td.requestQueue) > 0 {
		req := td.requestQueue[0]
		td.requestQueue[0] = nil
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
		td.responseQueue[0] = nil
		td.responseQueue = td.responseQueue[1:]
		td.responseQueueBytes -= len(resp.Data)
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

	_, _ = fmt.Fprintf(td.clientOut, "\nSeq:%d %s, len:%d\n", data.SeqNum, td.ConnectionInfo, len(data.Data))

	if isPrintable {
		// 可打印数据，直接输出
		_, _ = td.clientOut.Write(data.Data)
	} else {
		// 二进制数据，只显示摘要信息
		previewLen := 64
		if len(data.Data) < previewLen {
			previewLen = len(data.Data)
		}
		_, _ = fmt.Fprintf(td.clientOut, "[Binary data, showing first %d bytes in hex]\n", previewLen)
		for i := 0; i < previewLen; i++ {
			if i > 0 && i%16 == 0 {
				_, _ = fmt.Fprintln(td.clientOut)
			}
			_, _ = fmt.Fprintf(td.clientOut, "%02x ", data.Data[i])
		}
		if len(data.Data) > previewLen {
			_, _ = fmt.Fprintf(td.clientOut, "\n... (%d more bytes)\n", len(data.Data)-previewLen)
		}
	}

	_, _ = fmt.Fprintln(td.clientOut)
}

func (td *TLSDecryptor) FeedClient(data []byte) error {
	if td.isClosed.Load() {
		return nil // Silently ignore data after connection is closed
	}
	if err := td.clientIn.Write(data); err != nil {
		if errors.Is(err, io.ErrClosedPipe) {
			return nil // Silently ignore write to closed pipe (connection already closed)
		}
		td.recordFailure("input", "resource_limit", err)
		td.abortInput()
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
	if td.isClosed.Load() {
		return nil // Silently ignore data after connection is closed
	}
	if err := td.serverIn.Write(data); err != nil {
		if errors.Is(err, io.ErrClosedPipe) {
			return nil // Silently ignore write to closed pipe (connection already closed)
		}
		td.recordFailure("input", "resource_limit", err)
		td.abortInput()
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
	td.clientProcessMu.Lock()
	defer td.clientProcessMu.Unlock()
	if td.version == tls.VersionTLS13 {
		td.processTLS13Records(true)
		return
	}
	for {
		if td.aborted.Load() {
			return
		}
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
			td.handshakeMu.Lock()
			td.clientEncryptionStarted = true
			td.handshakeMu.Unlock()
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
		decryptor := td.clientDecryptor
		td.handshakeMu.RUnlock()

		plaintext, actualContentType, err := decryptor.Decrypt(record)
		if err != nil {
			td.recordFailure("decrypt", "authentication_failed", err)
			if td.httpEventMode() {
				td.abortInput()
				return
			}
			td.logger.Printf("Decrypt error (client): %v", err)
			continue
		}

		// Only output application data records
		if actualContentType != 0x17 {
			continue
		}

		td.clientApplicationSeen = true
		if len(plaintext) > 0 {
			td.queueRequest(plaintext)
		}
	}
}

// processServerRecords processes all available server records synchronously
func (td *TLSDecryptor) processServerRecords() {
	// A FeedServer racing the initial/late-key drain must not overtake client
	// records already buffered before it. Acquire the direction locks separately.
	td.processClientRecords()
	td.serverProcessMu.Lock()
	defer td.serverProcessMu.Unlock()
	if td.version == tls.VersionTLS13 {
		td.processTLS13Records(false)
		return
	}
	for {
		if td.aborted.Load() {
			return
		}
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
			td.handshakeMu.Lock()
			td.serverEncryptionStarted = true
			td.handshakeMu.Unlock()
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
		decryptor := td.serverDecryptor
		td.handshakeMu.RUnlock()

		plaintext, actualContentType, err := decryptor.Decrypt(record)
		if err != nil {
			td.recordFailure("decrypt", "authentication_failed", err)
			if td.httpEventMode() {
				td.abortInput()
				return
			}
			td.logger.Printf("Decrypt error (server): %v", err)
			continue
		}

		// Only output application data records
		if actualContentType == 0x15 && len(plaintext) == 2 && plaintext[1] == 0 {
			td.serverEnded.Store(true)
		} // TLS close_notify
		if actualContentType != 0x17 {
			continue
		}

		td.serverApplicationSeen = true
		if len(plaintext) > 0 {
			td.queueResponse(plaintext)
		}
	}
}

func (td *TLSDecryptor) CloseClient() error {
	_ = td.clientIn.Close()
	// Process any remaining records
	td.handshakeMu.RLock()
	complete := td.handshakeComplete
	td.handshakeMu.RUnlock()

	if complete {
		td.processClientRecords()
	}
	return nil
}

// ObserveTCPReset records the transport termination while allowing late keys
// to unlock authenticated bytes already buffered before the reset.
func (td *TLSDecryptor) ObserveTCPReset() { td.tcpReset.Store(true) }

func (td *TLSDecryptor) CloseServer() error {
	td.serverEnded.Store(true)
	_ = td.serverIn.Close()
	// Process any remaining records
	td.handshakeMu.RLock()
	complete := td.handshakeComplete
	td.handshakeMu.RUnlock()

	if complete {
		td.processServerRecords()
	}
	return nil
}

// stopInput only unblocks readers. It must not acquire processing/parser locks:
// callers include the handshake timer and a feed that reached a resource limit.
func (td *TLSDecryptor) stopInput() {
	td.stopInputOnce.Do(func() {
		td.isClosed.Store(true) // Mark as closed before closing streams
		close(td.closeSignal)
		_ = td.clientIn.Close()
		_ = td.serverIn.Close()
	})
}

func (td *TLSDecryptor) abortInput() {
	td.aborted.Store(true)
	td.stopInput()
}

func (td *TLSDecryptor) Close() error {
	td.closeOnce.Do(func() {
		td.stopInput()
		// Process any remaining records
		td.handshakeMu.RLock()
		complete := td.handshakeComplete
		td.handshakeMu.RUnlock()
		if complete {
			td.processClientRecords()
			td.processServerRecords()
		}
		// Flush parser to create any remaining HAR entries
		td.protocolMu.RLock()
		parser := td.parser
		td.protocolMu.RUnlock()

		if parser != nil && !td.httpEventMode() && !td.earlyOffered && !td.aborted.Load() {
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
	defer func() {
		_ = td.Close()
		td.releaseBuffers()
	}()

	// One deadline includes missing/partial hellos as well as missing secrets.
	timeout := td.options.SecretWaitTimeout()
	deadline := time.Now().Add(timeout)
	var expired atomic.Bool
	timerDone := make(chan struct{})
	timer := time.AfterFunc(timeout, func() {
		expired.Store(true)
		td.abortInput()
		close(timerDone)
	})
	err := td.parseHandshake()
	if !timer.Stop() {
		<-timerDone
	}
	if expired.Load() || !time.Now().Before(deadline) {
		td.abortInput()
		err = fmt.Errorf("TLS handshake/key wait exceeded %s: %w", timeout, context.DeadlineExceeded)
		td.recordFailure("keys", "key_wait_timeout", err)
	}
	if err != nil {
		td.errMu.Lock()
		failure := td.decryptErr
		td.errMu.Unlock()
		return errors.Join(fmt.Errorf("parse handshake: %w", err), failure)
	}
	if td.handshakeReady != nil {
		td.handshakeReady()
	}
	td.waitTLSRecords(deadline)
	// Close can race with the final Feed; direction locks join its record drain.
	td.processClientRecords()
	td.processServerRecords()
	td.clientProcessMu.Lock()
	if !td.clientApplicationSeen && td.clientProbeErr != nil {
		// Application-only keys cannot distinguish a handshake-only capture
		// from application records protected by unavailable or incorrect keys.
		td.recordFailure("decrypt", "no_authenticated_application_data", errors.New("TLS application data could not be authenticated"))
	}
	td.clientProcessMu.Unlock()
	td.serverProcessMu.Lock()
	if !td.serverApplicationSeen && td.serverProbeErr != nil {
		td.recordFailure("decrypt", "no_authenticated_application_data", errors.New("TLS application data could not be authenticated"))
	}
	td.serverProcessMu.Unlock()
	td.finishTLS13()
	if td.clientIn.Len() != 0 || td.serverIn.Len() != 0 {
		td.recordFailure("input", "truncated_record", fmt.Errorf("truncated TLS record: %w", io.ErrUnexpectedEOF))
	}
	td.errMu.Lock()
	incomplete := td.decryptErr != nil
	td.errMu.Unlock()
	td.protocolMu.Lock()
	if td.options.RawChunks && td.packetChan != nil && !td.rawEnded && !incomplete {
		td.rawEnded = true
		td.emitRawLocked(nil, "request", true)
		td.emitRawLocked(nil, "response", true)
	}
	td.protocolMu.Unlock()
	td.protocolMu.RLock()
	parser := td.parser
	td.protocolMu.RUnlock()
	// Close can run before this goroutine finishes draining queued TLS records.
	// Flush again after the drain so close-delimited HTTP/1.0 bodies are emitted.
	if events, ok := parser.(interface{ FinishHTTPEvents(string) }); ok && td.httpEventMode() {
		reason := ""
		switch {
		case incomplete || td.aborted.Load():
			reason = "partial"
		case td.tcpReset.Load():
			reason = "reset"
		case !td.serverEnded.Load():
			reason = "capture_eof"
		}
		events.FinishHTTPEvents(reason)
	} else if parser != nil && !td.aborted.Load() {
		parser.Flush()
	}
	if errorParser, ok := parser.(interface{ Err() error }); ok {
		if err := errorParser.Err(); err != nil {
			td.recordParserFailure(err)
		}
	}
	td.errMu.Lock()
	defer td.errMu.Unlock()
	return td.decryptErr
}

// releaseBuffers runs only after Decrypt has finished and Close has joined feeds.
// Releasing earlier would discard bytes needed by EOF/late-DSB final draining.
func (td *TLSDecryptor) releaseBuffers() {
	td.clientProcessMu.Lock()
	defer td.clientProcessMu.Unlock()
	td.serverProcessMu.Lock()
	defer td.serverProcessMu.Unlock()
	td.clientIn.Discard()
	td.serverIn.Discard()
	for i := range td.tls13 {
		td.tls13[i].handshake.Reset()
		td.tls13[i].early = nil
	}
	td.retryEarlyRecords = nil
	td.retryEarlyBytes = 0
	td.earlyMu.Lock()
	td.earlyPending = nil
	td.earlyBytes = 0
	td.earlyMu.Unlock()
	td.protocolMu.Lock()
	td.parser = nil
	td.plaintextSink = nil
	td.handshakeReady = nil
	td.rawMetadata = nil
	td.sniffBuffer = nil
	td.pendingResponses = nil
	td.pendingResponseBytes = 0
	td.protocolMu.Unlock()
	td.queueMu.Lock()
	td.requestQueue = nil
	td.responseQueue = nil
	td.responseQueueBytes = 0
	td.queueMu.Unlock()
}

func (td *TLSDecryptor) parseHandshake() error {
	// Read Client Hello and extract client random
	hello, err := crypto.ReadClientHello(td.clientIn)
	if err != nil {
		td.options.Report(td.ConnectionInfo, "handshake", "missing_client_hello")
		return fmt.Errorf("extract client random: %w", err)
	}

	clientRandom := hello.Random
	td.logger.Printf("Client Random: %s", hex.EncodeToString(clientRandom))

	// Read Server Hello and determine TLS version and cipher suite
	version, cipherSuite, serverHelloHandshake, err := crypto.ParseServerHello(td.serverIn)
	if err != nil {
		td.options.Report(td.ConnectionInfo, "handshake", "invalid_server_hello")
		return fmt.Errorf("parse server hello: %w", err)
	}
	firstHello := hello
	echOffered := hello.ECHOffered
	var retryHandshake []byte
	if crypto.IsHelloRetryRequest(serverHelloHandshake) {
		if version != tls.VersionTLS13 {
			return errTLS13Handshake
		}
		td.helloRetry = true
		retryHandshake = serverHelloHandshake
		retrySuite := cipherSuite
		second, err := crypto.ReadClientHelloRetry(td.clientIn, func(record []byte) error {
			if !hello.EarlyData && !hello.ECHOffered {
				return errTLS13Handshake
			}
			if len(record) > tlsPendingResponseLimit-td.retryEarlyBytes || len(td.retryEarlyRecords) >= tlsPendingResponseCount {
				return crypto.ErrHandshakeResourceLimit
			}
			td.retryEarlyRecords = append(td.retryEarlyRecords, record)
			td.retryEarlyBytes += len(record)
			return nil
		})
		if err != nil {
			return err
		}
		if second.EarlyData || !hello.ECHOffered && (!bytes.Equal(second.Random, clientRandom) || second.ECHOffered) {
			return errTLS13Handshake
		}
		hello = second
		version, cipherSuite, serverHelloHandshake, err = crypto.ParseServerHello(td.serverIn)
		if err != nil || crypto.IsHelloRetryRequest(serverHelloHandshake) || version != tls.VersionTLS13 || cipherSuite != retrySuite {
			return errTLS13Handshake
		}
		td.options.Report(td.ConnectionInfo, "handshake", "hello_retry_request")
	}
	if version != tls.VersionTLS12 && version != tls.VersionTLS13 {
		td.options.Report(td.ConnectionInfo, "decrypt", "unsupported_version")
		return fmt.Errorf("unsupported TLS version 0x%04x", version)
	}
	config, supported := crypto.GetCipherSuite(cipherSuite)
	if !supported || version == tls.VersionTLS12 && config.Version == crypto.TLSVersion13 || version == tls.VersionTLS13 && config.Version == crypto.TLSVersion12 {
		td.options.Report(td.ConnectionInfo, "decrypt", "unsupported_cipher")
		return fmt.Errorf("unsupported cipher suite 0x%04x", cipherSuite)
	}

	td.logger.Printf("TLS Version: 0x%04x, Cipher Suite: 0x%04x", version, cipherSuite)

	// Get secrets from key log
	if td.keyLog.GetSecrets(clientRandom) == nil {
		td.options.Report(td.ConnectionInfo, "keys", "waiting_secret")
	}
	applicationReady := func(s *crypto.TLSSecrets) bool {
		if s == nil {
			return false
		}
		if version == tls.VersionTLS13 {
			return len(s.ClientTrafficSecret) != 0 && len(s.ServerTrafficSecret) != 0
		}
		return len(s.MasterSecret) != 0
	}
	secrets, err := td.keyLog.WaitForSecrets(clientRandom, func(s *crypto.TLSSecrets) bool {
		return applicationReady(s) || firstHello.ECHOffered && s != nil && len(s.ECHSecret) > 0 && len(s.ECHConfig) > 0
	}, td.closeSignal, td.options.SecretWaitTimeout())
	if err != nil {
		td.options.Report(td.ConnectionInfo, "keys", "missing_secret")
		return fmt.Errorf("wait for TLS secrets: %w", err)
	}
	if firstHello.ECHOffered {
		var status string
		if td.helloRetry {
			firstHello, hello, status, err = crypto.ResolveECHClientHelloRetry(firstHello, hello, retryHandshake, serverHelloHandshake, secrets)
		} else if len(secrets.ECHSecret) > 0 && len(secrets.ECHConfig) > 0 {
			hello, status, err = crypto.ResolveECHClientHello(hello, serverHelloHandshake, secrets)
			firstHello = hello
		}
		if err != nil {
			td.options.Report(td.ConnectionInfo, "handshake", "ech_unavailable")
			return err
		}
		if len(secrets.ECHSecret) > 0 && len(secrets.ECHConfig) > 0 {
			clientRandom = hello.Random
			td.options.Report(td.ConnectionInfo, "handshake", "ech_"+status)
			secrets, err = td.keyLog.WaitForSecrets(clientRandom, applicationReady, td.closeSignal, td.options.SecretWaitTimeout())
			if err != nil {
				td.options.Report(td.ConnectionInfo, "keys", "missing_secret")
				return err
			}
		} else {
			td.echOuterCandidate = true
		}
	}
	td.clientRandom = bytes.Clone(clientRandom)
	td.earlyOffered = version == tls.VersionTLS13 && firstHello.EarlyData
	if td.helloRetry && echOffered && (td.earlyOffered || len(td.retryEarlyRecords) > 0) {
		td.options.Report(td.ConnectionInfo, "handshake", "unsupported_handshake")
		return errors.New("TLS ECH with HRR and early data is not supported")
	}
	if len(td.retryEarlyRecords) > 0 && !td.earlyOffered {
		return errTLS13Handshake
	}
	if td.helloRetry && td.earlyOffered {
		if err := td.resolveTLSEarly("rejected"); err != nil {
			return err
		}
	}
	if crypto.ServerHelloResumed(serverHelloHandshake) {
		td.options.Report(td.ConnectionInfo, "handshake", "session_resumed")
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
			td.tls13[0].phase = tls13Handshake
		}
		if td.serverHandshakeDecryptor != nil {
			td.tls13[1].phase = tls13Handshake
		}
		if td.earlyOffered && !td.helloRetry {
			td.tls13[0].phase = tls13Early
			td.tls13[1].phase = tls13Handshake
		}
	} else {
		// For TLS 1.2, encryption starts after ChangeCipherSpec
		td.clientEncryptionStarted = false
		td.serverEncryptionStarted = false
	}

	td.handshakeComplete = true
	td.handshakeMu.Unlock()
	return nil
}

// detectProtocol detects the application layer protocol (HTTP/1.x, HTTP/2, or WebSocket)
func (td *TLSDecryptor) detectProtocolLocked(data []byte) {
	if td.protocolDetected {
		return
	}

	td.protocolDetected = true

	// Use protocol registry to detect and create the appropriate parser
	parser, protocolName := protocol.SelectProtocol(td.options.ApplicationProtocol, data, td.ConnectionInfo, td.packetChan)
	if parser != nil {
		if td.options.ApplicationProtocol == "doh" {
			doh, ok := parser.(interface{ EnableDNSOverHTTP() })
			if !ok {
				td.recordFailure("protocol", "unsupported_protocol", errors.New("selected parser cannot parse DoH"))
				td.abortInput()
				return
			}
			doh.EnableDNSOverHTTP()
		} else if td.options.HTTPEvents {
			events, ok := parser.(interface{ EnableHTTPEvents(int64) })
			if !ok {
				td.recordFailure("protocol", "unsupported_protocol", errors.New("selected parser does not support HTTP events"))
				td.abortInput()
				return
			}
			events.EnableHTTPEvents(td.options.MaxDecodedBodyBytes)
		}
		td.parser = parser
		td.parser.SetPacketTime(td.packetTime)
		td.logger.Printf("Detected %s protocol for %s", protocolName, td.ConnectionInfo)
	} else {
		if td.httpEventMode() || td.options.ApplicationProtocol != "" {
			td.recordFailure("protocol", "unsupported_protocol", errors.New("unrecognized application protocol"))
			td.abortInput()
		} else {
			td.options.Report(td.ConnectionInfo, "protocol", "unsupported_protocol")
		}
	}
}

func (td *TLSDecryptor) recordParserFailure(err error) {
	code := "parse_failed"
	if errors.Is(err, protocol.ErrHTTPEventLimit) || errors.Is(err, errTLSUpgradeLimit) {
		code = "resource_limit"
	}
	td.recordFailure("protocol", code, err)
}

// Called under protocolMu after feeding authenticated application data.
func (td *TLSDecryptor) checkEventParser() {
	if p, ok := td.parser.(interface{ Err() error }); ok {
		if err := p.Err(); err != nil {
			td.recordParserFailure(err)
			td.abortInput()
		}
	}
}

func (td *TLSDecryptor) httpEventMode() bool {
	return td.options.HTTPEvents || td.options.ApplicationProtocol == "doh"
}
