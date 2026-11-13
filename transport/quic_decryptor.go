// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

// quic_decryptor.go - QUIC 解密器
package transport

import (
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/gojue/ecapture_decryptor/crypto"
	"github.com/gojue/ecapture_decryptor/protocol"
	"github.com/gojue/ecapture_decryptor/types"
	"golang.org/x/crypto/hkdf"
)

// QUIC packet types
const (
	QUICPacketTypeInitial            = 0x00
	QUICPacketType0RTT               = 0x01
	QUICPacketTypeHandshake          = 0x02
	QUICPacketTypeRetry              = 0x03
	QUICPacketType1RTT               = 0x04
	QUICPacketTypeVersionNegotiation = 0x05
	maxQUICBufferedBytes             = 32 << 20
	maxQUICQueuedPackets             = 64 << 10
)

var errQUICInputLimit = errors.New("QUIC input buffer limit exceeded")

// QUIC v1 Initial salt (RFC 9001)
var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
}

var quicV2InitialSalt = []byte{
	0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
	0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
	0xf9, 0xbd, 0x2e, 0xd9,
}

// QUIC draft-29 Initial salt
var quicDraft29InitialSalt = []byte{
	0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c,
	0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
	0x43, 0x90, 0xa8, 0x99,
}

// QUICDecryptor implements Decryptor interface for QUIC protocol
type QUICDecryptor struct {
	identityStarted  time.Time
	identityResolved bool
	connectionInfo   types.ConnectionKey
	keyLog           *crypto.KeyLogStore
	logger           *log.Logger
	closeCh          chan struct{}
	closeOnce        sync.Once
	isClosed         bool
	mu               sync.Mutex
	packetTime       time.Time
	wake             chan struct{}
	input            []quicDatagram
	inputBytes       int
	inputErr         error
	flow             *quicFlowState
	options          types.DecryptOptions
	packetChan       chan *types.DecryptedPacket
	routingHandler   func([]byte, bool, bool) ([]QUICRoutedPacket, error)

	// Connection state
	version    uint32
	destConnID []byte

	// Decryption keys
	clientInitialKeys *QUICKeys
	serverInitialKeys *QUICKeys

	// HTTP/3 parser for HAR output
	http3Parser *protocol.HTTP3StreamParser
	doqParser   *protocol.DoQStreamParser
}

// QUICKeys holds encryption keys for a direction
type QUICKeys struct {
	key     []byte
	iv      []byte
	hp      []byte // Header protection key
	aead    cipher.AEAD
	suite   quicCipherSuite
	secret  []byte
	version uint32
}

// QUICBuffer is a simple buffer for QUIC packets
type QUICBuffer struct {
	packets [][]byte
	mu      sync.Mutex
	closed  bool
	cond    *sync.Cond
}

// NewQUICBuffer creates a new QUIC buffer
func NewQUICBuffer() *QUICBuffer {
	b := &QUICBuffer{
		packets: make([][]byte, 0),
	}
	b.cond = sync.NewCond(&b.mu)
	return b
}

// Write adds a packet to the buffer
func (b *QUICBuffer) Write(data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return io.ErrClosedPipe
	}
	packet := make([]byte, len(data))
	copy(packet, data)
	b.packets = append(b.packets, packet)
	b.cond.Signal()
	return nil
}

// TryRead reads a packet from the buffer (non-blocking)
func (b *QUICBuffer) TryRead() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.packets) == 0 {
		return nil
	}
	packet := b.packets[0]
	b.packets = b.packets[1:]
	return packet
}

// Read reads a packet from the buffer (blocking)
func (b *QUICBuffer) Read() ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for len(b.packets) == 0 && !b.closed {
		b.cond.Wait()
	}
	if b.closed && len(b.packets) == 0 {
		return nil, io.EOF
	}
	packet := b.packets[0]
	b.packets = b.packets[1:]
	return packet, nil
}

// Close closes the buffer
func (b *QUICBuffer) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	b.cond.Broadcast()
}

// NewQUICDecryptor creates a new QUIC decryptor
func NewQUICDecryptor(ci types.ConnectionKey, keyLog *crypto.KeyLogStore, logger *log.Logger, _ io.Writer, packetChan chan *types.DecryptedPacket) types.Decryptor {
	ci.TLS = &types.ConnectionTLS{}
	q := &QUICDecryptor{
		identityStarted: time.Now(),
		connectionInfo:  ci,
		keyLog:          keyLog.NewConnectionScope(),
		logger:          logger,
		closeCh:         make(chan struct{}),
		wake:            make(chan struct{}, 1),
		flow:            newQUICFlowState(),
		packetChan:      packetChan,
	}
	// Initialize HTTP/3 parser if channel is available
	if packetChan != nil {
		q.http3Parser = protocol.NewHTTP3StreamParser(ci, packetChan)
	}
	return q
}

// SetOptions configures output before Decrypt starts. Raw chunks replace HTTP/3
// messages; they do not claim an application protocol or negotiated ALPN.
func (q *QUICDecryptor) SetOptions(options types.DecryptOptions) {
	q.options = options
	q.http3Parser = nil
	q.doqParser = nil
	if options.ApplicationProtocol == "doq" && q.packetChan != nil {
		q.doqParser = protocol.NewDoQStreamParser(q.connectionInfo, q.packetChan)
		return
	}
	if !options.RawChunks && q.packetChan != nil {
		q.http3Parser = protocol.NewHTTP3StreamParser(q.connectionInfo, q.packetChan)
		if options.HTTPEvents {
			q.http3Parser.EnableHTTPEvents(options.MaxDecodedBodyBytes)
		} else if options.ApplicationProtocol == "doh" {
			q.http3Parser.EnableDNSOverHTTP()
		}
	}
}

// GetAddr returns the connection address
func (q *QUICDecryptor) GetAddr() types.ConnectionKey {
	return q.connectionInfo
}

// SetPacketTime sets the packet timestamp.
func (q *QUICDecryptor) SetPacketTime(t time.Time) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.packetTime = t
}

// Decrypt starts the QUIC decryption process
func (q *QUICDecryptor) Decrypt() (result error) {
	defer q.keyLog.ReleaseKeyReferences()
	q.logger.Printf("QUIC decryption started for %s", q.connectionInfo)
	var keyTimer *time.Timer
	var keyTimeout <-chan time.Time
	var keyDeadline time.Time
	defer func() {
		if keyTimer != nil {
			keyTimer.Stop()
		}
		_ = q.Close()
		q.mu.Lock()
		q.input = nil
		q.inputBytes = 0
		result = errors.Join(result, q.inputErr)
		q.mu.Unlock()
		q.flow = newQUICFlowState()
		if q.http3Parser != nil && (q.options.HTTPEvents || q.options.ApplicationProtocol == "doh") {
			q.http3Parser.AbortHTTPEvents()
		}
		q.http3Parser = nil
		q.doqParser = nil
		q.clientInitialKeys, q.serverInitialKeys = nil, nil
		q.destConnID = nil
		q.routingHandler = nil
	}()
	if name := q.options.ApplicationProtocol; q.options.TLSUpgrade != "" || name != "" && name != "doh" && name != "doq" {
		q.options.Report(q.connectionInfo, "protocol", "unsupported_protocol")
		return errors.New("selected application protocol is not supported over QUIC")
	}
	updates := q.keyLog.Updates()
	for {
		q.mu.Lock()
		inputFailed := q.inputErr != nil
		q.mu.Unlock()
		if inputFailed {
			return nil // The deferred cleanup preserves the queue error.
		}
		if q.flow.terminalErr != nil {
			return q.flow.terminalErr
		}
		waitSince := q.flow.pendingSince
		if !q.identityResolved && (waitSince.IsZero() || q.identityStarted.Before(waitSince)) {
			waitSince = q.identityStarted
		}
		if early := q.flow.early.since; !early.IsZero() && (waitSince.IsZero() || early.Before(waitSince)) {
			waitSince = early
		}
		if q.http3Parser != nil {
			since := q.http3Parser.PendingSince()
			if !since.IsZero() && (waitSince.IsZero() || since.Before(waitSince)) {
				waitSince = since
			}
		}
		if waitSince.IsZero() {
			if keyTimer != nil {
				keyTimer.Stop()
			}
			keyTimeout, keyDeadline = nil, time.Time{}
		} else {
			deadline := waitSince.Add(q.options.SecretWaitTimeout())
			if !deadline.After(time.Now()) {
				return q.quicWaitExpired()
			}
			if !deadline.Equal(keyDeadline) {
				if keyTimer == nil {
					keyTimer = time.NewTimer(time.Until(deadline))
				} else {
					keyTimer.Reset(time.Until(deadline))
				}
				keyTimeout, keyDeadline = keyTimer.C, deadline
			}
		}
		select {
		case <-q.wake:
			if q.identityWaitExpired() {
				return q.quicWaitExpired()
			}
			q.drainQUICInput(true)
		case <-updates:
			if q.identityWaitExpired() {
				return q.quicWaitExpired()
			}
			// Resubscribe before looking up keys: a concurrent DSB must wake the
			// next select even if it arrives during this retry.
			updates = q.keyLog.Updates()
			q.retryQUICPacketsWithNewKeys()
		case <-keyTimeout:
			return q.quicWaitExpired()
		case <-q.closeCh:
			q.drainQUICInput(false)
			q.mu.Lock()
			inputFailed = q.inputErr != nil
			q.mu.Unlock()
			if inputFailed {
				return nil
			}
			if q.flow.terminalErr != nil {
				return q.flow.terminalErr
			}
			// CID announcements unlocked by a trailing DSB can route earlier
			// encrypted packets even during EOF drain. Drain them before exit.
			for {
				q.retryDeferredQUICPackets()
				q.retryQUICPacketsWithNewKeys() // A retry can resolve early-data acceptance.
				q.mu.Lock()
				more := len(q.input) > 0
				q.mu.Unlock()
				if !more || q.flow.terminalErr != nil {
					break
				}
				q.drainQUICInput(false)
			}
			if len(q.flow.pending) != 0 {
				if len(q.flow.clientRandom) == 0 {
					q.options.Report(q.connectionInfo, "handshake", "missing_client_hello")
				} else {
					q.options.Report(q.connectionInfo, "keys", "missing_secret")
				}
				q.appendQUICError(fmt.Errorf("%d QUIC packets could not be decrypted: matching SSLKEYLOG secrets or ClientHello missing", len(q.flow.pending)))
			}
			if err := q.finishQUICEarly(); err != nil {
				q.appendQUICError(err)
			}
			if !IsQUICVersionSupported(q.version) && q.version != 0 {
				q.appendQUICError(errors.New("QUIC negotiation did not select a supported version"))
			}
			incomplete := 0
			for _, streams := range []map[quicStreamKey]*quicStreamAssembler{q.flow.streams, q.flow.early.streams} {
				for _, stream := range streams {
					if !stream.finished && (stream.pendingBytes > 0 || stream.hasFinal && stream.next < stream.final) {
						incomplete++
					}
				}
			}
			if incomplete != 0 {
				q.options.Report(q.connectionInfo, "reassembly", "incomplete_stream")
				q.appendQUICError(fmt.Errorf("%d QUIC streams have missing bytes at input end", incomplete))
			}
			if q.http3Parser != nil {
				if err := q.http3Parser.Close(); err != nil {
					q.reportHTTP3Error(err)
					q.appendQUICError(err)
				}
			}
			if q.doqParser != nil {
				if err := q.doqParser.CloseQUICStreams(); err != nil {
					q.reportHTTP3Error(err)
					q.appendQUICError(err)
				}
			}
			q.logger.Printf("QUIC decryption ended for %s", q.connectionInfo)
			return errors.Join(q.flow.errors...)
		}
	}
}

func (q *QUICDecryptor) identityWaitExpired() bool {
	return !q.identityResolved && time.Since(q.identityStarted) >= q.options.SecretWaitTimeout()
}

func (q *QUICDecryptor) drainQUICInput(stopAtDeadline bool) {
	for {
		if stopAtDeadline && q.identityWaitExpired() {
			return
		}
		q.mu.Lock()
		if len(q.input) == 0 || q.inputErr != nil {
			q.mu.Unlock()
			return
		}
		item := q.input[0]
		q.input[0] = quicDatagram{}
		q.input = q.input[1:]
		q.inputBytes -= len(item.data)
		q.mu.Unlock()
		q.processQUICDatagram(item)
		keyExpired := !q.flow.pendingSince.IsZero() && time.Since(q.flow.pendingSince) >= q.options.SecretWaitTimeout()
		earlyExpired := !q.flow.early.since.IsZero() && time.Since(q.flow.early.since) >= q.options.SecretWaitTimeout()
		httpExpired := false
		if q.http3Parser != nil {
			since := q.http3Parser.PendingSince()
			httpExpired = !since.IsZero() && time.Since(since) >= q.options.SecretWaitTimeout()
		}
		identityExpired := q.identityWaitExpired()
		if q.flow.terminalErr != nil || stopAtDeadline && (identityExpired || keyExpired || earlyExpired || httpExpired) {
			return
		}
	}
}

// deriveInitialKeys derives initial encryption keys from destination connection ID
func (q *QUICDecryptor) deriveInitialKeys(dcid []byte) {
	q.clientInitialKeys, q.serverInitialKeys = quicInitialKeys(q.version, dcid)
}

func quicInitialKeys(version uint32, dcid []byte) (*QUICKeys, *QUICKeys) {
	salt := quicV1InitialSalt
	if version == quicVersion2 {
		salt = quicV2InitialSalt
	} else if version == 0xff00001d {
		salt = quicDraft29InitialSalt
	}
	secret := quicHkdfExtract(salt, dcid)
	// Fixed 32-byte secrets and AES-128 always form a valid key/suite pair.
	client, _ := deriveQUICKeys(quicHkdfExpandLabel(secret, "client in", nil, 32), version, quicAES128)
	server, _ := deriveQUICKeys(quicHkdfExpandLabel(secret, "server in", nil, 32), version, quicAES128)
	return client, server
}

// getPacketTypeName returns the name of a QUIC packet type
func (q *QUICDecryptor) getPacketTypeName(packetType uint8) string {
	switch packetType {
	case QUICPacketTypeInitial:
		return "Initial"
	case QUICPacketType0RTT:
		return "0-RTT"
	case QUICPacketTypeHandshake:
		return "Handshake"
	case QUICPacketTypeRetry:
		return "Retry"
	case QUICPacketType1RTT:
		return "1-RTT"
	default:
		return "Unknown"
	}
}

// FeedClient feeds client QUIC packets
func (q *QUICDecryptor) FeedClient(data []byte) error {
	return q.queueQUICDatagram(data, true)
}

// FeedServer feeds server QUIC packets
func (q *QUICDecryptor) FeedServer(data []byte) error {
	return q.queueQUICDatagram(data, false)
}

func (q *QUICDecryptor) queueQUICDatagram(data []byte, isClient bool) error {
	q.mu.Lock()
	if q.isClosed {
		q.mu.Unlock()
		return io.ErrClosedPipe
	}
	if len(data) == 0 {
		q.mu.Unlock()
		return nil
	}
	if len(data) > maxQUICBufferedBytes-q.inputBytes || len(q.input) >= maxQUICQueuedPackets {
		q.inputErr = errQUICInputLimit
		q.isClosed = true
		q.mu.Unlock()
		q.options.Report(q.connectionInfo, "input", "resource_limit")
		_ = q.Close()
		return errQUICInputLimit
	}
	q.input = append(q.input, quicDatagram{data: append([]byte(nil), data...), isClient: isClient, at: q.packetTime})
	q.inputBytes += len(data)
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return nil
}

// CloseClient closes the client side
func (q *QUICDecryptor) CloseClient() error {
	return nil
}

// CloseServer closes the server side
func (q *QUICDecryptor) CloseServer() error {
	return nil
}

// Close closes the QUIC decryptor
func (q *QUICDecryptor) Close() error {
	q.closeOnce.Do(func() {
		q.mu.Lock()
		q.isClosed = true
		q.mu.Unlock()
		close(q.closeCh)
	})
	return nil
}

// HKDF helper functions for QUIC

func quicHkdfExtract(salt, ikm []byte) []byte {
	return hkdf.Extract(sha256.New, ikm, salt)
}

func quicHkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	fullLabel := "tls13 " + label
	hkdfLabel := make([]byte, 2+1+len(fullLabel)+1+len(context))
	hkdfLabel[0] = byte(length >> 8)
	hkdfLabel[1] = byte(length)
	hkdfLabel[2] = byte(len(fullLabel))
	copy(hkdfLabel[3:], fullLabel)
	hkdfLabel[3+len(fullLabel)] = byte(len(context))
	copy(hkdfLabel[4+len(fullLabel):], context)

	reader := hkdf.Expand(sha256.New, secret, hkdfLabel)
	out := make([]byte, length)
	_, _ = reader.Read(out)
	return out
}

// QUIC version registry
var quicVersionNames = map[uint32]string{
	0x00000001: "QUIC v1",
	0x6b3343cf: "QUIC v2",
}

// IsQUICVersionSupported checks if the QUIC version is supported
func IsQUICVersionSupported(version uint32) bool {
	if _, ok := quicVersionNames[version]; ok {
		return true
	}
	return version == 0xff00001d // draft-29
}
