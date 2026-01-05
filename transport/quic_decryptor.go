// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

// quic_decryptor.go - QUIC 解密器
package transport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"sync"
	"time"

	"github.com/cfc4n/ecapture_decryptor/crypto"
	"github.com/cfc4n/ecapture_decryptor/protocol"
	"github.com/cfc4n/ecapture_decryptor/types"
	"golang.org/x/crypto/hkdf"
)

// QUIC packet types
const (
	QUICPacketTypeInitial   = 0x00
	QUICPacketType0RTT      = 0x01
	QUICPacketTypeHandshake = 0x02
	QUICPacketTypeRetry     = 0x03
)

// QUIC v1 Initial salt (RFC 9001)
var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
}

// QUIC draft-29 Initial salt
var quicDraft29InitialSalt = []byte{
	0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c,
	0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
	0x43, 0x90, 0xa8, 0x99,
}

// QUICDecryptor implements Decryptor interface for QUIC protocol
type QUICDecryptor struct {
	connectionInfo types.ConnectionKey
	keyLog         *crypto.KeyLogStore
	logger         *log.Logger
	stdout         io.Writer
	clientIn       *QUICBuffer
	serverIn       *QUICBuffer
	closeCh        chan struct{}
	closeOnce      sync.Once
	isClosed       bool
	mu             sync.Mutex
	outputMu       sync.Mutex
	packetTime     time.Time

	// Connection state
	version    uint32
	destConnID []byte
	srcConnID  []byte

	// Decryption keys
	clientInitialKeys   *QUICKeys
	serverInitialKeys   *QUICKeys
	clientHandshakeKeys *QUICKeys
	serverHandshakeKeys *QUICKeys
	client1RTTKeys      *QUICKeys
	server1RTTKeys      *QUICKeys

	// HTTP/3 parser for HAR output
	http3Parser *protocol.HTTP3StreamParser
	packetChan  chan *types.DecryptedPacket // 解密包输出通道
}

// QUICKeys holds encryption keys for a direction
type QUICKeys struct {
	key  []byte
	iv   []byte
	hp   []byte // Header protection key
	aead cipher.AEAD
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
func NewQUICDecryptor(ci types.ConnectionKey, keyLog *crypto.KeyLogStore, logger *log.Logger, stdout io.Writer, packetChan chan *types.DecryptedPacket) types.Decryptor {
	q := &QUICDecryptor{
		connectionInfo: ci,
		keyLog:         keyLog,
		logger:         logger,
		stdout:         stdout,
		clientIn:       NewQUICBuffer(),
		serverIn:       NewQUICBuffer(),
		closeCh:        make(chan struct{}),
		packetChan:     packetChan,
	}
	// Initialize HTTP/3 parser if channel is available
	if packetChan != nil {
		q.http3Parser = protocol.NewHTTP3StreamParser(ci, packetChan)
	}
	return q
}

// GetAddr returns the connection address
func (q *QUICDecryptor) GetAddr() types.ConnectionKey {
	return q.connectionInfo
} // SetPacketTime sets the packet timestamp
func (q *QUICDecryptor) SetPacketTime(t time.Time) {
	q.packetTime = t
}

// Decrypt starts the QUIC decryption process
func (q *QUICDecryptor) Decrypt() error {
	q.logger.Printf("QUIC decryption started for %s", q.connectionInfo)

	for {
		select {
		case <-q.closeCh:
			q.logger.Printf("QUIC decryption ended for %s", q.connectionInfo)
			return nil
		default:
			q.processClientPackets()
			q.processServerPackets()
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// processClientPackets processes available client packets
func (q *QUICDecryptor) processClientPackets() {
	for {
		packet := q.clientIn.TryRead()
		if packet == nil {
			return
		}
		q.decryptAndLogPacket(packet, true)
	}
}

// processServerPackets processes available server packets
func (q *QUICDecryptor) processServerPackets() {
	for {
		packet := q.serverIn.TryRead()
		if packet == nil {
			return
		}
		q.decryptAndLogPacket(packet, false)
	}
}

// decryptAndLogPacket decrypts a QUIC packet and logs the result
func (q *QUICDecryptor) decryptAndLogPacket(packet []byte, isClient bool) {
	if len(packet) < 1 {
		return
	}

	direction := "<====="
	if isClient {
		direction = "====>"
	}

	headerByte := packet[0]
	isLongHeader := (headerByte & 0x80) != 0

	if isLongHeader {
		q.handleLongHeaderPacket(packet, isClient, direction)
	} else {
		q.handleShortHeaderPacket(packet, isClient, direction)
	}
}

// handleLongHeaderPacket handles QUIC long header packets
func (q *QUICDecryptor) handleLongHeaderPacket(packet []byte, isClient bool, direction string) {
	if len(packet) < 7 {
		q.logger.Printf("%s %s QUIC packet too short for long header", direction, q.connectionInfo)
		return
	}

	packetType := (packet[0] & 0x30) >> 4
	version := binary.BigEndian.Uint32(packet[1:5])

	if q.version == 0 {
		q.version = version
	}

	dcidLen := int(packet[5])
	if len(packet) < 6+dcidLen {
		return
	}
	dcid := packet[6 : 6+dcidLen]

	scidLenOffset := 6 + dcidLen
	if len(packet) < scidLenOffset+1 {
		return
	}
	scidLen := int(packet[scidLenOffset])
	if len(packet) < scidLenOffset+1+scidLen {
		return
	}
	scid := packet[scidLenOffset+1 : scidLenOffset+1+scidLen]

	if isClient && q.destConnID == nil {
		q.destConnID = make([]byte, len(dcid))
		copy(q.destConnID, dcid)
		q.srcConnID = make([]byte, len(scid))
		copy(q.srcConnID, scid)
		q.deriveInitialKeys(dcid)
	}

	packetTypeName := q.getPacketTypeName(packetType)
	q.logger.Printf("%s %s QUIC %s packet, version=0x%08x, dcid=%s, scid=%s, len=%d",
		direction, q.connectionInfo, packetTypeName, version,
		hex.EncodeToString(dcid), hex.EncodeToString(scid), len(packet))

	var keys *QUICKeys
	switch packetType {
	case QUICPacketTypeInitial:
		if isClient {
			keys = q.clientInitialKeys
		} else {
			keys = q.serverInitialKeys
		}
	case QUICPacketTypeHandshake:
		if isClient {
			keys = q.clientHandshakeKeys
		} else {
			keys = q.serverHandshakeKeys
		}
	case QUICPacketType0RTT:
		keys = q.client1RTTKeys
	}

	if keys != nil && keys.aead != nil {
		plaintext, err := q.decryptPacket(packet, keys, true)
		if err != nil {
			q.logger.Printf("%s %s QUIC decrypt error: %v", direction, q.connectionInfo, err)
		} else if len(plaintext) > 0 {
			q.outputDecrypted(plaintext, direction, isClient)
		}
	}
}

// handleShortHeaderPacket handles QUIC short header packets (1-RTT)
func (q *QUICDecryptor) handleShortHeaderPacket(packet []byte, isClient bool, direction string) {
	q.logger.Printf("%s %s QUIC 1-RTT packet, len=%d", direction, q.connectionInfo, len(packet))

	var keys *QUICKeys
	if isClient {
		keys = q.client1RTTKeys
	} else {
		keys = q.server1RTTKeys
	}

	if keys != nil && keys.aead != nil {
		plaintext, err := q.decryptPacket(packet, keys, false)
		if err != nil {
			q.logger.Printf("%s %s QUIC 1-RTT decrypt error: %v", direction, q.connectionInfo, err)
		} else if len(plaintext) > 0 {
			q.outputDecrypted(plaintext, direction, isClient)
		}
	}
}

// deriveInitialKeys derives initial encryption keys from destination connection ID
func (q *QUICDecryptor) deriveInitialKeys(dcid []byte) {
	salt := quicV1InitialSalt
	if q.version >= 0xff000000 && q.version <= 0xff00001d {
		salt = quicDraft29InitialSalt
	}

	initialSecret := quicHkdfExtract(salt, dcid)
	clientSecret := quicHkdfExpandLabel(initialSecret, "client in", nil, 32)
	serverSecret := quicHkdfExpandLabel(initialSecret, "server in", nil, 32)

	q.logger.Printf("QUIC Initial secrets derived from DCID: %s", hex.EncodeToString(dcid))

	var err error
	q.clientInitialKeys, err = q.deriveKeysFromSecret(clientSecret)
	if err != nil {
		q.logger.Printf("Failed to derive client initial keys: %v", err)
	}

	q.serverInitialKeys, err = q.deriveKeysFromSecret(serverSecret)
	if err != nil {
		q.logger.Printf("Failed to derive server initial keys: %v", err)
	}
}

// deriveKeysFromSecret derives QUIC keys from a traffic secret
func (q *QUICDecryptor) deriveKeysFromSecret(secret []byte) (*QUICKeys, error) {
	keys := &QUICKeys{
		key: quicHkdfExpandLabel(secret, "quic key", nil, 16),
		iv:  quicHkdfExpandLabel(secret, "quic iv", nil, 12),
		hp:  quicHkdfExpandLabel(secret, "quic hp", nil, 16),
	}

	block, err := aes.NewCipher(keys.key)
	if err != nil {
		return nil, err
	}
	keys.aead, err = cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return keys, nil
}

// decryptPacket decrypts a QUIC packet
func (q *QUICDecryptor) decryptPacket(packet []byte, keys *QUICKeys, isLongHeader bool) ([]byte, error) {
	if keys == nil || keys.aead == nil {
		return nil, errors.New("no keys available")
	}
	q.logger.Printf("QUIC packet received, keys available but full decryption not implemented")
	return nil, nil
}

// outputDecrypted outputs decrypted data and feeds to HTTP/3 parser
func (q *QUICDecryptor) outputDecrypted(data []byte, direction string, isClient bool) {
	// Feed to HTTP/3 parser for HAR output
	if q.http3Parser != nil {
		if isClient {
			q.http3Parser.FeedRequest(data)
		} else {
			q.http3Parser.FeedResponse(data)
		}
	}

	q.outputMu.Lock()
	defer q.outputMu.Unlock()
	//fmt.Printf("\n%s %s (QUIC/HTTP3)\n", direction, q.connectionInfo)
	//fmt.Printf("%s\n", string(data))
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
	default:
		return "Unknown"
	}
}

// FeedClient feeds client QUIC packets
func (q *QUICDecryptor) FeedClient(data []byte) error {
	q.mu.Lock()
	if q.isClosed {
		q.mu.Unlock()
		return nil
	}
	q.mu.Unlock()
	return q.clientIn.Write(data)
}

// FeedServer feeds server QUIC packets
func (q *QUICDecryptor) FeedServer(data []byte) error {
	q.mu.Lock()
	if q.isClosed {
		q.mu.Unlock()
		return nil
	}
	q.mu.Unlock()
	return q.serverIn.Write(data)
}

// CloseClient closes the client side
func (q *QUICDecryptor) CloseClient() error {
	q.clientIn.Close()
	return nil
}

// CloseServer closes the server side
func (q *QUICDecryptor) CloseServer() error {
	q.serverIn.Close()
	return nil
}

// Close closes the QUIC decryptor
func (q *QUICDecryptor) Close() error {
	q.closeOnce.Do(func() {
		q.mu.Lock()
		q.isClosed = true
		q.mu.Unlock()
		close(q.closeCh)
		q.clientIn.Close()
		q.serverIn.Close()
		// Flush HTTP/3 parser to create any remaining HAR entries
		if q.http3Parser != nil {
			q.http3Parser.Flush()
		}
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
	// Draft versions
	if (version & 0xff000000) == 0xff000000 {
		return true
	}
	return false
}
