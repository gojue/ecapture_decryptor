package transport

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/gojue/ecapture_decryptor/crypto"
)

const (
	quicLevelInitial = iota
	quicLevelHandshake
	quicLevelApplication
	quicLevelEarly
)

type quicDatagram struct {
	data     []byte
	isClient bool
	at       time.Time
}

type quicDeferredPacket struct {
	packet   quicPacket
	isClient bool
	at       time.Time
}

// Retain only one previous generation. The next candidates are cached even on
// authentication failure, so forged phase bits cannot force repeated HKDF work.
// Before suite selection there are at most two candidates (AES128 / ChaCha20).
type quicKeyPhaseState struct {
	generation      uint64
	authenticated   bool
	firstPN         uint64
	minimumPN       uint64
	previousMinimum uint64
	previous        *QUICKeys
	next            [2]*QUICKeys
}

type quicFlowState struct {
	clientRandom   []byte
	clientCID      []byte
	serverCID      []byte
	clientCrypto   quicStreamAssembler
	clientHello    bytes.Buffer
	streams        map[quicStreamKey]*quicStreamAssembler
	keys           [2][4][]*QUICKeys
	keyPhase       [2]quicKeyPhaseState
	largest        [2][3]uint64
	haveLargest    [2][3]bool
	pending        []quicDeferredPacket
	pendingLevels  [2][4]bool
	pendingBytes   int
	pendingSince   time.Time
	terminalErr    error
	errors         []error
	lastSecrets    *crypto.TLSSecrets
	initialRetried bool
}

func newQUICFlowState() *quicFlowState {
	return &quicFlowState{streams: make(map[quicStreamKey]*quicStreamAssembler)}
}

func quicDirectionIndex(isClient bool) int {
	if isClient {
		return 0
	}
	return 1
}

func quicPacketLevel(packet quicPacket) int {
	if !packet.long {
		return quicLevelApplication
	}
	switch packet.packetType {
	case QUICPacketTypeInitial:
		return quicLevelInitial
	case QUICPacketTypeHandshake:
		return quicLevelHandshake
	case QUICPacketType0RTT:
		return quicLevelEarly
	default:
		return -1
	}
}

func quicPacketNumberSpace(level int) int {
	if level == quicLevelEarly {
		return quicLevelApplication
	}
	return level
}

func (q *QUICDecryptor) appendQUICError(err error) {
	if err == nil {
		return
	}
	q.logger.Printf("QUIC %s: %v", q.connectionInfo, err)
	if len(q.flow.errors) < 16 {
		q.flow.errors = append(q.flow.errors, err)
	}
}

func (q *QUICDecryptor) processQUICDatagram(datagram quicDatagram) {
	packets, err := splitQUICDatagram(datagram.data)
	if err != nil {
		q.options.Report(q.connectionInfo, "input", "invalid_packet")
		q.appendQUICError(err)
		return
	}
	for _, packet := range packets {
		deferred, err := q.processQUICPacket(packet, datagram.isClient, datagram.at)
		if err != nil {
			q.appendQUICError(err)
			if q.flow.terminalErr != nil {
				return
			}
		} else if deferred {
			if len(packet.data) > maxQUICBufferedBytes-q.flow.pendingBytes || len(q.flow.pending) >= maxQUICQueuedPackets {
				q.flow.terminalErr = errors.New("QUIC deferred packet buffer limit exceeded")
				q.options.Report(q.connectionInfo, "reassembly", "resource_limit")
				q.appendQUICError(q.flow.terminalErr)
				_ = q.Close()
				return
			}
			if q.flow.pendingSince.IsZero() {
				q.flow.pendingSince = time.Now()
			}
			// Retain only this packet, not the entire coalesced/padded datagram.
			packet.data = bytes.Clone(packet.data)
			packet.dcid = bytes.Clone(packet.dcid)
			packet.scid = bytes.Clone(packet.scid)
			q.flow.pending = append(q.flow.pending, quicDeferredPacket{packet: packet, isClient: datagram.isClient, at: datagram.at})
			q.flow.pendingLevels[quicDirectionIndex(datagram.isClient)][quicPacketLevel(packet)] = true
			q.flow.pendingBytes += len(packet.data)
		}
	}
	q.retryQUICPacketsWithNewKeys()
}

func (q *QUICDecryptor) retryQUICPacketsWithNewKeys() {
	if len(q.flow.pending) != 0 {
		initialReady := q.clientInitialKeys != nil && !q.flow.initialRetried
		var secrets *crypto.TLSSecrets
		if len(q.flow.clientRandom) != 0 {
			secrets = q.keyLog.GetSecrets(q.flow.clientRandom)
		}
		if initialReady || !sameQUICSecrets(secrets, q.flow.lastSecrets) {
			q.flow.initialRetried = q.clientInitialKeys != nil
			q.flow.lastSecrets = secrets
			q.retryDeferredQUICPackets()
		}
	}
}

func sameQUICSecrets(a, b *crypto.TLSSecrets) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return bytes.Equal(a.ClientTrafficSecret, b.ClientTrafficSecret) &&
		bytes.Equal(a.ServerTrafficSecret, b.ServerTrafficSecret) &&
		bytes.Equal(a.ClientHandshakeTrafficSecret, b.ClientHandshakeTrafficSecret) &&
		bytes.Equal(a.ServerHandshakeTrafficSecret, b.ServerHandshakeTrafficSecret) &&
		bytes.Equal(a.ClientEarlyTrafficSecret, b.ClientEarlyTrafficSecret)
}

func (q *QUICDecryptor) retryDeferredQUICPackets() {
	deferred := q.flow.pending
	q.flow.pending = nil
	q.flow.pendingBytes = 0
	q.flow.pendingLevels = [2][4]bool{}
	for _, item := range deferred {
		pending, err := q.processQUICPacket(item.packet, item.isClient, item.at)
		if err != nil {
			q.appendQUICError(err)
			if q.flow.terminalErr != nil {
				return
			}
		} else if pending {
			q.flow.pending = append(q.flow.pending, item)
			q.flow.pendingLevels[quicDirectionIndex(item.isClient)][quicPacketLevel(item.packet)] = true
			q.flow.pendingBytes += len(item.packet.data)
		}
	}
	if len(q.flow.pending) == 0 {
		q.flow.pendingSince = time.Time{}
	}
}

func (q *QUICDecryptor) processQUICPacket(packet quicPacket, isClient bool, at time.Time) (bool, error) {
	if packet.long {
		if !IsQUICVersionSupported(packet.version) {
			q.options.Report(q.connectionInfo, "decrypt", "unsupported_version")
			return false, fmt.Errorf("unsupported QUIC version 0x%08x", packet.version)
		}
		if q.version == 0 {
			q.version = packet.version
		}
		if packet.version != q.version {
			q.options.Report(q.connectionInfo, "decrypt", "version_change")
			return false, fmt.Errorf("mixed QUIC versions 0x%08x and 0x%08x", q.version, packet.version)
		}
		if packet.packetType == QUICPacketTypeInitial {
			if isClient && q.destConnID == nil {
				q.destConnID = bytes.Clone(packet.dcid)
				q.flow.clientCID = bytes.Clone(packet.scid)
				q.deriveInitialKeys(packet.dcid)
			} else if !isClient && len(q.flow.serverCID) == 0 {
				q.flow.serverCID = bytes.Clone(packet.scid)
			}
		}
	}
	level := quicPacketLevel(packet)
	if level < 0 {
		return false, nil
	}
	direction := quicDirectionIndex(isClient)
	// Preserve arrival order within a direction/level while waiting for keys.
	// A secret can arrive midway through a retry pass: later packets must not
	// advance generations before earlier deferred packets get their turn.
	if q.flow.pendingLevels[direction][level] {
		return true, nil
	}
	keys, err := q.quicKeysForLevel(direction, level)
	if err != nil {
		q.options.Report(q.connectionInfo, "decrypt", "invalid_key_material")
		return false, err
	}
	if len(keys) == 0 {
		return true, nil
	}
	space := quicPacketNumberSpace(level)
	var cidLengths []int
	if !packet.long {
		known := len(q.flow.clientCID)
		if isClient {
			known = len(q.flow.serverCID)
		}
		cidLengths = append(cidLengths, known)
		for size := 0; size <= 20; size++ {
			if size != known {
				cidLengths = append(cidLengths, size)
			}
		}
	} else {
		cidLengths = []int{0}
	}
	for keyIndex, key := range keys {
		for _, cidLen := range cidLengths {
			var plaintext []byte
			var pn uint64
			var decryptErr error
			if level == quicLevelApplication {
				plaintext, pn, decryptErr = q.decryptQUICApplication(packet, key, keyIndex, cidLen, direction)
			} else {
				plaintext, pn, _, decryptErr = decryptQUICPacket(packet, key, cidLen, q.flow.largest[direction][space], q.flow.haveLargest[direction][space])
			}
			if decryptErr != nil {
				continue
			}
			if !q.flow.haveLargest[direction][space] || pn > q.flow.largest[direction][space] {
				q.flow.largest[direction][space] = pn
				q.flow.haveLargest[direction][space] = true
			}
			if err := q.parseQUICFrames(plaintext, level, isClient, at); err != nil {
				return false, err
			}
			return false, nil
		}
	}
	directionName := "server"
	if isClient {
		directionName = "client"
	}
	q.options.Report(q.connectionInfo, "decrypt", "authentication_failed")
	return false, fmt.Errorf("cannot authenticate QUIC %s packet (direction=%s, bytes=%d, first=0x%02x)",
		q.getPacketTypeName(packet.packetType), directionName, len(packet.data), packet.data[0])
}

func (q *QUICDecryptor) decryptQUICApplication(packet quicPacket, current *QUICKeys, keyIndex, cidLen, direction int) ([]byte, uint64, error) {
	state := &q.flow.keyPhase[direction]
	largest := q.flow.largest[direction][quicLevelApplication]
	haveLargest := q.flow.haveLargest[direction][quicLevelApplication]
	phase := uint8(state.generation & 1)
	// Try only current, previous, and next; never chase missing generations.
	for attempt := 0; attempt < 3; attempt++ {
		key := current
		if attempt == 1 {
			key = state.previous
			if key == nil {
				continue
			}
		} else if attempt == 2 {
			if state.next[keyIndex] == nil {
				var err error
				state.next[keyIndex], err = current.nextKeys()
				if err != nil {
					return nil, 0, err
				}
			}
			key = state.next[keyIndex]
		}
		plaintext, pn, first, err := decryptQUICPacket(packet, key, cidLen, largest, haveLargest)
		if err != nil {
			continue
		}
		packetPhase := (first >> 2) & 1
		switch attempt {
		case 0:
			if packetPhase != phase || pn < state.minimumPN {
				continue
			}
			if !state.authenticated || pn < state.firstPN {
				state.firstPN = pn
			}
		case 1:
			if packetPhase == phase || pn < state.previousMinimum || pn >= state.firstPN {
				continue
			}
			// A later reordered old packet tightens the lower bound for current.
			if pn >= state.minimumPN {
				state.minimumPN = pn + 1
			}
			return plaintext, pn, nil
		case 2:
			if packetPhase == phase || (haveLargest && pn <= largest) {
				continue
			}
			state.previous = current
			state.previousMinimum = state.minimumPN
			state.minimumPN = 0
			if haveLargest {
				state.minimumPN = largest + 1
			}
			state.firstPN = pn
			state.generation++
		}
		state.authenticated = true
		q.flow.keys[direction][quicLevelApplication] = []*QUICKeys{key}
		if attempt == 2 {
			state.next = [2]*QUICKeys{}
		} else {
			state.next = [2]*QUICKeys{state.next[keyIndex]}
		}
		return plaintext, pn, nil
	}
	return nil, 0, errors.New("QUIC application packet authentication failed")
}

func (q *QUICDecryptor) quicKeysForLevel(direction, level int) ([]*QUICKeys, error) {
	if level == quicLevelInitial {
		key := q.serverInitialKeys
		if direction == 0 {
			key = q.clientInitialKeys
		}
		if key == nil {
			return nil, nil
		}
		return []*QUICKeys{key}, nil
	}
	if keys := q.flow.keys[direction][level]; len(keys) != 0 {
		return keys, nil
	}
	if len(q.flow.clientRandom) == 0 {
		return nil, nil
	}
	secrets := q.keyLog.GetSecrets(q.flow.clientRandom)
	if secrets == nil {
		return nil, nil
	}
	var secret []byte
	switch level {
	case quicLevelHandshake:
		if direction == 0 {
			secret = secrets.ClientHandshakeTrafficSecret
		} else {
			secret = secrets.ServerHandshakeTrafficSecret
		}
	case quicLevelApplication:
		if direction == 0 {
			secret = secrets.ClientTrafficSecret
		} else {
			secret = secrets.ServerTrafficSecret
		}
	case quicLevelEarly:
		if direction == 0 {
			secret = secrets.ClientEarlyTrafficSecret
		}
	}
	if len(secret) == 0 {
		return nil, nil
	}
	var suites []quicCipherSuite
	if len(secret) == 48 {
		suites = []quicCipherSuite{quicAES256}
	} else {
		suites = []quicCipherSuite{quicAES128, quicChaCha20}
	}
	for _, suite := range suites {
		key, err := deriveQUICKeys(secret, q.version, suite)
		if err != nil {
			return nil, err
		}
		q.flow.keys[direction][level] = append(q.flow.keys[direction][level], key)
	}
	return q.flow.keys[direction][level], nil
}
