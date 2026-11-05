package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
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
	order    uint64
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

type quicHandshakeState struct {
	originalDCID    []byte
	retry           *quicPacket
	retryApplied    bool
	versions        []uint32
	confirmed       bool
	previousInitial [2]*QUICKeys
}

type quicEarlyFrame struct {
	id, offset uint64
	data       []byte
	fin        bool
	reset      bool
	errorCode  uint64
	at         time.Time
}

type quicEarlyState struct {
	status         string // empty until authenticated EncryptedExtensions
	lastStatus     string
	seen, emitting bool
	frames         []quicEarlyFrame
	bytes          int
	since          time.Time
	streams        map[quicStreamKey]*quicStreamAssembler
}

type quicFlowState struct {
	early           quicEarlyState
	serverCrypto    [2]quicStreamAssembler
	serverHandshake [2]bytes.Buffer
	cipherSuite     uint16
	handshake       quicHandshakeState
	clientRandom    []byte
	clientCID       []byte
	serverCID       []byte
	clientCrypto    quicStreamAssembler
	clientHello     bytes.Buffer
	streams         map[quicStreamKey]*quicStreamAssembler
	keys            [2][4][]*QUICKeys
	keyPhase        [2]quicKeyPhaseState
	largest         [2][3]uint64
	haveLargest     [2][3]bool
	pending         []quicDeferredPacket
	pendingLevels   [2][4]bool
	pendingBytes    int
	pendingSince    time.Time
	terminalErr     error
	errors          []error
	lastSecrets     *crypto.TLSSecrets
	initialRetried  bool
	cids            [2]map[uint64]quicCID
	zeroCID         [2]bool
	cidFloor        [2]uint64
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
			packet.token = bytes.Clone(packet.token)
			q.flow.pending = append(q.flow.pending, quicDeferredPacket{packet: packet, isClient: datagram.isClient, at: datagram.at})
			q.flow.pendingLevels[quicDirectionIndex(datagram.isClient)][quicPacketLevel(packet)] = true
			q.flow.pendingBytes += len(packet.data)
		}
	}
	q.retryQUICPacketsWithNewKeys()
}

func (q *QUICDecryptor) retryQUICPacketsWithNewKeys() {
	for pass := 0; pass < 3 && len(q.flow.pending) != 0; pass++ {
		initialReady := q.clientInitialKeys != nil && !q.flow.initialRetried
		var secrets *crypto.TLSSecrets
		if len(q.flow.clientRandom) != 0 {
			secrets = q.keyLog.GetSecrets(q.flow.clientRandom)
		}
		if initialReady || !sameQUICSecrets(secrets, q.flow.lastSecrets) || q.flow.early.status != q.flow.early.lastStatus {
			q.flow.early.lastStatus = q.flow.early.status
			q.flow.initialRetried = q.clientInitialKeys != nil
			q.flow.lastSecrets = secrets
			q.retryDeferredQUICPackets()
		} else {
			break
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
		if packet.packetType == QUICPacketTypeRetry || packet.version == 0 {
			return false, q.observeQUICNegotiation(packet, isClient)
		}
		if !IsQUICVersionSupported(packet.version) {
			q.options.Report(q.connectionInfo, "decrypt", "unsupported_version")
			if isClient && packet.packetType == QUICPacketTypeInitial && len(packet.data) > 0 && q.version == 0 {
				q.version = packet.version
				q.destConnID = bytes.Clone(packet.dcid)
				q.flow.clientCID = bytes.Clone(packet.scid)
				return false, nil // A following VN can select a supported version.
			}
			return false, fmt.Errorf("unsupported QUIC version 0x%08x", packet.version)
		}
		if packet.packetType == QUICPacketTypeInitial {
			return q.processQUICInitial(packet, isClient, at)
		}
		if packet.version != q.version {
			q.options.Report(q.connectionInfo, "decrypt", "version_change")
			return false, errors.New("unexpected QUIC version change")
		}
	}
	level := quicPacketLevel(packet)
	if level < 0 {
		return false, nil
	}
	direction := quicDirectionIndex(isClient)
	if level == quicLevelEarly && !isClient {
		return false, errors.New("server cannot send QUIC 0-RTT")
	}
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
		if level == quicLevelEarly && q.flow.early.status == "rejected" && !q.options.RawChunks {
			return false, nil // Rejected ciphertext need not delay a 1-RTT replay.
		}
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
			if level == quicLevelApplication || level == quicLevelHandshake {
				q.flow.handshake.confirmed = true
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
	if level != quicLevelEarly && q.flow.cipherSuite != 0 {
		switch q.flow.cipherSuite {
		case 0x1301:
			suites = []quicCipherSuite{quicAES128}
		case 0x1302:
			suites = []quicCipherSuite{quicAES256}
		case 0x1303:
			suites = []quicCipherSuite{quicChaCha20}
		default:
			return nil, errors.New("unsupported QUIC TLS cipher suite")
		}
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

const maxQUICConnectionIDs = 64

type quicCID struct {
	id, token []byte
	retired   bool
}

// QUICRoutedPacket transfers an already captured packet from the SDK router.
// Order is the reader's ordinal, not a capture timestamp.
type QUICRoutedPacket struct {
	Data     []byte
	IsClient bool
	Time     time.Time
	Order    uint64
}

// SetConnectionIDHandler connects authenticated CID updates to the SDK router.
// Configure before Decrypt. The handler must not call this decryptor; returned
// packets are merged into its bounded input in capture arrival order.
func (q *QUICDecryptor) SetConnectionIDHandler(handler func([]byte, bool, bool) ([]QUICRoutedPacket, error)) {
	q.routingHandler = handler
}

func (q *QUICDecryptor) FeedQUICPacket(packet QUICRoutedPacket) error {
	q.mu.Lock()
	if q.isClosed {
		q.mu.Unlock()
		return io.ErrClosedPipe
	}
	err := q.insertRoutedPacketsLocked([]QUICRoutedPacket{packet})
	q.mu.Unlock()
	if err != nil {
		q.options.Report(q.connectionInfo, "input", "resource_limit")
		_ = q.Close()
		return err
	}
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return nil
}

func (q *QUICDecryptor) insertRoutedPacketsLocked(packets []QUICRoutedPacket) error {
	for _, packet := range packets {
		if len(q.input) >= maxQUICQueuedPackets || len(packet.Data) > maxQUICBufferedBytes-q.inputBytes {
			q.inputErr = errQUICInputLimit
			return errQUICInputLimit
		}
		q.input = append(q.input, quicDatagram{data: bytes.Clone(packet.Data), isClient: packet.IsClient, at: packet.Time, order: packet.Order})
		q.inputBytes += len(packet.Data)
	}
	return nil
}

func (q *QUICDecryptor) publishQUICCID(cid []byte, ownerClient, retired bool) error {
	if q.routingHandler == nil {
		return nil
	}
	packets, err := q.routingHandler(cid, ownerClient, retired)
	if err == nil && len(packets) > 0 {
		q.mu.Lock()
		err = q.insertRoutedPacketsLocked(packets)
		// Buffered unknown-CID packets must not be overtaken by later packets
		// already in the worker queue, especially across key generations.
		sort.SliceStable(q.input, func(i, j int) bool { return q.input[i].order < q.input[j].order })
		q.mu.Unlock()
		select {
		case q.wake <- struct{}{}:
		default:
		}
	}
	if err != nil {
		q.flow.terminalErr = err
		q.options.Report(q.connectionInfo, "input", "resource_limit")
		_ = q.Close()
	}
	return err
}

func (q *QUICDecryptor) observeQUICCID(sequence, retirePrior uint64, cid, token []byte, ownerClient bool) error {
	if len(cid) == 0 || len(cid) > 20 || retirePrior > sequence {
		return errors.New("invalid QUIC connection ID")
	}
	dir := quicDirectionIndex(ownerClient)
	if q.flow.cids[dir] == nil {
		q.flow.cids[dir] = make(map[uint64]quicCID)
	}
	ids := q.flow.cids[dir]
	if q.flow.zeroCID[dir] {
		return errors.New("NEW_CONNECTION_ID after zero-length CID")
	}
	for seq, old := range ids {
		if seq != sequence && bytes.Equal(old.id, cid) {
			return errors.New("duplicate QUIC CID with different sequence")
		}
	}
	if old, ok := ids[sequence]; ok && len(old.id) > 0 && (!bytes.Equal(old.id, cid) || len(old.token) > 0 && len(token) > 0 && !bytes.Equal(old.token, token)) {
		return errors.New("conflicting QUIC connection ID sequence")
	}
	for seq, old := range ids {
		if seq < retirePrior {
			if !old.retired && len(old.id) > 0 {
				if err := q.publishQUICCID(old.id, ownerClient, true); err != nil {
					return err
				}
			}
			delete(ids, seq)
		}
	}
	if retirePrior > q.flow.cidFloor[dir] {
		q.flow.cidFloor[dir] = retirePrior
	}
	if sequence < q.flow.cidFloor[dir] {
		return nil
	}
	if _, ok := ids[sequence]; ok {
		return nil
	}
	if len(ids) >= maxQUICConnectionIDs {
		err := errors.New("QUIC connection ID limit exceeded")
		q.flow.terminalErr = err
		q.options.Report(q.connectionInfo, "reassembly", "resource_limit")
		_ = q.Close()
		return err
	}
	ids[sequence] = quicCID{id: bytes.Clone(cid), token: bytes.Clone(token)}
	return q.publishQUICCID(cid, ownerClient, false)
}

func (q *QUICDecryptor) retireQUICCID(sequence uint64, ownerClient bool) error {
	dir := quicDirectionIndex(ownerClient)
	if sequence < q.flow.cidFloor[dir] {
		return nil
	}
	if q.flow.cids[dir] == nil {
		q.flow.cids[dir] = make(map[uint64]quicCID)
	}
	ids := q.flow.cids[dir]
	old, known := ids[sequence]
	if old.retired {
		return nil
	}
	if !known && len(ids) >= maxQUICConnectionIDs {
		err := errors.New("QUIC retired connection ID limit exceeded")
		q.flow.terminalErr = err
		q.options.Report(q.connectionInfo, "reassembly", "resource_limit")
		_ = q.Close()
		return err
	}
	old.retired = true
	ids[sequence] = old
	if len(old.id) > 0 {
		if err := q.publishQUICCID(old.id, ownerClient, true); err != nil {
			return err
		}
	}
	for ids[q.flow.cidFloor[dir]].retired {
		delete(ids, q.flow.cidFloor[dir])
		q.flow.cidFloor[dir]++
	}
	return nil
}

func (q *QUICDecryptor) observeQUICNegotiation(packet quicPacket, isClient bool) error {
	hs := &q.flow.handshake
	fail := func(code string) error {
		q.options.Report(q.connectionInfo, "handshake", code)
		return fmt.Errorf("QUIC negotiation: %s", code)
	}
	if isClient || q.destConnID == nil || !bytes.Equal(packet.dcid, q.flow.clientCID) {
		return fail("invalid_negotiation")
	}
	if packet.version == 0 {
		data := packet.data[packet.pnOffset:]
		if len(data) == 0 || len(data)%4 != 0 || len(data) > 64 || !bytes.Equal(packet.scid, q.destConnID) {
			return fail("invalid_version_negotiation")
		}
		var versions []uint32
		for len(data) > 0 {
			v := binary.BigEndian.Uint32(data[:4])
			if v == 0 || v == q.version {
				return fail("invalid_version_negotiation")
			}
			versions = append(versions, v)
			data = data[4:]
		}
		if !hs.confirmed && hs.retry == nil {
			hs.versions = versions // Observation only; never selects a version.
		}
		return nil
	}
	if packet.version != q.version || bytes.Equal(packet.scid, hs.originalDCID) || !validQUICRetry(packet, hs.originalDCID) {
		return fail("invalid_retry")
	}
	if hs.confirmed || hs.retry != nil {
		return nil // At most one Retry; duplicates cannot reset any epoch.
	}
	packet.data = bytes.Clone(packet.data)
	packet.dcid = bytes.Clone(packet.dcid)
	packet.scid = bytes.Clone(packet.scid)
	packet.token = bytes.Clone(packet.data[packet.pnOffset : len(packet.data)-16])
	hs.retry = &packet
	return q.publishQUICCID(packet.scid, false, false)
}

func (q *QUICDecryptor) processQUICInitial(packet quicPacket, isClient bool, at time.Time) (bool, error) {
	hs := &q.flow.handshake
	dir := quicDirectionIndex(isClient)
	client, server := q.clientInitialKeys, q.serverInitialKeys
	first := q.destConnID == nil
	retry := isClient && hs.retry != nil && !hs.retryApplied && bytes.Equal(packet.dcid, hs.retry.scid)
	versionChange := packet.version != q.version && !first
	if versionChange {
		allowed := false
		for _, v := range hs.versions {
			allowed = allowed || v == packet.version
		}
		if !isClient || hs.confirmed || !allowed {
			q.options.Report(q.connectionInfo, "decrypt", "version_change")
			return false, errors.New("unexpected QUIC version change")
		}
	}
	if retry && (!bytes.Equal(packet.token, hs.retry.token) || !bytes.Equal(packet.scid, q.flow.clientCID)) {
		q.options.Report(q.connectionInfo, "handshake", "invalid_retry")
		return false, errors.New("Initial does not echo Retry token and client CID")
	}
	if isClient && (first || retry || versionChange) {
		client, server = quicInitialKeys(packet.version, packet.dcid)
	}
	key := server
	if isClient {
		key = client
	}
	if key == nil {
		return true, nil
	}
	largest, have := q.flow.largest[dir][quicLevelInitial], q.flow.haveLargest[dir][quicLevelInitial]
	if versionChange {
		largest, have = 0, false
	}
	plain, pn, _, err := decryptQUICPacket(packet, key, 0, largest, have)
	if err != nil {
		if old := hs.previousInitial[dir]; old != nil {
			if _, _, _, oldErr := decryptQUICPacket(packet, old, 0, largest, have); oldErr == nil {
				return false, nil
			}
		}
		q.options.Report(q.connectionInfo, "decrypt", "authentication_failed")
		return false, errors.New("cannot authenticate QUIC Initial")
	}
	if first || retry || versionChange {
		if retry {
			hs.previousInitial = [2]*QUICKeys{q.clientInitialKeys, q.serverInitialKeys}
			hs.retryApplied = true
		}
		if versionChange {
			q.flow.keys = [2][4][]*QUICKeys{}
			q.flow.largest, q.flow.haveLargest = [2][3]uint64{}, [2][3]bool{}
			hs.versions = nil
		}
		q.version = packet.version
		q.destConnID = bytes.Clone(packet.dcid)
		q.flow.clientCID = bytes.Clone(packet.scid)
		q.clientInitialKeys, q.serverInitialKeys = client, server
		q.flow.clientCrypto, q.flow.clientHello = quicStreamAssembler{}, bytes.Buffer{}
		q.flow.clientRandom = nil
		if first || versionChange {
			hs.originalDCID = bytes.Clone(packet.dcid)
		}
	}
	if !isClient {
		hs.confirmed = true
		q.flow.serverCID = bytes.Clone(packet.scid)
	}
	if !q.flow.haveLargest[dir][quicLevelInitial] || pn > q.flow.largest[dir][quicLevelInitial] {
		q.flow.largest[dir][quicLevelInitial], q.flow.haveLargest[dir][quicLevelInitial] = pn, true
	}
	if len(packet.scid) == 0 {
		q.flow.zeroCID[dir] = true
		err = q.publishQUICCID(nil, isClient, false)
	} else {
		err = q.observeQUICCID(0, 0, packet.scid, nil, isClient)
	}
	if err != nil {
		return false, err
	}
	// Initial retransmissions can use a peer CID announced in encrypted frames
	// whose directional secret has not arrived yet. This packet proves the link.
	if !q.flow.keyPhase[0].authenticated && !q.flow.keyPhase[1].authenticated {
		// Once authenticated application frames can retire CIDs, delayed Initial
		// packets must not resurrect the retired routing entries.
		if err := q.publishQUICCID(packet.dcid, !isClient, false); err != nil {
			return false, err
		}
	}
	return false, q.parseQUICFrames(plain, quicLevelInitial, isClient, at)
}
