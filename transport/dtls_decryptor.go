// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/gojue/ecapture_decryptor/crypto"
	"github.com/gojue/ecapture_decryptor/types"
)

const (
	dtlsQueueLimit     = 4 << 20
	dtlsRecordLimit    = 4096
	dtlsHandshakeLimit = 1 << 20
	dtlsMessageLimit   = 256 << 10
)

var (
	errDTLS            = errors.New("invalid DTLS record or handshake")
	errDTLSUnsupported = errors.New("unsupported DTLS version, cipher, or epoch")
	errDTLSLimit       = errors.New("DTLS resource limit exceeded")
)

type dtlsDatagram struct {
	data []byte
	side int
	at   time.Time
}
type dtlsFragmentKey struct {
	side       int
	epoch, seq uint16
}
type dtlsFragment struct {
	typ        byte
	data, seen []byte
	count      int
	done       bool
	size       int
}
type dtlsReplay struct {
	set     bool
	highest uint64
	bits    [2]uint64
}

func (r *dtlsReplay) seen(n uint64) bool {
	if !r.set || n > r.highest {
		return false
	}
	delta := r.highest - n
	return delta >= 128 || r.bits[delta/64]&(uint64(1)<<(delta%64)) != 0
}
func (r *dtlsReplay) add(n uint64) {
	if !r.set {
		r.set = true
		r.highest = n
		r.bits[0] = 1
		return
	}
	if n > r.highest {
		d := n - r.highest
		switch {
		case d >= 128:
			r.bits = [2]uint64{}
		case d >= 64:
			r.bits[1] = r.bits[0] << (d - 64)
			r.bits[0] = 0
		default:
			r.bits[1] = r.bits[1]<<d | r.bits[0]>>(64-d)
			r.bits[0] <<= d
		}
		r.highest = n
	}
	d := r.highest - n
	r.bits[d/64] |= uint64(1) << (d % 64)
}

// DTLSDecryptor outputs one packet per authenticated application record. It
// never synthesizes a byte stream, retransmits, or interprets application data.
type DTLSDecryptor struct {
	conn      types.ConnectionKey
	keys      *crypto.KeyLogStore
	out       chan *types.DecryptedPacket
	options   types.DecryptOptions
	mu        sync.Mutex
	queue     []dtlsDatagram
	queued    int
	at        time.Time
	closed    bool
	inputErr  error
	wake      chan struct{}
	stop      chan struct{}
	closeOnce sync.Once
	// The remaining state is owned only by Decrypt.
	fragments                  map[dtlsFragmentKey]*dtlsFragment
	fragmentBytes              int
	clientSide                 int
	serverSide                 int
	clientRandom, serverRandom []byte
	suite                      uint16
	offered                    map[uint16]bool
	clientHelloSeq             uint16
	deferred                   []dtlsDatagram
	deferredBytes              int
	decryptors                 [2]*crypto.DTLSRecordDecryptor
	replay                     [2]dtlsReplay
	err                        error
}

func NewDTLSDecryptor(conn types.ConnectionKey, keys *crypto.KeyLogStore, out chan *types.DecryptedPacket) *DTLSDecryptor {
	return &DTLSDecryptor{conn: conn, keys: keys, out: out, wake: make(chan struct{}, 1), stop: make(chan struct{}), clientSide: -1, serverSide: -1, fragments: make(map[dtlsFragmentKey]*dtlsFragment)}
}
func (d *DTLSDecryptor) SetOptions(o types.DecryptOptions) { d.options = o }
func (d *DTLSDecryptor) GetAddr() types.ConnectionKey      { return d.conn }
func (d *DTLSDecryptor) SetPacketTime(t time.Time)         { d.mu.Lock(); d.at = t; d.mu.Unlock() }
func (d *DTLSDecryptor) FeedClient(data []byte) error      { return d.feed(data, 0) }
func (d *DTLSDecryptor) FeedServer(data []byte) error      { return d.feed(data, 1) }
func (d *DTLSDecryptor) feed(data []byte, side int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	if len(data) > 65535 || len(data) > dtlsQueueLimit-d.queued || len(d.queue) >= dtlsRecordLimit {
		d.inputErr = errDTLSLimit
		select {
		case d.wake <- struct{}{}:
		default:
		}
		return errDTLSLimit
	}
	d.queue = append(d.queue, dtlsDatagram{bytes.Clone(data), side, d.at})
	d.queued += len(data)
	select {
	case d.wake <- struct{}{}:
	default:
	}
	return nil
}
func (d *DTLSDecryptor) CloseClient() error { return nil }
func (d *DTLSDecryptor) CloseServer() error { return nil }
func (d *DTLSDecryptor) Close() error {
	d.closeOnce.Do(func() { d.mu.Lock(); d.closed = true; d.mu.Unlock(); close(d.stop) })
	return nil
}
func (d *DTLSDecryptor) failure(stage, code string, err error) error {
	if d.err == nil {
		d.err = err
		d.options.Report(d.conn, stage, code)
	}
	return d.err
}
func (d *DTLSDecryptor) Decrypt() error {
	defer func() {
		_ = d.Close()
		d.mu.Lock()
		d.queue = nil
		d.queued = 0
		d.mu.Unlock()
		d.fragments = nil
		d.deferred = nil
		d.clientRandom = nil
		d.serverRandom = nil
		d.offered = nil
		d.decryptors = [2]*crypto.DTLSRecordDecryptor{}
	}()
	if err := d.options.Validate(); err != nil {
		return d.failure("input", "invalid_options", err)
	}
	if d.out == nil || d.options.ApplicationProtocol != "" || d.options.TLSUpgrade != "" || d.options.HTTPEvents {
		return d.failure("input", "invalid_options", errDTLSUnsupported)
	}
	timer := time.NewTimer(d.options.SecretWaitTimeout())
	defer timer.Stop()
	deadline := timer.C
	for {
		updates := d.keys.Updates()
		d.mu.Lock()
		queue := d.queue
		d.queue = nil
		d.queued = 0
		inputErr := d.inputErr
		closed := d.closed
		d.mu.Unlock()
		if inputErr != nil {
			return d.failure("input", "resource_limit", inputErr)
		}
		for _, datagram := range queue {
			if err := d.datagram(datagram); err != nil {
				return d.reportError(err)
			}
		}
		if err := d.retry(); err != nil {
			return d.reportError(err)
		}
		if d.decryptors[0] != nil {
			deadline = nil
		}
		if closed {
			if d.decryptors[0] == nil {
				return d.failure("keys", "missing_secret", errors.New("DTLS handshake or key unavailable"))
			}
			for _, f := range d.fragments {
				if !f.done {
					return d.failure("handshake", "truncated_handshake", io.ErrUnexpectedEOF)
				}
			}
			return d.err
		}
		select {
		case <-d.wake:
		case <-updates:
		case <-d.stop:
		case <-deadline:
			return d.failure("keys", "key_wait_timeout", errors.New("DTLS handshake/key deadline exceeded"))
		}
	}
}
func (d *DTLSDecryptor) reportError(err error) error {
	code := "invalid_record"
	stage := "handshake"
	if errors.Is(err, errDTLSLimit) {
		stage, code = "input", "resource_limit"
	} else if errors.Is(err, errDTLSUnsupported) {
		code = "unsupported_protocol"
	}
	return d.failure(stage, code, err)
}
func (d *DTLSDecryptor) datagram(p dtlsDatagram) error {
	data := p.data
	if len(data) == 0 {
		return errDTLS
	}
	for len(data) > 0 {
		if len(data) < 13 {
			return errDTLS
		}
		size := 13 + int(binary.BigEndian.Uint16(data[11:]))
		if size > len(data) || size > 13+18432 {
			return errDTLS
		}
		record := data[:size]
		data = data[size:]
		version, epoch := binary.BigEndian.Uint16(record[1:]), binary.BigEndian.Uint16(record[3:])
		if version != 0xfefd && !(epoch == 0 && version == 0xfeff) {
			return errDTLSUnsupported
		}
		if record[0] < 20 || record[0] > 23 {
			return errDTLSUnsupported
		}
		if epoch == 0 {
			if size > 13+16384 {
				return errDTLS
			}
			switch record[0] {
			case 22:
				if err := d.handshake(record[13:], p.side, epoch); err != nil {
					return err
				}
			case 20:
				if !bytes.Equal(record[13:], []byte{1}) {
					return errDTLS
				}
			case 21:
				if len(record) != 15 {
					return errDTLS
				}
			default:
				return errDTLS
			}
			continue
		}
		if epoch != 1 || version != 0xfefd {
			return errDTLSUnsupported
		}
		if d.decryptors[0] == nil {
			if len(record) > dtlsQueueLimit-d.deferredBytes || len(d.deferred) >= dtlsRecordLimit {
				return errDTLSLimit
			}
			d.deferred = append(d.deferred, dtlsDatagram{bytes.Clone(record), p.side, p.at})
			d.deferredBytes += len(record)
		} else if err := d.authenticated(record, p.side, p.at); err != nil {
			return err
		}
	}
	return nil
}
func (d *DTLSDecryptor) retry() error {
	if d.decryptors[0] == nil && d.clientSide >= 0 && len(d.serverRandom) > 0 {
		secrets := d.keys.GetSecrets(d.clientRandom)
		if secrets == nil || len(secrets.MasterSecret) == 0 {
			return nil
		}
		if !d.offered[d.suite] {
			return errDTLS
		}
		for side := range 2 {
			dec, err := crypto.NewDTLSRecordDecryptor(d.suite, secrets.MasterSecret, d.clientRandom, d.serverRandom, side != d.clientSide)
			if err != nil {
				return d.failure("keys", "invalid_secret", err)
			}
			d.decryptors[side] = dec
		}
	}
	if d.decryptors[0] == nil {
		return nil
	}
	pending := d.deferred
	d.deferred = nil
	d.deferredBytes = 0
	for _, p := range pending {
		if err := d.authenticated(p.data, p.side, p.at); err != nil {
			return err
		}
	}
	return nil
}
func (d *DTLSDecryptor) authenticated(record []byte, side int, at time.Time) error {
	seq := uint64(0)
	for _, b := range record[5:11] {
		seq = seq<<8 | uint64(b)
	}
	// Old/duplicate records cannot affect state or output. Unseen records are
	// committed to the replay window only after their authentication succeeds.
	if d.replay[side].seen(seq) {
		return nil
	}
	plain, err := d.decryptors[side].Decrypt(record)
	if err != nil {
		_ = d.failure("decrypt", "authentication_failed", err) // Preserve the final error while decoding later records.
		return nil
	}
	d.replay[side].add(seq)
	switch record[0] {
	case 23:
		direction := "response"
		if side == d.clientSide {
			direction = "request"
		}
		packet := types.NewDecryptedPacket("udp", "dtls", direction, plain, at, d.conn)
		// The association ID preserves the first captured tuple, which may
		// originate at the server. Public endpoints still describe this packet.
		if d.clientSide == 1 {
			packet.SrcIP, packet.DstIP = packet.DstIP, packet.SrcIP
			packet.SrcPort, packet.DstPort = packet.DstPort, packet.SrcPort
		}
		packet.Metadata["kind"] = "datagram"
		packet.Metadata["epoch"] = uint16(1)
		packet.Metadata["sequence"] = seq
		d.out <- packet
	case 22:
		return d.handshake(plain, side, 1)
	case 21:
		if len(plain) != 2 {
			return errDTLS
		}
	default:
		return errDTLS
	}
	return nil
}
func dtlsUint24(b []byte) int { return int(b[0])<<16 | int(b[1])<<8 | int(b[2]) }
func (d *DTLSDecryptor) handshake(data []byte, side int, epoch uint16) error {
	for len(data) > 0 {
		if len(data) < 12 {
			return errDTLS
		}
		typ, size, seq := data[0], dtlsUint24(data[1:]), binary.BigEndian.Uint16(data[4:])
		offset, n := dtlsUint24(data[6:]), dtlsUint24(data[9:])
		if n > len(data)-12 || offset > size || n > size-offset || n == 0 && size != 0 {
			return errDTLS
		}
		if size > dtlsMessageLimit {
			return errDTLSLimit
		}
		key := dtlsFragmentKey{side, epoch, seq}
		f := d.fragments[key]
		if f == nil {
			if len(d.fragments) >= 64 || size > dtlsHandshakeLimit-d.fragmentBytes {
				return errDTLSLimit
			}
			f = &dtlsFragment{typ: typ, size: size, data: make([]byte, size), seen: make([]byte, size)}
			d.fragments[key] = f
			d.fragmentBytes += size
		} else if f.typ != typ || f.size != size {
			if f.done && (f.typ == 1 || f.typ == 2) {
				return errDTLSUnsupported
			}
			return errDTLS
		}
		if f.done && f.data != nil && !bytes.Equal(f.data[offset:offset+n], data[12:12+n]) {
			// A changed Hello reusing a completed message number is a new or
			// conflicting handshake, not a retransmission under the old keys.
			return errDTLSUnsupported
		}
		if !f.done {
			for i, b := range data[12 : 12+n] {
				pos := offset + i
				if f.seen[pos] != 0 {
					if f.data[pos] != b {
						return errDTLS
					}
				} else {
					f.data[pos] = b
					f.seen[pos] = 1
					f.count++
				}
			}
			if f.count == size {
				if err := d.hello(typ, f.data, side, epoch, seq); err != nil {
					return err
				}
				f.done = true
				f.seen = nil
				// Retain only key-selecting Hellos for exact comparison of
				// retransmitted fragments. They share the existing payload cap.
				if typ != 1 && typ != 2 {
					f.data = nil
					d.fragmentBytes -= size
				}
			}
		}
		data = data[12+n:]
	}
	return nil
}
func (d *DTLSDecryptor) hello(typ byte, body []byte, side int, epoch, seq uint16) error {
	if epoch == 1 {
		if typ != 20 || len(body) != 12 {
			return errDTLSUnsupported
		}
		return nil
	}
	switch typ {
	case 1:
		if len(body) < 38 || binary.BigEndian.Uint16(body) != 0xfefd {
			return errDTLSUnsupported
		}
		if d.serverSide == side || d.clientSide >= 0 && (d.clientSide != side || !bytes.Equal(d.clientRandom, body[2:34])) {
			return errDTLSUnsupported
		}
		p := 35 + int(body[34])
		if body[34] > 32 || p >= len(body) {
			return errDTLS
		}
		cookie := int(body[p])
		p++
		if p+cookie+2 > len(body) {
			return errDTLS
		}
		p += cookie
		n := int(binary.BigEndian.Uint16(body[p:]))
		p += 2
		if n < 2 || n%2 != 0 || p+n+1 > len(body) {
			return errDTLS
		}
		offered := make(map[uint16]bool)
		for end := p + n; p < end; p += 2 {
			offered[binary.BigEndian.Uint16(body[p:])] = true
		}
		compression := int(body[p])
		p++
		if compression == 0 || p+compression > len(body) || !bytes.Contains(body[p:p+compression], []byte{0}) {
			return errDTLS
		}
		p += compression
		if err := validateDTLSExtensions(body[p:]); err != nil {
			return err
		}
		if d.clientSide < 0 || seq >= d.clientHelloSeq {
			d.clientSide = side
			d.clientRandom = bytes.Clone(body[2:34])
			d.clientHelloSeq = seq
			d.offered = offered
		}
	case 2:
		if len(body) < 38 || binary.BigEndian.Uint16(body) != 0xfefd {
			return errDTLSUnsupported
		}
		p := 35 + int(body[34])
		if body[34] > 32 || p+3 > len(body) || body[p+2] != 0 {
			return errDTLS
		}
		suite := binary.BigEndian.Uint16(body[p:])
		if suite != 0xc02f && suite != 0xc030 {
			return errDTLSUnsupported
		}
		if err := validateDTLSExtensions(body[p+3:]); err != nil {
			return err
		}
		if d.clientSide == side || d.serverSide >= 0 && d.serverSide != side {
			return errDTLS
		}
		if len(d.serverRandom) > 0 && (!bytes.Equal(d.serverRandom, body[2:34]) || d.suite != suite) {
			return errDTLSUnsupported
		}
		d.serverSide = side
		d.serverRandom = bytes.Clone(body[2:34])
		d.suite = suite
	case 3: // HelloVerifyRequest's cookie exchange stays in the same tuple.
		if len(body) < 3 || len(body) != 3+int(body[2]) {
			return errDTLS
		}
	default:
		if typ != 11 && typ != 12 && typ != 13 && typ != 14 && typ != 15 && typ != 16 && typ != 4 {
			return errDTLSUnsupported
		}
	}
	return nil
}
func validateDTLSExtensions(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if len(data) < 2 || int(binary.BigEndian.Uint16(data)) != len(data)-2 {
		return errDTLS
	}
	seen := make(map[uint16]bool)
	for data = data[2:]; len(data) > 0; {
		if len(data) < 4 {
			return errDTLS
		}
		typ, n := binary.BigEndian.Uint16(data), int(binary.BigEndian.Uint16(data[2:]))
		if n > len(data)-4 || seen[typ] {
			return errDTLS
		}
		seen[typ] = true
		if typ == 43 || typ == 54 {
			return errDTLSUnsupported
		}
		data = data[4+n:]
	}
	return nil
}
