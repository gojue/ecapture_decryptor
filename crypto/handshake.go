// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

const maxHandshakeMessage = 1 << 20

var ErrHandshakeResourceLimit = errors.New("TLS handshake resource limit exceeded")
var errInvalidHandshake = errors.New("invalid TLS handshake message")

// HandshakeAssembler frames authenticated handshake fragments. A complete
// message owns its bytes; only the current incomplete message is retained.
// The caller serializes access and validates encryption-epoch boundaries.
type HandshakeAssembler struct {
	pending []byte
	err     error
}

func (a *HandshakeAssembler) Feed(data []byte) (messages [][]byte, err error) {
	if a.err != nil {
		return nil, a.err
	}
	for len(data) > 0 {
		size := 4
		if len(a.pending) >= 4 {
			size += int(a.pending[1])<<16 | int(a.pending[2])<<8 | int(a.pending[3])
			if size > maxHandshakeMessage {
				a.pending = nil
				a.err = ErrHandshakeResourceLimit
				return nil, a.err
			}
		}
		n := min(size-len(a.pending), len(data))
		a.pending = append(a.pending, data[:n]...)
		data = data[n:]
		if len(a.pending) < 4 {
			continue
		}
		size = 4 + int(a.pending[1])<<16 + int(a.pending[2])<<8 + int(a.pending[3])
		if size > maxHandshakeMessage || len(messages) >= 4096 {
			a.pending = nil
			a.err = ErrHandshakeResourceLimit
			return nil, a.err
		}
		if len(a.pending) == size {
			messages = append(messages, a.pending)
			a.pending = nil
		}
	}
	return messages, nil
}
func (a *HandshakeAssembler) Pending() bool { return len(a.pending) != 0 }
func (a *HandshakeAssembler) Reset()        { a.pending = nil; a.err = nil }

// readHandshakeMessage accepts a split four-byte header and preserves every
// following message from its final plaintext record for subsequent processing.
func readHandshakeMessage(s *StreamBuffer, earlyRecord ...func([]byte) error) ([]byte, error) {
	var message []byte
	size := 4
	for records := 0; ; records++ {
		if records >= 4096 {
			return nil, ErrHandshakeResourceLimit
		}
		record, err := s.ReadRecord()
		if err != nil {
			if len(message) != 0 && errors.Is(err, io.EOF) {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		if len(record) < 5 || record[1] != 3 {
			return nil, errInvalidHandshake
		}
		if record[0] == 23 && len(message) == 0 && len(earlyRecord) == 1 {
			if record[2] != 3 || len(record)-5 > 16384+256 {
				return nil, errInvalidHandshake
			}
			if err := earlyRecord[0](record); err != nil {
				return nil, err
			}
			continue
		}
		if len(record)-5 > 16384 {
			return nil, errInvalidHandshake
		}
		if record[0] == 20 && bytes.Equal(record[5:], []byte{1}) && len(message) == 0 {
			continue
		}
		if record[0] != 22 || len(record) == 5 {
			return nil, errInvalidHandshake
		}
		data := record[5:]
		for len(data) > 0 {
			n := min(size-len(message), len(data))
			message = append(message, data[:n]...)
			data = data[n:]
			if len(message) < 4 {
				break
			}
			size = 4 + int(message[1])<<16 + int(message[2])<<8 + int(message[3])
			if size > maxHandshakeMessage {
				return nil, ErrHandshakeResourceLimit
			}
			if len(message) == size {
				if len(data) > 0 {
					tail := append(bytes.Clone(record[:5]), data...)
					binary.BigEndian.PutUint16(tail[3:5], uint16(len(data)))
					if err := s.unreadRecord(tail); err != nil {
						return nil, err
					}
				}
				return message, nil
			}
		}
	}
}

type helloExtension struct {
	typ   uint16
	data  []byte
	start int
}

func parseHelloExtensions(message []byte, offset int) ([]helloExtension, error) {
	if offset == len(message) {
		return nil, nil
	}
	if offset+2 > len(message) || int(binary.BigEndian.Uint16(message[offset:])) != len(message)-offset-2 {
		return nil, errInvalidHandshake
	}
	var extensions []helloExtension
	seen := make(map[uint16]bool)
	for p := offset + 2; p < len(message); {
		if p+4 > len(message) {
			return nil, errInvalidHandshake
		}
		typ, n := binary.BigEndian.Uint16(message[p:]), int(binary.BigEndian.Uint16(message[p+2:]))
		if seen[typ] || n > len(message)-p-4 {
			return nil, errInvalidHandshake
		}
		if len(extensions) >= 1024 {
			return nil, ErrHandshakeResourceLimit
		}
		seen[typ] = true
		extensions = append(extensions, helloExtension{typ, message[p+4 : p+4+n], p + 4})
		p += 4 + n
	}
	return extensions, nil
}
func validHandshake(message []byte, typ byte) bool {
	return len(message) >= 4 && len(message) <= maxHandshakeMessage && message[0] == typ &&
		4+int(message[1])<<16+int(message[2])<<8+int(message[3]) == len(message)
}

// ClientHelloInfo retains the complete wire handshake for ECH authentication;
// Random always names this message, never an inferred or searched keylog entry.
type ClientHelloInfo struct {
	Random          []byte
	EarlyData       bool
	ECHOffered      bool
	Message         []byte
	extensions      []helloExtension
	extensionOffset int
	sessionID       []byte
}

// ReadClientHello reads one complete plaintext ClientHello, preserving tails.
func ReadClientHello(s *StreamBuffer) (*ClientHelloInfo, error) {
	message, err := readHandshakeMessage(s)
	if err != nil {
		return nil, err
	}
	return parseClientHello(message)
}

// ReadClientHelloRetry reads CH2 after HRR. The caller bounds and retains each
// preceding encrypted early record; ciphertext inside a split CH2 is invalid.
func ReadClientHelloRetry(s *StreamBuffer, earlyRecord func([]byte) error) (*ClientHelloInfo, error) {
	if earlyRecord == nil {
		return nil, errInvalidHandshake
	}
	message, err := readHandshakeMessage(s, earlyRecord)
	if err != nil {
		return nil, err
	}
	return parseClientHello(message)
}
func parseClientHello(message []byte) (*ClientHelloInfo, error) {
	if !validHandshake(message, 1) || len(message) < 39 {
		return nil, errInvalidHandshake
	}
	message = bytes.Clone(message)
	p := 38
	sid := int(message[p])
	p++
	if sid > 32 || p+sid+2 > len(message) {
		return nil, errInvalidHandshake
	}
	session := message[p : p+sid]
	p += sid
	suites := int(binary.BigEndian.Uint16(message[p:]))
	p += 2
	if suites < 2 || suites%2 != 0 || p+suites+1 > len(message) {
		return nil, errInvalidHandshake
	}
	p += suites
	compression := int(message[p])
	p++
	if compression == 0 || p+compression > len(message) {
		return nil, errInvalidHandshake
	}
	p += compression
	extensions, err := parseHelloExtensions(message, p)
	if err != nil {
		return nil, err
	}
	result := &ClientHelloInfo{Random: bytes.Clone(message[6:38]), Message: message, extensions: extensions, extensionOffset: p, sessionID: session}
	for _, e := range extensions {
		switch e.typ {
		case 42:
			if len(e.data) != 0 {
				return nil, errInvalidHandshake
			}
			result.EarlyData = true
		case 0xfe0d:
			if len(e.data) == 0 || e.data[0] > 1 || e.data[0] == 1 && len(e.data) != 1 {
				return nil, errInvalidHandshake
			}
			result.ECHOffered = e.data[0] == 0
		}
	}
	return result, nil
}

func ExtractClientRandom(s *StreamBuffer) ([]byte, error) {
	hello, err := ReadClientHello(s)
	if err != nil {
		return nil, err
	}
	return hello.Random, nil
}
func ExtractServerRandom(handshake []byte) ([]byte, error) {
	if !validHandshake(handshake, 2) || len(handshake) < 38 {
		return nil, errInvalidHandshake
	}
	return bytes.Clone(handshake[6:38]), nil
}

func serverHello(message []byte) (version, suite uint16, extensions []helloExtension, err error) {
	if !validHandshake(message, 2) || len(message) < 42 {
		return 0, 0, nil, errInvalidHandshake
	}
	sid := int(message[38])
	p := 39 + sid
	if sid > 32 || p+3 > len(message) || message[p+2] != 0 {
		return 0, 0, nil, errInvalidHandshake
	}
	version, suite = binary.BigEndian.Uint16(message[4:]), binary.BigEndian.Uint16(message[p:])
	extensions, err = parseHelloExtensions(message, p+3)
	if err != nil {
		return 0, 0, nil, err
	}
	for _, e := range extensions {
		if e.typ == 43 {
			if len(e.data) != 2 {
				return 0, 0, nil, errInvalidHandshake
			}
			version = binary.BigEndian.Uint16(e.data)
		}
		if e.typ == 41 && len(e.data) != 2 {
			return 0, 0, nil, errInvalidHandshake
		}
	}
	return version, suite, extensions, nil
}

// ParseServerHello returns one ServerHello or HelloRetryRequest. Callers must
// handle HRR before selecting application keys and must reject repeated HRR.
func ParseServerHello(s *StreamBuffer) (version uint16, cipherSuite uint16, handshakeMsg []byte, err error) {
	handshakeMsg, err = readHandshakeMessage(s)
	if err != nil {
		return 0, 0, nil, err
	}
	version, cipherSuite, _, err = serverHello(handshakeMsg)
	return
}

var helloRetryRandom = []byte{0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c}

func IsHelloRetryRequest(message []byte) bool {
	return validHandshake(message, 2) && len(message) >= 38 && bytes.Equal(message[6:38], helloRetryRandom)
}
func ServerHelloResumed(message []byte) bool {
	version, _, extensions, err := serverHello(message)
	if err != nil || version != VersionTLS13 || IsHelloRetryRequest(message) {
		return false
	}
	for _, e := range extensions {
		if e.typ == 41 {
			return true
		}
	}
	return false
}

var (
	ErrECHSecretsUnavailable = errors.New("ECH keylog material unavailable")
	ErrECHUnsupported        = errors.New("unsupported ECH parameters or retry")
	ErrECHAuthentication     = errors.New("ECH authentication failed")
	ErrECHInvalid            = errors.New("invalid ECH encoding")
)

// ResolveECHClientHello authenticates the encrypted ClientHello with RFC 9850
// ECH_SECRET/ECH_CONFIG attached to its exact outer random. Only a verified
// RFC 9849 acceptance confirmation selects the inner random for TLS key lookup.
// It supports the mandatory X25519/HKDF-SHA256/AES-128-GCM ECH suite, without HRR.
func ResolveECHClientHello(outer *ClientHelloInfo, serverMessage []byte, secrets *TLSSecrets) (*ClientHelloInfo, string, error) {
	if outer == nil {
		return nil, "unknown", ErrECHInvalid
	}
	// Reparse the exported wire value so caller mutation cannot detach offsets
	// or random metadata from the authenticated ClientHello.
	outer, err := parseClientHello(outer.Message)
	if err != nil {
		return nil, "unknown", ErrECHInvalid
	}
	if !outer.ECHOffered {
		return outer, "not_offered", nil
	}
	if IsHelloRetryRequest(serverMessage) {
		return nil, "unknown", ErrECHUnsupported
	}
	version, suite, _, err := serverHello(serverMessage)
	if err != nil {
		return nil, "unknown", ErrECHInvalid
	}
	if version != VersionTLS13 {
		return outer, "rejected", nil
	}
	inner, err := decryptECHHello(outer, secrets, 0)
	if err != nil {
		return nil, "unknown", err
	}
	modified := bytes.Clone(serverMessage)
	clear(modified[30:38])
	confirmation, err := echConfirmation(suite, inner.Random, "ech accept confirmation", false, inner.Message, modified)
	if err != nil {
		return nil, "unknown", err
	}
	if !hmac.Equal(confirmation, serverMessage[30:38]) {
		return outer, "rejected", nil
	}
	return inner, "accepted", nil
}

// ECHClientEarlyRandom authenticates CH1's encrypted payload and returns its
// inner random only when it offers early data. ECH rejection does not change
// that early-secret index; this result never selects the application handshake
// or asserts server acceptance. The caller supplies material for this outer CH.
func ECHClientEarlyRandom(outer *ClientHelloInfo, secrets *TLSSecrets) ([]byte, error) {
	if outer == nil {
		return nil, ErrECHInvalid
	}
	outer, err := parseClientHello(outer.Message)
	if err != nil || !outer.ECHOffered {
		return nil, ErrECHInvalid
	}
	inner, err := decryptECHHello(outer, secrets, 0)
	if err != nil {
		return nil, err
	}
	if !inner.EarlyData {
		return nil, nil
	}
	// RFC 9849 Section 6.1 requires the first outer CH to copy early_data,
	// allowing a rejecting server to safely discard the early records.
	if !outer.EarlyData {
		return nil, ErrECHInvalid
	}
	return bytes.Clone(inner.Random), nil
}

func decryptECHHello(outer *ClientHelloInfo, secrets *TLSSecrets, sequence byte) (*ClientHelloInfo, error) {
	if secrets == nil || len(secrets.ECHSecret) == 0 || len(secrets.ECHConfig) == 0 {
		return nil, ErrECHSecretsUnavailable
	}
	var ech helloExtension
	for _, e := range outer.extensions {
		if e.typ == 0xfd00 {
			return nil, ErrECHInvalid
		}
		if e.typ == 0xfe0d {
			ech = e
		}
	}
	data := ech.data
	if len(data) < 10 || data[0] != 0 {
		return nil, ErrECHInvalid
	}
	kdf, aead := binary.BigEndian.Uint16(data[1:]), binary.BigEndian.Uint16(data[3:])
	if kdf != 1 || aead != 1 {
		return nil, ErrECHUnsupported
	}
	enc := int(binary.BigEndian.Uint16(data[6:]))
	if sequence == 0 && enc != 32 || sequence == 1 && enc != 0 || sequence > 1 {
		return nil, ErrECHUnsupported
	}
	p := 8 + enc
	if p+2 > len(data) {
		return nil, ErrECHInvalid
	}
	n := int(binary.BigEndian.Uint16(data[p:]))
	p += 2
	if n < 16 || n != len(data)-p {
		return nil, ErrECHInvalid
	}
	if err := validateECHConfig(secrets.ECHConfig, data[5]); err != nil {
		return nil, err
	}
	protection, nonce, err := echProtection(secrets.ECHSecret, secrets.ECHConfig)
	if err != nil {
		return nil, err
	}
	// RFC 9180: the second Seal/Open uses base_nonce XOR I2OSP(1, Nn).
	nonce[len(nonce)-1] ^= sequence
	// ClientHelloOuterAAD omits the handshake header and replaces only the
	// encrypted payload with zeros; the enc, length and other fields stay bound.
	aad := bytes.Clone(outer.Message[4:])
	clear(aad[ech.start+p-4 : ech.start+p-4+n])
	encoded, err := protection.Open(nil, nonce, data[p:], aad)
	if err != nil {
		return nil, ErrECHAuthentication
	}
	return decodeECHInner(outer, encoded)
}

func echConfirmation(suite uint16, random []byte, label string, retry bool, messages ...[]byte) ([]byte, error) {
	var newHash func() hash.Hash
	switch suite {
	case 0x1301, 0x1303:
		newHash = sha256.New
	case 0x1302:
		newHash = sha512.New384
	default:
		return nil, ErrECHUnsupported
	}
	transcript := newHash()
	for i, message := range messages {
		if i == 0 && retry {
			// HRR replaces CH1 with the synthetic message_hash handshake.
			first := newHash()
			first.Write(message)
			transcript.Write([]byte{254, 0, 0, byte(first.Size())})
			transcript.Write(first.Sum(nil))
		} else {
			transcript.Write(message)
		}
	}
	context := transcript.Sum(nil)
	secret := hkdf.Extract(newHash, random, nil)
	label = "tls13 " + label
	info := append([]byte{0, 8, byte(len(label))}, label...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	confirmation := make([]byte, 8)
	if _, err := io.ReadFull(hkdf.Expand(newHash, secret, info), confirmation); err != nil {
		return nil, ErrECHInvalid
	}
	return confirmation, nil
}

// ResolveECHClientHelloRetry authenticates both ECH payloads and the HRR/final
// confirmations. It retains no state after returning. The first selected hello
// supplies any early-data offer; the second supplies the final TLS key index.
func ResolveECHClientHelloRetry(first, second *ClientHelloInfo, retry, final []byte, secrets *TLSSecrets) (*ClientHelloInfo, *ClientHelloInfo, string, error) {
	if first == nil || second == nil {
		return nil, nil, "unknown", ErrECHInvalid
	}
	first, err := parseClientHello(first.Message)
	if err != nil {
		return nil, nil, "unknown", err
	}
	second, err = parseClientHello(second.Message)
	if err != nil || !first.ECHOffered || !second.ECHOffered {
		return nil, nil, "unknown", ErrECHInvalid
	}
	version, suite, extensions, err := serverHello(retry)
	finalVersion, finalSuite, _, finalErr := serverHello(final)
	if err != nil || finalErr != nil || !IsHelloRetryRequest(retry) || IsHelloRetryRequest(final) || version != VersionTLS13 || finalVersion != version || finalSuite != suite {
		return nil, nil, "unknown", ErrECHInvalid
	}
	var signal helloExtension
	for _, e := range extensions {
		if e.typ == 0xfe0d {
			signal = e
			if len(e.data) != 8 {
				return nil, nil, "unknown", ErrECHInvalid
			}
		}
	}
	var firstECH, secondECH []byte
	for _, e := range first.extensions {
		if e.typ == 0xfe0d {
			firstECH = e.data
		}
	}
	for _, e := range second.extensions {
		if e.typ == 0xfe0d {
			secondECH = e.data
		}
	}
	// Rejection/GREASE keeps the outer random and the complete ECH extension.
	outerRetry := bytes.Equal(first.Random, second.Random) && bytes.Equal(first.sessionID, second.sessionID) && bytes.Equal(firstECH, secondECH)
	if secrets == nil || len(secrets.ECHSecret) == 0 || len(secrets.ECHConfig) == 0 {
		if outerRetry {
			if second.EarlyData {
				return nil, nil, "unknown", ErrECHInvalid
			}
			return first, second, "unknown", nil
		}
		return nil, nil, "unknown", ErrECHSecretsUnavailable
	}
	inner1, err := decryptECHHello(first, secrets, 0)
	if err != nil {
		return nil, nil, "unknown", err
	}
	modified := bytes.Clone(retry)
	if len(signal.data) == 8 {
		clear(modified[signal.start : signal.start+8])
	}
	confirm, err := echConfirmation(suite, inner1.Random, "hrr ech accept confirmation", true, inner1.Message, modified)
	if err != nil {
		return nil, nil, "unknown", err
	}
	if !hmac.Equal(confirm, signal.data) {
		if second.EarlyData {
			return nil, nil, "unknown", ErrECHInvalid
		}
		if !outerRetry {
			return nil, nil, "unknown", ErrECHAuthentication
		}
		return first, second, "rejected", nil
	}
	if len(firstECH) < 6 || len(secondECH) < 6 || !bytes.Equal(firstECH[:6], secondECH[:6]) {
		return nil, nil, "unknown", ErrECHInvalid
	}
	inner2, err := decryptECHHello(second, secrets, 1)
	if err != nil {
		return nil, nil, "unknown", err
	}
	// An accepted ECH CH2 outer AAD may copy CH1's extensions, including
	// early_data (RFC 9849 Section 6.1.5). Its authenticated inner must remove it.
	if inner2.EarlyData || !bytes.Equal(inner1.Random, inner2.Random) || !bytes.Equal(inner1.sessionID, inner2.sessionID) {
		return nil, nil, "unknown", ErrECHInvalid
	}
	modified = bytes.Clone(final)
	clear(modified[30:38])
	confirm, err = echConfirmation(suite, inner2.Random, "ech accept confirmation", true, inner1.Message, retry, inner2.Message, modified)
	if err != nil || !hmac.Equal(confirm, final[30:38]) {
		return nil, nil, "unknown", ErrECHAuthentication
	}
	return inner1, inner2, "accepted", nil
}

func validateECHConfig(config []byte, id byte) error {
	if len(config) < 12 || binary.BigEndian.Uint16(config) != 0xfe0d || int(binary.BigEndian.Uint16(config[2:])) != len(config)-4 || config[4] != id {
		return ErrECHInvalid
	}
	if binary.BigEndian.Uint16(config[5:]) != 0x20 {
		return ErrECHUnsupported
	}
	keyLen := int(binary.BigEndian.Uint16(config[7:]))
	p := 9 + keyLen
	if keyLen != 32 || p+2 > len(config) {
		return ErrECHInvalid
	}
	suites := int(binary.BigEndian.Uint16(config[p:]))
	p += 2
	if suites < 4 || suites%4 != 0 || p+suites+2 > len(config) {
		return ErrECHInvalid
	}
	matched := false
	for end := p + suites; p < end; p += 4 {
		matched = matched || binary.BigEndian.Uint16(config[p:]) == 1 && binary.BigEndian.Uint16(config[p+2:]) == 1
	}
	if !matched {
		return ErrECHUnsupported
	}
	p++ // maximum_name_length is a padding hint, not a hostname bound.
	nameLen := int(config[p])
	p++
	if nameLen == 0 || p+nameLen+2 > len(config) {
		return ErrECHInvalid
	}
	p += nameLen
	extensions, err := parseHelloExtensions(config, p)
	if err != nil {
		return ErrECHInvalid
	}
	for _, e := range extensions {
		if e.typ&0x8000 != 0 {
			return ErrECHUnsupported
		}
	}
	return nil
}

// RFC 9180 base-mode key schedule, beginning at the logged KEM shared_secret.
// crypto/hpke does not expose importing an already-derived shared secret.
func echProtection(shared, config []byte) (cipher.AEAD, []byte, error) {
	if len(shared) != 32 {
		return nil, nil, ErrECHInvalid
	}
	suite := []byte{'H', 'P', 'K', 'E', 0, 0x20, 0, 1, 0, 1}
	extract := func(salt []byte, label string, ikm []byte) []byte {
		h := hmac.New(sha256.New, salt)
		h.Write([]byte("HPKE-v1"))
		h.Write(suite)
		h.Write([]byte(label))
		h.Write(ikm)
		return h.Sum(nil)
	}
	info := append([]byte("tls ech\x00"), config...)
	context := append([]byte{0}, extract(nil, "psk_id_hash", nil)...)
	context = append(context, extract(nil, "info_hash", info)...)
	secret := extract(shared, "secret", nil)
	expand := func(label string, n int) []byte {
		info := append([]byte{0, byte(n)}, []byte("HPKE-v1")...)
		info = append(info, suite...)
		info = append(info, label...)
		info = append(info, context...)
		result := make([]byte, n)
		_, _ = io.ReadFull(hkdf.Expand(sha256.New, secret, info), result)
		return result
	}
	block, err := aes.NewCipher(expand("key", 16))
	if err != nil {
		return nil, nil, ErrECHInvalid
	}
	aead, err := cipher.NewGCM(block)
	return aead, expand("base_nonce", 12), err
}

func decodeECHInner(outer *ClientHelloInfo, encoded []byte) (*ClientHelloInfo, error) {
	if len(encoded) < 40 || encoded[34] != 0 {
		return nil, ErrECHInvalid
	}
	p := 35
	suites := int(binary.BigEndian.Uint16(encoded[p:]))
	p += 2
	if suites < 2 || suites%2 != 0 || p+suites+1 > len(encoded) {
		return nil, ErrECHInvalid
	}
	p += suites
	compression := int(encoded[p])
	p++
	if compression == 0 || p+compression+2 > len(encoded) {
		return nil, ErrECHInvalid
	}
	p += compression
	end := p + 2 + int(binary.BigEndian.Uint16(encoded[p:]))
	if end > len(encoded) {
		return nil, ErrECHInvalid
	}
	for _, padding := range encoded[end:] {
		if padding != 0 {
			return nil, ErrECHInvalid
		}
	}
	message := handshakeEncoding(1, encoded[:end])
	compressed, err := parseClientHello(message)
	if err != nil {
		return nil, ErrECHInvalid
	}
	var extensions []byte
	seen := make(map[uint16]bool)
	for _, e := range compressed.extensions {
		if e.typ != 0xfd00 {
			seen[e.typ] = true
		}
	}
	innerECH := false
	for _, e := range compressed.extensions {
		if e.typ != 0xfd00 {
			extensions = append(extensions, message[e.start-4:e.start+len(e.data)]...)
			innerECH = innerECH || e.typ == 0xfe0d && bytes.Equal(e.data, []byte{1})
			continue
		}
		if len(e.data) < 3 || len(e.data) != int(e.data[0])+1 || e.data[0]%2 != 0 {
			return nil, ErrECHInvalid
		}
		last := -1
		for i := 1; i < len(e.data); i += 2 {
			typ := binary.BigEndian.Uint16(e.data[i:])
			if typ == 0xfe0d || typ == 0xfd00 || seen[typ] {
				return nil, ErrECHInvalid
			}
			found := -1
			for j := last + 1; j < len(outer.extensions); j++ {
				if outer.extensions[j].typ == typ {
					found = j
					break
				}
			}
			if found < 0 {
				return nil, ErrECHInvalid
			}
			x := outer.extensions[found]
			extensions = append(extensions, outer.Message[x.start-4:x.start+len(x.data)]...)
			seen[typ], last = true, found
		}
	}
	if !innerECH || len(extensions) > 65535 {
		return nil, ErrECHInvalid
	}
	body := append(bytes.Clone(encoded[:34]), byte(len(outer.sessionID)))
	body = append(body, outer.sessionID...)
	body = append(body, encoded[35:p]...)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	inner, err := parseClientHello(handshakeEncoding(1, body))
	if err != nil || bytes.Equal(inner.Random, outer.Random) {
		return nil, ErrECHInvalid
	}
	return inner, nil
}

func handshakeEncoding(typ byte, body []byte) []byte {
	message := []byte{typ, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(message, body...)
}

const (
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304
)
