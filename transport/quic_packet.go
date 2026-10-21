package transport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	quicVersion1      uint32 = 1
	quicVersion2      uint32 = 0x6b3343cf
	quicMaxPacketSize        = 64 << 10
)

type quicCipherSuite uint8

const (
	quicAES128 quicCipherSuite = iota
	quicAES256
	quicChaCha20
)

type quicPacket struct {
	data       []byte
	version    uint32
	packetType uint8
	long       bool
	pnOffset   int
	dcid       []byte
	scid       []byte
}

func readQUICVarint(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, ioUnexpectedQUICEnd
	}
	size := 1 << (data[0] >> 6)
	if len(data) < size {
		return 0, 0, ioUnexpectedQUICEnd
	}
	value := uint64(data[0] & 0x3f)
	for _, b := range data[1:size] {
		value = value<<8 | uint64(b)
	}
	return value, size, nil
}

var ioUnexpectedQUICEnd = errors.New("truncated QUIC packet")

// A UDP datagram can contain several coalesced long-header packets. A short
// header packet, when present, consumes the rest of the datagram. An all-zero
// tail after a long-header packet is padding, not a short-header packet.
func splitQUICDatagram(data []byte) ([]quicPacket, error) {
	var packets []quicPacket
	for len(data) > 0 {
		if len(data) > quicMaxPacketSize {
			return nil, fmt.Errorf("QUIC datagram exceeds %d bytes", quicMaxPacketSize)
		}
		if data[0]&0x80 == 0 {
			// A long-header packet can be followed by zero-filled UDP padding.
			// The tail is not a separate protected 1-RTT packet.
			if len(packets) > 0 && data[0] == 0 {
				padding := true
				for _, b := range data[1:] {
					if b != 0 {
						padding = false
						break
					}
				}
				if padding {
					break
				}
			}
			packets = append(packets, quicPacket{data: data, packetType: QUICPacketType1RTT})
			break
		}
		if len(data) < 7 {
			return nil, ioUnexpectedQUICEnd
		}
		version := binary.BigEndian.Uint32(data[1:5])
		if version == 0 { // Version Negotiation has no protected payload.
			break
		}
		pos := 5
		dcidLen := int(data[pos])
		pos++
		if dcidLen > 20 || len(data) < pos+dcidLen+1 {
			return nil, ioUnexpectedQUICEnd
		}
		dcid := data[pos : pos+dcidLen]
		pos += dcidLen
		scidLen := int(data[pos])
		pos++
		if scidLen > 20 || len(data) < pos+scidLen {
			return nil, ioUnexpectedQUICEnd
		}
		scid := data[pos : pos+scidLen]
		pos += scidLen
		packetType := (data[0] >> 4) & 3
		if version == quicVersion2 {
			packetType = (packetType + 3) & 3 // v2: Retry, Initial, 0-RTT, Handshake.
		}
		if packetType == QUICPacketTypeRetry {
			break // Retry is not AEAD protected and consumes the datagram.
		}
		if packetType == QUICPacketTypeInitial {
			tokenLen, n, err := readQUICVarint(data[pos:])
			if err != nil || tokenLen > uint64(len(data)-pos-n) {
				return nil, ioUnexpectedQUICEnd
			}
			pos += n + int(tokenLen)
		}
		payloadLen, n, err := readQUICVarint(data[pos:])
		if err != nil || payloadLen < 17 || payloadLen > uint64(len(data)-pos-n) {
			return nil, ioUnexpectedQUICEnd
		}
		pos += n
		end := pos + int(payloadLen)
		packets = append(packets, quicPacket{
			data: data[:end], version: version, packetType: packetType,
			long: true, pnOffset: pos, dcid: dcid, scid: scid,
		})
		data = data[end:]
	}
	return packets, nil
}

func quicHash(secret []byte) (func() hash.Hash, error) {
	switch len(secret) {
	case sha256.Size:
		return sha256.New, nil
	case sha512.Size384:
		return sha512.New384, nil
	default:
		return nil, fmt.Errorf("unsupported QUIC traffic secret length %d", len(secret))
	}
}

func expandQUICLabel(secret []byte, label string, length int) ([]byte, error) {
	hashFn, err := quicHash(secret)
	if err != nil {
		return nil, err
	}
	fullLabel := "tls13 " + label
	info := make([]byte, 2+1+len(fullLabel)+1)
	binary.BigEndian.PutUint16(info[:2], uint16(length))
	info[2] = byte(len(fullLabel))
	copy(info[3:], fullLabel)
	out := make([]byte, length)
	_, err = hkdf.Expand(hashFn, secret, info).Read(out)
	return out, err
}

func deriveQUICKeys(secret []byte, version uint32, suite quicCipherSuite) (*QUICKeys, error) {
	keyLen := 16
	if suite != quicAES128 {
		keyLen = 32
	}
	if suite == quicAES256 && len(secret) != sha512.Size384 || suite != quicAES256 && len(secret) != sha256.Size {
		return nil, errors.New("QUIC cipher suite and traffic secret hash mismatch")
	}
	label := "quic "
	if version == quicVersion2 {
		label = "quicv2 "
	}
	key, err := expandQUICLabel(secret, label+"key", keyLen)
	if err != nil {
		return nil, err
	}
	iv, err := expandQUICLabel(secret, label+"iv", 12)
	if err != nil {
		return nil, err
	}
	hp, err := expandQUICLabel(secret, label+"hp", keyLen)
	if err != nil {
		return nil, err
	}
	keys := &QUICKeys{key: key, iv: iv, hp: hp, suite: suite, secret: append([]byte(nil), secret...), version: version}
	if suite == quicChaCha20 {
		keys.aead, err = chacha20poly1305.New(key)
	} else {
		var block cipher.Block
		block, err = aes.NewCipher(key)
		if err == nil {
			keys.aead, err = cipher.NewGCM(block)
		}
	}
	return keys, err
}

func (k *QUICKeys) headerMask(sample []byte) ([5]byte, error) {
	var mask [5]byte
	if len(sample) < 16 {
		return mask, ioUnexpectedQUICEnd
	}
	if k.suite == quicChaCha20 {
		stream, err := chacha20.NewUnauthenticatedCipher(k.hp, sample[4:16])
		if err != nil {
			return mask, err
		}
		stream.SetCounter(binary.LittleEndian.Uint32(sample[:4]))
		stream.XORKeyStream(mask[:], mask[:])
		return mask, nil
	}
	block, err := aes.NewCipher(k.hp)
	if err != nil {
		return mask, err
	}
	var encrypted [16]byte
	block.Encrypt(encrypted[:], sample[:16])
	copy(mask[:], encrypted[:5])
	return mask, nil
}

func reconstructQUICPacketNumber(truncated uint64, pnLen int, largest uint64, haveLargest bool) uint64 {
	if !haveLargest {
		return truncated
	}
	expected := largest + 1
	window := uint64(1) << (pnLen * 8)
	half := window / 2
	candidate := (expected & ^(window - 1)) | truncated
	if candidate+half <= expected && candidate < (1<<62)-window {
		return candidate + window
	}
	if candidate > expected+half && candidate >= window {
		return candidate - window
	}
	return candidate
}

func decryptQUICPacket(packet quicPacket, keys *QUICKeys, cidLen int, largest uint64, haveLargest bool) ([]byte, uint64, uint8, error) {
	if keys == nil || keys.aead == nil {
		return nil, 0, 0, errors.New("QUIC decryption keys unavailable")
	}
	pnOffset := packet.pnOffset
	if !packet.long {
		pnOffset = 1 + cidLen
	}
	if pnOffset < 1 || pnOffset+4+16 > len(packet.data) {
		return nil, 0, 0, ioUnexpectedQUICEnd
	}
	mask, err := keys.headerMask(packet.data[pnOffset+4 : pnOffset+20])
	if err != nil {
		return nil, 0, 0, err
	}
	first := packet.data[0]
	if packet.long {
		first ^= mask[0] & 0x0f
	} else {
		first ^= mask[0] & 0x1f
	}
	pnLen := int(first&3) + 1
	header := append([]byte(nil), packet.data[:pnOffset+pnLen]...)
	header[0] = first
	var truncated uint64
	for i := 0; i < pnLen; i++ {
		header[pnOffset+i] ^= mask[i+1]
		truncated = truncated<<8 | uint64(header[pnOffset+i])
	}
	pn := reconstructQUICPacketNumber(truncated, pnLen, largest, haveLargest)
	nonce := append([]byte(nil), keys.iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	plaintext, err := keys.aead.Open(nil, nonce, packet.data[pnOffset+pnLen:], header)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("QUIC packet authentication: %w", err)
	}
	return plaintext, pn, first, nil
}
