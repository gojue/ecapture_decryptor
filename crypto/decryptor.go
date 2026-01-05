// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"hash"
	"sync"

	"golang.org/x/crypto/hkdf"
)

// RecordDecryptor handles decryption of TLS records
type RecordDecryptor struct {
	version     uint16
	cipherSuite uint16
	aead        cipher.AEAD
	seq         uint64
	iv          []byte     // For TLS 1.3
	mu          sync.Mutex // protects seq and ensures thread-safe decryption
	// For TLS 1.2 and earlier with CBC mode
	blockCipher cipher.Block
	macHash     hash.Hash
	macSize     int
	ivSize      int
}

// NewRecordDecryptor creates a decryptor for TLS 1.3
func NewRecordDecryptor(version uint16, cipherSuite uint16, trafficSecret []byte) (*RecordDecryptor, error) {
	rd := &RecordDecryptor{
		version:     version,
		cipherSuite: cipherSuite,
		seq:         0,
	}

	// Get cipher suite config from registry
	config, ok := GetCipherSuite(cipherSuite)
	if !ok || config.Version == TLSVersion12 {
		return nil, fmt.Errorf("unsupported TLS 1.3 cipher suite: 0x%04x", cipherSuite)
	}

	// Derive key and IV using HKDF-Expand-Label
	key := hkdfExpandLabel(config.HashFunc, trafficSecret, "key", nil, config.KeyLen)
	iv := hkdfExpandLabel(config.HashFunc, trafficSecret, "iv", nil, 12)

	// Create AEAD cipher
	var err error
	rd.aead, err = config.AEADFactory(key)
	if err != nil {
		return nil, err
	}

	rd.iv = iv
	return rd, nil
}

// hkdfExpandLabel implements HKDF-Expand-Label from RFC 8446
func hkdfExpandLabel(hashFunc func() hash.Hash, secret []byte, label string, context []byte, length int) []byte {
	// HkdfLabel structure:
	// struct {
	//     uint16 length = Length;
	//     opaque label<7..255> = "tls13 " + Label;
	//     opaque context<0..255> = Context;
	// } HkdfLabel;
	fullLabel := "tls13 " + label
	hkdfLabel := make([]byte, 2+1+len(fullLabel)+1+len(context))
	hkdfLabel[0] = byte(length >> 8)
	hkdfLabel[1] = byte(length)
	hkdfLabel[2] = byte(len(fullLabel))
	copy(hkdfLabel[3:], fullLabel)
	hkdfLabel[3+len(fullLabel)] = byte(len(context))
	copy(hkdfLabel[4+len(fullLabel):], context)

	reader := hkdf.Expand(hashFunc, secret, hkdfLabel)
	result := make([]byte, length)
	reader.Read(result)
	return result
}

// NewRecordDecryptorTLS12 creates a decryptor for TLS 1.2 and earlier
func NewRecordDecryptorTLS12(version uint16, cipherSuite uint16, masterSecret, clientRandom, serverRandom []byte, isServer bool) (*RecordDecryptor, error) {
	rd := &RecordDecryptor{
		version:     version,
		cipherSuite: cipherSuite,
		seq:         0,
	}

	// Get cipher suite config from registry
	config, ok := GetCipherSuite(cipherSuite)
	if !ok {
		return nil, fmt.Errorf("unsupported cipher suite: 0x%04x", cipherSuite)
	}

	// Generate key material
	keys := keysFromMasterSecret(version, masterSecret, clientRandom, serverRandom, config.MacLen, config.KeyLen, config.IVLen)

	var (
		macKey, encKey, iv []byte
	)

	if isServer {
		macKey = keys.serverMAC
		encKey = keys.serverKey
		iv = keys.serverIV
	} else {
		macKey = keys.clientMAC
		encKey = keys.clientKey
		iv = keys.clientIV
	}

	if config.IsAEAD {
		var err error
		rd.aead, err = config.AEADFactory(encKey)
		if err != nil {
			return nil, err
		}
		rd.ivSize = len(iv)
		rd.iv = iv
		rd.blockCipher = nil
	} else {
		// CBC mode
		block, err := aes.NewCipher(encKey)
		if err != nil {
			return nil, err
		}
		rd.blockCipher = block
		rd.macSize = config.MacLen
		rd.ivSize = config.IVLen

		// Create MAC
		rd.macHash = hmac.New(sha1.New, macKey)
	}

	return rd, nil
}

type keyMaterial struct {
	clientMAC []byte
	serverMAC []byte
	clientKey []byte
	serverKey []byte
	clientIV  []byte
	serverIV  []byte
}

func keysFromMasterSecret(version uint16, masterSecret, clientRandom, serverRandom []byte, macLen, keyLen, ivLen int) *keyMaterial {
	seed := make([]byte, 0, len(clientRandom)+len(serverRandom))
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)

	n := 2*macLen + 2*keyLen + 2*ivLen
	keyMaterialBytes := prf12(masterSecret, []byte("key expansion"), seed, n)

	km := &keyMaterial{}
	km.clientMAC = keyMaterialBytes[:macLen]
	keyMaterialBytes = keyMaterialBytes[macLen:]
	km.serverMAC = keyMaterialBytes[:macLen]
	keyMaterialBytes = keyMaterialBytes[macLen:]
	km.clientKey = keyMaterialBytes[:keyLen]
	keyMaterialBytes = keyMaterialBytes[keyLen:]
	km.serverKey = keyMaterialBytes[:keyLen]
	keyMaterialBytes = keyMaterialBytes[keyLen:]
	km.clientIV = keyMaterialBytes[:ivLen]
	keyMaterialBytes = keyMaterialBytes[ivLen:]
	km.serverIV = keyMaterialBytes[:ivLen]

	return km
}

// prf12 implements the TLS 1.2 PRF
func prf12(secret, label, seed []byte, n int) []byte {
	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label)
	copy(labelAndSeed[len(label):], seed)

	return pHash(secret, labelAndSeed, n)
}

func pHash(secret, seed []byte, n int) []byte {
	mac := hmac.New(sha256.New, secret)

	result := make([]byte, n)
	a := seed

	for i := 0; i < n; {
		mac.Reset()
		mac.Write(a)
		a = mac.Sum(nil)

		mac.Reset()
		mac.Write(a)
		mac.Write(seed)
		b := mac.Sum(nil)

		copy(result[i:], b)
		i += len(b)
	}

	return result
}

func (rd *RecordDecryptor) Decrypt(record []byte) ([]byte, byte, error) {
	rd.mu.Lock()
	defer rd.mu.Unlock()

	if len(record) < 5 {
		return nil, 0, fmt.Errorf("record too short")
	}

	recordType := record[0]
	version := binary.BigEndian.Uint16(record[1:3])
	payloadLen := binary.BigEndian.Uint16(record[3:5])
	payload := record[5:]

	if len(payload) != int(payloadLen) {
		return nil, 0, fmt.Errorf("payload length mismatch")
	}

	if rd.aead != nil {
		return rd.decryptAEAD(recordType, version, payload)
	}

	plaintext, err := rd.decryptCBC(recordType, version, payload)
	return plaintext, recordType, err
}

func (rd *RecordDecryptor) decryptAEAD(recordType byte, version uint16, payload []byte) ([]byte, byte, error) {
	if len(payload) < rd.aead.NonceSize() {
		return nil, 0, fmt.Errorf("payload too short for nonce")
	}

	// For TLS 1.3, the nonce is derived from sequence number
	// For TLS 1.2 with AEAD, the nonce is explicit in the record
	var nonce []byte
	var ciphertext []byte

	if rd.version == tls.VersionTLS13 {
		// TLS 1.3: nonce = fixed_iv XOR seq_num
		nonce = make([]byte, len(rd.iv))
		copy(nonce, rd.iv)
		seqBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(seqBytes, rd.seq)
		// XOR with implicit IV
		for i, b := range seqBytes {
			nonce[len(nonce)-8+i] ^= b
		}
		ciphertext = payload
	} else {
		// TLS 1.2: explicit nonce at the beginning
		explicitNonceLen := 8 // For GCM
		if rd.cipherSuite == tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ||
			rd.cipherSuite == tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 {
			explicitNonceLen = 0 // ChaCha20-Poly1305 uses implicit nonce
		}

		if explicitNonceLen > 0 {
			nonce = make([]byte, rd.aead.NonceSize())
			// Implicit IV (first 4 bytes from key material) + explicit nonce (8 bytes from record)
			copy(nonce, rd.iv)
			copy(nonce[len(rd.iv):], payload[:explicitNonceLen])
			ciphertext = payload[explicitNonceLen:]
		} else {
			// ChaCha20-Poly1305: nonce is sequence number XORed with IV
			nonce = make([]byte, 12)
			copy(nonce, rd.iv)
			seqBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(seqBytes, rd.seq)
			for i, b := range seqBytes {
				nonce[4+i] ^= b
			}
			ciphertext = payload
		}
	}

	// Additional data for AEAD
	var additionalData []byte
	if rd.version == tls.VersionTLS13 {
		additionalData = make([]byte, 5)
		additionalData[0] = recordType
		binary.BigEndian.PutUint16(additionalData[1:], version)
		binary.BigEndian.PutUint16(additionalData[3:], uint16(len(ciphertext)))
	} else {
		additionalData = make([]byte, 13)
		binary.BigEndian.PutUint64(additionalData, rd.seq)
		additionalData[8] = recordType
		binary.BigEndian.PutUint16(additionalData[9:], version)
		binary.BigEndian.PutUint16(additionalData[11:], uint16(len(ciphertext)-rd.aead.Overhead()))
	}

	plaintext, err := rd.aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, 0, fmt.Errorf("AEAD decryption failed: %w", err)
	}

	rd.seq++

	// For TLS 1.3, remove content type padding and extract actual type
	actualContentType := recordType
	if rd.version == tls.VersionTLS13 {
		// Find actual content by removing trailing zeros and content type byte
		n := len(plaintext)
		for n > 0 && plaintext[n-1] == 0 {
			n--
		}
		if n == 0 {
			return []byte{}, 0, nil
		}
		actualContentType = plaintext[n-1]
		plaintext = plaintext[:n-1]
	}

	return plaintext, actualContentType, nil
}

func (rd *RecordDecryptor) decryptCBC(recordType byte, version uint16, payload []byte) ([]byte, error) {
	if rd.blockCipher == nil {
		return nil, fmt.Errorf("CBC decryption not configured")
	}

	blockSize := rd.blockCipher.BlockSize()
	if len(payload)%blockSize != 0 {
		return nil, fmt.Errorf("payload not multiple of block size")
	}

	// Extract IV (first block for TLS 1.1+)
	var iv []byte
	var ciphertext []byte

	if version >= tls.VersionTLS11 {
		if len(payload) < blockSize {
			return nil, fmt.Errorf("payload too short for IV")
		}
		iv = payload[:blockSize]
		ciphertext = payload[blockSize:]
	} else {
		// TLS 1.0: IV is part of cipher state (not implemented here)
		return nil, fmt.Errorf("TLS 1.0 CBC not fully supported")
	}

	// Decrypt
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(rd.blockCipher, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove padding
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("empty plaintext")
	}

	paddingLen := int(plaintext[len(plaintext)-1])
	if paddingLen+1 > len(plaintext) {
		return nil, fmt.Errorf("invalid padding length")
	}

	plaintext = plaintext[:len(plaintext)-paddingLen-1]

	// Verify and remove MAC
	if len(plaintext) < rd.macSize {
		return nil, fmt.Errorf("plaintext too short for MAC")
	}

	content := plaintext[:len(plaintext)-rd.macSize]
	mac := plaintext[len(plaintext)-rd.macSize:]

	// Compute expected MAC
	rd.macHash.Reset()
	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, rd.seq)
	rd.macHash.Write(seqBytes)
	rd.macHash.Write([]byte{recordType})
	versionBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(versionBytes, version)
	rd.macHash.Write(versionBytes)
	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, uint16(len(content)))
	rd.macHash.Write(lengthBytes)
	rd.macHash.Write(content)
	expectedMAC := rd.macHash.Sum(nil)

	if !hmac.Equal(mac, expectedMAC) {
		return nil, fmt.Errorf("MAC verification failed")
	}

	rd.seq++

	return content, nil
}
