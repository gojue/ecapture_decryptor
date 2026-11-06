// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package crypto

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

// DTLSRecordDecryptor authenticates DTLS 1.2 AES-GCM records using their explicit
// epoch/sequence, without imposing TLS's reliable ordered-record semantics.
// Replay state belongs to the connection and is updated only after success.
type DTLSRecordDecryptor struct {
	aead cipher.AEAD
	iv   []byte
}

func NewDTLSRecordDecryptor(suite uint16, master, clientRandom, serverRandom []byte, server bool) (*DTLSRecordDecryptor, error) {
	if suite != 0xc02f && suite != 0xc030 {
		return nil, errors.New("unsupported DTLS cipher suite")
	}
	if len(master) != 48 || len(clientRandom) != 32 || len(serverRandom) != 32 {
		return nil, errors.New("invalid DTLS key material")
	}
	config, _ := GetCipherSuite(suite)
	keys := keysFromMasterSecret(config.HashFunc, master, clientRandom, serverRandom, config.MacLen, config.KeyLen, config.IVLen)
	key, iv := keys.clientKey, keys.clientIV
	if server {
		key, iv = keys.serverKey, keys.serverIV
	}
	aead, err := config.AEADFactory(key)
	if err != nil {
		return nil, err
	}
	return &DTLSRecordDecryptor{aead: aead, iv: iv}, nil
}
func (d *DTLSRecordDecryptor) Decrypt(record []byte) ([]byte, error) {
	if len(record) < 13 || binary.BigEndian.Uint16(record[1:]) != 0xfefd || binary.BigEndian.Uint16(record[3:]) != 1 || int(binary.BigEndian.Uint16(record[11:])) != len(record)-13 || len(record) > 13+8+16384+16 {
		return nil, errors.New("invalid DTLS record")
	}
	payload := record[13:]
	if len(payload) < 8+d.aead.Overhead() {
		return nil, errors.New("invalid DTLS record")
	}
	nonce := append(append([]byte(nil), d.iv...), payload[:8]...)
	aad := append([]byte(nil), record[3:11]...)
	aad = append(aad, record[:3]...)
	size := len(payload) - 8 - d.aead.Overhead()
	aad = append(aad, byte(size>>8), byte(size))
	plain, err := d.aead.Open(nil, nonce, payload[8:], aad)
	if err != nil {
		return nil, errors.New("DTLS authentication failed")
	}
	return plain, nil
}
