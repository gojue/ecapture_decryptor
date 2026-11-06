// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package crypto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestDTLSRecordAuthenticationBounds(t *testing.T) {
	for _, suite := range []uint16{0xc02f, 0xc030} {
		master, client, server := bytes.Repeat([]byte{1}, 48), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
		decryptor, err := NewDTLSRecordDecryptor(suite, master, client, server, false)
		if err != nil {
			t.Fatal(err)
		}
		// Exercise explicit record-number AAD; transport tests use an independent
		// standard-library PRF producer and the real fixtures use OpenSSL.
		header := []byte{23, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 7, 0, 24}
		nonce := append(bytes.Clone(decryptor.iv), header[3:11]...)
		aad := append(bytes.Clone(header[3:11]), header[:3]...)
		aad = append(aad, 0, 0)
		wire := append(bytes.Clone(header), header[3:11]...)
		wire = append(wire, decryptor.aead.Seal(nil, nonce, nil, aad)...)
		for i := 0; i < 2; i++ {
			plain, err := decryptor.Decrypt(wire)
			if err != nil || len(plain) != 0 {
				t.Fatal("stateless empty record", err)
			}
		}
		for _, index := range []int{0, 2, 4, 10, 13, len(wire) - 1} {
			bad := bytes.Clone(wire)
			bad[index] ^= 1
			if _, err := decryptor.Decrypt(bad); err == nil {
				t.Fatalf("unauthenticated header/ciphertext byte %d accepted", index)
			}
		}
		for _, short := range [][]byte{nil, wire[:12], wire[:20], append(bytes.Clone(wire), 0)} {
			if _, err := decryptor.Decrypt(short); err == nil {
				t.Fatal("bad frame accepted")
			}
		}
		over := make([]byte, 13+8+16385+16)
		copy(over, wire[:13])
		binary.BigEndian.PutUint16(over[11:], uint16(len(over)-13))
		if _, err := decryptor.Decrypt(over); err == nil {
			t.Fatal("overlong plaintext accepted")
		}
	}
	for _, suite := range []uint16{0x1301, 0xc02b, 0, 0x009c} {
		if _, err := NewDTLSRecordDecryptor(suite, make([]byte, 48), make([]byte, 32), make([]byte, 32), false); err == nil {
			t.Fatal("unsupported suite accepted")
		}
	}
	if _, err := NewDTLSRecordDecryptor(0xc02f, make([]byte, 47), make([]byte, 32), make([]byte, 32), false); err == nil {
		t.Fatal("short master accepted")
	}
}
