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
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestTLS13KeyUpdateIndependentVectors(t *testing.T) {
	// Independently generated with Python hashlib/hmac implementing RFC 8446
	// HKDF-Expand-Label, not the production derivation or RecordDecryptor.
	sha256Secrets := []string{
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"2cecd0a17506ef5fa73edc062d6e7b5397cf074ec1b4d8f99a120772932f0b45",
		"2d3fb1fe267c2e0126351cc169afb7ca25c0d8867167c55c5533e3715558a6b9",
	}
	sha256IVs := []string{"2f41c846a431a163814bcd71", "4ef68fed17d39b5f23bb4b30", "2739edacb4dc79885391a769"}
	for _, tc := range []struct {
		suite              uint16
		secrets, keys, ivs []string
	}{
		{tls.TLS_AES_128_GCM_SHA256, sha256Secrets, []string{"9c9783cf77ea32d44f369da41f19f3cc", "05cdc7251fb9f925889f80ebc1fd385f", "f795fc0182a370f8af96a1d6dfba76ac"}, sha256IVs},
		{tls.TLS_CHACHA20_POLY1305_SHA256, sha256Secrets, []string{"2ffbc449e87844051c7768f61ffd8ad070830f01ec2c520ef65f08e8296dffa0", "c690ede9a7525f64b759094f3bda2da3b5b52e50cffacd89a37bdf85affdd091", "a0bbbcfeba507420e29aff13ebeaeb194782449236bef1c04640793d86732721"}, sha256IVs},
		{tls.TLS_AES_256_GCM_SHA384, []string{
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
			"401331b63e9d59f202e8f041042d9516f4cd7fa2e2ee14631d3b49fc340d7af37fc2c0c9f252d8036f81ec5b85cbe5db",
			"1fed39ab8257f49d1c0c45bfbf71ffa8525b22ea44fdbbe0f7dfff32ea98fa53864320d595ea4ab13a8292965996db9b",
		}, []string{"6877d022f1c61d24ebb7487c16752d9a4798e40431c75b39320e537c90e23225", "eb354f3b48924ed78de34dd8aa6a6a0a51d857ddad1454d5cfa7b69f60712911", "2d9c985947a6214bd2d1eef320171612b39ade8f7b8f0df6c09023ab183d172e"}, []string{"42822531a0fe88648fc09e9f", "8478ffbe4f2e5450789775b3", "fd5be82f2a1fe585114075cc"}},
	} {
		t.Run(tls.CipherSuiteName(tc.suite), func(t *testing.T) {
			secret := decodeTLSFixture(t, tc.secrets[0])
			rd, err := NewRecordDecryptor(tls.VersionTLS13, tc.suite, secret)
			if err != nil {
				t.Fatal(err)
			}
			secret[0] ^= 1 // Constructor must own retained key material.
			seal := func(generation int, seq uint64) []byte {
				t.Helper()
				key := decodeTLSFixture(t, tc.keys[generation])
				var aead cipher.AEAD
				var err error
				if tc.suite == tls.TLS_CHACHA20_POLY1305_SHA256 {
					aead, err = chacha20poly1305.New(key)
				} else {
					block, e := aes.NewCipher(key)
					if e != nil {
						t.Fatal(e)
					}
					aead, err = cipher.NewGCM(block)
				}
				if err != nil {
					t.Fatal(err)
				}
				nonce := decodeTLSFixture(t, tc.ivs[generation])
				binary.BigEndian.PutUint64(nonce[4:], binary.BigEndian.Uint64(nonce[4:])^seq)
				header := []byte{23, 3, 3, 0, 20}
				return append(header, aead.Seal(nil, nonce, []byte{'k', 'u', byte(generation), 23}, header)...)
			}
			for generation := range tc.secrets {
				if !bytes.Equal(rd.secret, decodeTLSFixture(t, tc.secrets[generation])) || !bytes.Equal(rd.iv, decodeTLSFixture(t, tc.ivs[generation])) || rd.seq != 0 {
					t.Fatal("wrong traffic secret, IV or reset sequence", generation)
				}
				valid := seal(generation, 0)
				bad := bytes.Clone(valid)
				bad[len(bad)-1] ^= 1
				if p, _, err := rd.Decrypt(bad); err == nil || len(p) != 0 || rd.seq != 0 {
					t.Fatal("authentication failure advanced sequence or exposed bytes")
				}
				if generation < 2 {
					if _, _, err := rd.Decrypt(seal(generation+1, 0)); err == nil || rd.seq != 0 {
						t.Fatal("future key was accepted without KeyUpdate")
					}
				}
				if generation > 0 {
					if _, _, err := rd.Decrypt(seal(generation-1, 0)); err == nil || rd.seq != 0 {
						t.Fatal("old key replay accepted after KeyUpdate")
					}
				}
				if p, typ, err := rd.Decrypt(valid); err != nil || typ != 23 || !bytes.Equal(p, []byte{'k', 'u', byte(generation)}) {
					t.Fatalf("independent record: %x %d %v", p, typ, err)
				}
				if _, _, err := rd.Decrypt(seal(generation, 1)); err != nil {
					t.Fatal(err)
				}
				if generation < 2 {
					if err := rd.UpdateTrafficSecret(); err != nil {
						t.Fatal(err)
					}
				}
			}
			rd.seq = ^uint64(0)
			if _, _, err := rd.Decrypt(seal(2, rd.seq)); err != nil {
				t.Fatal(err)
			}
			if _, _, err := rd.Decrypt(seal(2, 0)); err == nil {
				t.Fatal("record sequence wrapped")
			}
			if _, err := NewRecordDecryptor(tls.VersionTLS13, tc.suite, secret[:len(secret)-1]); err == nil {
				t.Fatal("incorrect secret length accepted")
			}
		})
	}
}

func TestTLSRecordCipherVersionBinding(t *testing.T) {
	secret := bytes.Repeat([]byte{1}, 32)
	for _, tc := range []struct{ version, suite uint16 }{
		{tls.VersionTLS12, tls.TLS_AES_128_GCM_SHA256},
		{tls.VersionTLS13, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		{tls.VersionTLS13, 0xffff},
	} {
		if _, err := NewRecordDecryptor(tc.version, tc.suite, secret); err == nil {
			t.Fatalf("invalid TLS 1.3 version/suite pair accepted: %+v", tc)
		}
	}
	if _, err := NewRecordDecryptorTLS12(tls.VersionTLS12, tls.TLS_AES_128_GCM_SHA256, secret, secret, secret, false); err == nil {
		t.Fatal("TLS 1.3-only cipher was accepted by TLS 1.2 constructor")
	}
}

func decodeTLSFixture(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestTLS12PRFKeyExpansionVector(t *testing.T) {
	// NIST key-expansion vector published by OpenSSL, independent of this PRF.
	// https://github.com/openssl/openssl/blob/master/test/recipes/30-test_evp_data/evpkdf_tls12_prf.txt
	secret := decodeTLSFixture(t, "202c88c00f84a17a20027079604787461176455539e705be730890602c289a5001e34eeb3a043e5d52a65e66125188bf")
	seed := decodeTLSFixture(t, "ae6c806f8ad4d80784549dff28a4b58fd837681a51d928c3e30ee5ff14f3986862e1fd91f23f558a605f28478c58cf72637b89784d959df7e946d3f07bd1b616")
	want := decodeTLSFixture(t, "d06139889fffac1e3a71865f504aa5d0d2a2e89506c6f2279b670c3e1b74f531016a2530c51a3a0f7e1d6590d0f0566b2f387f8d11fd4f731cdd572d2eae927f6f2f81410b25e6960be68985add6c38445ad9f8c64bf8068bf9a6679485d966f1ad6f68b43495b10a683755ea2b858d70ccac7ec8b053c6bd41ca299d4e51928")
	got := prf12(sha256.New, secret, []byte("key expansion"), seed, len(want))
	if !bytes.Equal(got, want) {
		t.Fatal("TLS 1.2 SHA256 PRF does not match independent vector")
	}
}

func TestTLS12GCMRecordVectors(t *testing.T) {
	for _, vector := range tls12GCMVectors {
		for _, suite := range vector.suites {
			t.Run(tls.CipherSuiteName(suite), func(t *testing.T) {
				for _, direction := range []struct {
					name    string
					server  bool
					records []string
					bodies  []string
				}{
					{"client", false, vector.clientRecords, []string{"fixture client request one", "fixture client request two\x00\xff"}},
					{"server", true, vector.serverRecords, []string{"fixture server response one", "fixture server response two\x00\xfe"}},
				} {
					t.Run(direction.name, func(t *testing.T) {
						newDecryptor := func(secret []byte, server bool) *RecordDecryptor {
							t.Helper()
							decryptor, err := NewRecordDecryptorTLS12(tls.VersionTLS12, suite, secret,
								decodeTLSFixture(t, vector.clientRandom), decodeTLSFixture(t, vector.serverRandom), server)
							if err != nil {
								t.Fatal(err)
							}
							return decryptor
						}
						secret := decodeTLSFixture(t, vector.masterSecret)
						decryptor := newDecryptor(secret, direction.server)
						finished := decodeTLSFixture(t, direction.records[0])
						plain, contentType, err := decryptor.Decrypt(finished)
						if err != nil || contentType != 0x16 || len(plain) != 16 || !bytes.Equal(plain[:4], []byte{0x14, 0, 0, 12}) {
							t.Fatalf("decrypt independent Finished record: content type=%x, length=%d, error=%v", contentType, len(plain), err)
						}
						for i, body := range direction.bodies {
							record := decodeTLSFixture(t, direction.records[i+1])
							corrupt := bytes.Clone(record)
							corrupt[len(corrupt)-1] ^= 1
							plain, _, err := decryptor.Decrypt(corrupt)
							if err == nil || len(plain) != 0 {
								t.Fatal("tampered record returned plaintext or no error")
							}
							// A failed authentication must not advance the record sequence.
							plain, contentType, err = decryptor.Decrypt(record)
							if err != nil || contentType != 0x17 || !bytes.Equal(plain, []byte(body)) {
								t.Fatalf("decrypt independent application record %d: content type=%x, error=%v", i, contentType, err)
							}
						}
						wrongSecret := bytes.Clone(secret)
						wrongSecret[0] ^= 1
						for _, invalid := range []*RecordDecryptor{
							newDecryptor(wrongSecret, direction.server),
							newDecryptor(secret, !direction.server),
						} {
							plain, _, err := invalid.Decrypt(finished)
							if err == nil || len(plain) != 0 {
								t.Fatal("wrong secret or direction returned plaintext or no error")
							}
						}
					})
				}
			})
		}
	}
}

// Synthetic TLS 1.2 sessions generated on Linux with Python ssl.MemoryBIO and
// OpenSSL 3.5.5 27 Jan 2026. Each direction contains Finished followed by
// two application records. No repository PRF/encryptor generated these bytes.
// ECDHE-RSA generated the sessions; the other listed suites share exactly
// the same record protection and exercise their registry-selected PRF.
var tls12GCMVectors = []struct {
	suites                                   []uint16
	masterSecret, clientRandom, serverRandom string
	clientRecords, serverRecords             []string
}{
	{
		suites: []uint16{
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		masterSecret: "5be40fd7540c419576c05c6ec0a7d4be422c2b46bd01ad1263021483212c90c573151c84495a41912c05da9792e64a9f",
		clientRandom: "024153bcc0cc7a4b7fba93a51aef55ebb1987118d71706df30acf46dc9a441a0",
		serverRandom: "1fef2302f70c157347e4dcb670ebae626d7fdd0470d5b20feb5d12d4bfb161f9",
		clientRecords: []string{
			"1603030028ae5a3f5d8343da5ecadb81d3c5d989535ecc8e2ce64e33f0ffc2161f4250011a1a93fe68bcd4560b",
			"1703030032ae5a3f5d8343da5fc5c9ea22a98787697957c875dbbd33d70185b40d554d14cd6c29c0672d8fff4939d8865d670f733977f1",
			"1703030034ae5a3f5d8343da60c744299e5cb0335e84878111cfe46f9c0f96de6542a4a0c9543bcd4a3c3935061524e59dac03f5cd842b1ebc",
		},
		serverRecords: []string{
			"1603030028bc66ad3d95be1056b5a53b09cdc5a61b5a1e1bbef9b5d11e7d8bcba491693a1cf10eced16ca14341",
			"1703030033bc66ad3d95be10570d612078f89dedb5c81c06c2ebc6c28fbee87315307a92409285c81da67d9b4f6304e7bf94970415c3bca1",
			"1703030035bc66ad3d95be1058f1e3f7e21a38ca6439cbb537a2e5daafba52d73278c4b164a573d8211689074305b0c0f295630e2f2dda24c676",
		},
	},
	{
		suites: []uint16{
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
		masterSecret: "dfc9b4115d99fc4a37111240beddb44a5b8388cf599a324c59286d3ab9f17f6ca7d4bfa804755b735badf30d2d19e619",
		clientRandom: "1b5fbeed8c595369a1d78344ca067a0c71c0de7a15a8510e8b74f200d5217c87",
		serverRandom: "4b7b93d319047d8df24eccbd642a6143e996d1420bde3dee130186accd7784c6",
		clientRecords: []string{
			"1603030028ab52b547c47c6343b7539031a6bda19168c2116f2126bce48286ae7a61184d3e37c8970c608a47ea",
			"1703030032ab52b547c47c6344752ec9bcacd2793701ae58407208f288210a8eb0025fd32d9ae8748d0c2dab7c68d373b65a8684327fa2",
			"1703030034ab52b547c47c6345c082ab25acc3db17f2ab530bfe9540d35c17851e671ca21499c7a31415faad773b1fa80645c868fdd29955a6",
		},
		serverRecords: []string{
			"1603030028e7afe7ea15f57309c10def2e86e973f837206ea92ed5860372c9ef7d4d0cea9b2536171e79dfd7aa",
			"1703030033e7afe7ea15f5730aec228767331a3cf719e4ea6bcbb5e8cb6ac0f21930a2d104b593db51872bca9ed342fe2d11ec203f887c35",
			"1703030035e7afe7ea15f5730bdbd98bb5bf1a3b7b6b1a4bdb871d72c1311a1df56c0f105d049ff47a2fd9830228f0f0201a0ddc6ec697eb945e",
		},
	},
}
