// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

package crypto

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"testing"
)

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
