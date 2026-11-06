// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package transport

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	sdkcrypto "github.com/gojue/ecapture_decryptor/crypto"
	"github.com/gojue/ecapture_decryptor/types"
)

var dtlsTestMaster = bytes.Repeat([]byte{0x33}, 48)
var dtlsTestClientRandom = bytes.Repeat([]byte{0x11}, 32)
var dtlsTestServerRandom = bytes.Repeat([]byte{0x22}, 32)

func dtlsTestRecord(typ byte, epoch uint16, seq uint64, payload []byte) []byte {
	header := []byte{typ, 0xfe, 0xfd, byte(epoch >> 8), byte(epoch), 0, 0, 0, 0, 0, 0, byte(len(payload) >> 8), byte(len(payload))}
	for i := 10; i >= 5; i-- {
		header[i] = byte(seq)
		seq >>= 8
	}
	return append(header, payload...)
}
func dtlsTestFragment(typ byte, seq uint16, body []byte, offset, n int) []byte {
	data := []byte{typ, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body)), byte(seq >> 8), byte(seq), byte(offset >> 16), byte(offset >> 8), byte(offset), byte(n >> 16), byte(n >> 8), byte(n)}
	return append(data, body[offset:offset+n]...)
}
func dtlsTestHello(client bool, suite uint16, cookie []byte) []byte {
	random := dtlsTestServerRandom
	if client {
		random = dtlsTestClientRandom
	}
	body := append([]byte{0xfe, 0xfd}, random...)
	body = append(body, 0)
	if client {
		body = append(body, byte(len(cookie)))
		body = append(body, cookie...)
		body = append(body, 0, 2, byte(suite>>8), byte(suite), 1, 0)
	} else {
		body = append(body, byte(suite>>8), byte(suite), 0)
	}
	return append(body, 0, 0)
}

// Independent TLS 1.2 P_hash producer: it does not use the SDK's PRF or key
// derivation, and encrypts the DTLS AAD with the standard library AEAD.
func dtlsTestSeal(t *testing.T, suite uint16, server bool, typ byte, seq uint64, plain []byte) []byte {
	t.Helper()
	var hf func() hash.Hash = sha256.New
	keyLen := 16
	if suite == 0xc030 {
		hf = sha512.New384
		keyLen = 32
	}
	seed := append([]byte("key expansion"), dtlsTestServerRandom...)
	seed = append(seed, dtlsTestClientRandom...)
	mac := func(data []byte) []byte { h := hmac.New(hf, dtlsTestMaster); h.Write(data); return h.Sum(nil) }
	a := seed
	var material []byte
	for len(material) < 2*keyLen+8 {
		a = mac(a)
		material = append(material, mac(append(bytes.Clone(a), seed...))...)
	}
	offset := 0
	if server {
		offset = keyLen
	}
	key := material[offset : offset+keyLen]
	ivOffset := 2 * keyLen
	if server {
		ivOffset += 4
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	header := dtlsTestRecord(typ, 1, seq, nil)
	nonce := append(bytes.Clone(material[ivOffset:ivOffset+4]), header[3:11]...)
	aad := append(bytes.Clone(header[3:11]), header[:3]...)
	aad = append(aad, byte(len(plain)>>8), byte(len(plain)))
	payload := append(bytes.Clone(header[3:11]), aead.Seal(nil, nonce, plain, aad)...)
	return dtlsTestRecord(typ, 1, seq, payload)
}
func newDTLSTest(t *testing.T, keys bool) (*DTLSDecryptor, chan *types.DecryptedPacket) {
	t.Helper()
	store := sdkcrypto.NewKeyLogStore()
	if keys {
		store.AddSecret("CLIENT_RANDOM", hex.EncodeToString(dtlsTestClientRandom), dtlsTestMaster)
	}
	out := make(chan *types.DecryptedPacket, 32)
	d := NewDTLSDecryptor(types.ConnectionKey{Proto: "udp", SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2), SrcPort: 12345, DstPort: 44463}, store, out)
	d.SetOptions(types.DecryptOptions{UDPProtocol: "dtls", KeyWaitTimeout: time.Second})
	return d, out
}
func dtlsTestFeedHello(t *testing.T, d *DTLSDecryptor, suite uint16, reverse bool) {
	t.Helper()
	client, server := 0, 1
	if reverse {
		client, server = server, client
	}
	ch, sh := dtlsTestHello(true, suite, nil), dtlsTestHello(false, suite, nil)
	// ServerHello can arrive first; fragments arrive out of order and overlap.
	if err := d.feed(dtlsTestRecord(22, 0, 4, dtlsTestFragment(2, 1, sh, 15, len(sh)-15)), server); err != nil {
		t.Fatal(err)
	}
	if err := d.feed(dtlsTestRecord(22, 0, 3, dtlsTestFragment(2, 1, sh, 0, 20)), server); err != nil {
		t.Fatal(err)
	}
	for _, part := range [][2]int{{0, 3}, {1, 8}, {9, len(ch) - 9}} {
		if err := d.feed(dtlsTestRecord(22, 0, 0, dtlsTestFragment(1, 0, ch, part[0], part[1])), client); err != nil {
			t.Fatal(err)
		}
	}
	// Cookie retry has a new handshake message number, not a new association.
	cookie := dtlsTestHello(true, suite, []byte{1, 2, 3})
	if err := d.feed(dtlsTestRecord(22, 0, 1, dtlsTestFragment(1, 1, cookie, 0, len(cookie))), client); err != nil {
		t.Fatal(err)
	}
}
func TestDTLSLateKeysReorderAndAuthenticatedReplay(t *testing.T) {
	for _, suite := range []uint16{0xc02f, 0xc030} {
		t.Run(hex.EncodeToString([]byte{byte(suite >> 8), byte(suite)}), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d, out := newDTLSTest(t, false)
				dtlsTestFeedHello(t, d, suite, true)
				valid := dtlsTestSeal(t, suite, false, 23, 2, []byte("same"))
				bad := bytes.Clone(valid)
				bad[len(bad)-1] ^= 1
				// A forged record for seq 2 must not block the authentic seq 2 following it.
				records := bytes.Join([][]byte{bad, valid, valid, dtlsTestSeal(t, suite, false, 23, 0, []byte("same")), dtlsTestSeal(t, suite, false, 23, 1, nil)}, nil)
				if err := d.FeedServer(records); err != nil {
					t.Fatal(err)
				}
				if err := d.FeedClient(dtlsTestSeal(t, suite, true, 23, 0, []byte("response"))); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- d.Decrypt() }()
				synctest.Wait()
				if len(out) != 0 {
					t.Fatal("output without keys")
				}
				d.keys.AddSecret("CLIENT_RANDOM", hex.EncodeToString(dtlsTestClientRandom), dtlsTestMaster)
				synctest.Wait()
				if len(out) != 4 {
					t.Fatalf("before EOF: %d", len(out))
				}
				for i, seq := range []uint64{2, 0, 1, 0} {
					p := <-out
					if p.Protocol != "dtls" || p.Metadata["kind"] != "datagram" || p.Metadata["epoch"] != uint16(1) || p.Metadata["sequence"] != seq {
						t.Fatal(p.Metadata)
					}
					if _, ok := p.Metadata["offset"]; ok {
						t.Fatal("stream offset on DTLS")
					}
					direction := "request"
					if i == 3 {
						direction = "response"
					}
					if p.Direction != direction {
						t.Fatal(p.Direction)
					}
					wantSrc, wantDst := d.conn.DstIP.String(), d.conn.SrcIP.String()
					wantSrcPort, wantDstPort := uint32(d.conn.DstPort), uint32(d.conn.SrcPort)
					if i == 3 {
						wantSrc, wantDst = wantDst, wantSrc
						wantSrcPort, wantDstPort = wantDstPort, wantSrcPort
					}
					if p.SrcIP != wantSrc || p.DstIP != wantDst || p.SrcPort != wantSrcPort || p.DstPort != wantDstPort || p.ConnectionID() != d.conn.String() {
						t.Fatal("server-first endpoints or connection identity changed", p)
					}
				}
				_ = d.Close()
				_ = d.Close()
				synctest.Wait()
				if err := <-done; err == nil {
					t.Fatal("bad authentication lost terminal error")
				}
				if d.fragments != nil || d.deferred != nil || d.queue != nil {
					t.Fatal("DTLS retained input after exit")
				}
			})
		})
	}
}
func TestDTLSReplayWindowBoundary(t *testing.T) {
	d, out := newDTLSTest(t, true)
	dtlsTestFeedHello(t, d, 0xc02f, false)
	for _, seq := range []uint64{200, 73, 72, 74, 200, 201} {
		if err := d.FeedClient(dtlsTestSeal(t, 0xc02f, false, 23, seq, []byte{1})); err != nil {
			t.Fatal(err)
		}
	}
	_ = d.Close()
	if err := d.Decrypt(); err != nil {
		t.Fatal(err)
	}
	if len(out) != 4 {
		t.Fatalf("output records=%d", len(out))
	}
	for _, want := range []uint64{200, 73, 74, 201} {
		if (<-out).Metadata["sequence"] != want {
			t.Fatal("replay window changed arrival order")
		}
	}
}
func TestDTLSRecordAndFragmentFailures(t *testing.T) {
	hello := dtlsTestHello(true, 0xc02f, nil)
	for name, wire := range map[string][]byte{
		"short": {23, 0xfe}, "truncated_record": dtlsTestRecord(22, 0, 0, []byte{1}),
		"unsupported_epoch": dtlsTestRecord(23, 2, 0, nil), "plain_application": dtlsTestRecord(23, 0, 0, []byte{1}),
		"unknown_suite":   dtlsTestRecord(22, 0, 0, dtlsTestFragment(2, 0, dtlsTestHello(false, 0x1301, nil), 0, len(dtlsTestHello(false, 0x1301, nil)))),
		"fragment_offset": dtlsTestRecord(22, 0, 0, []byte{1, 0, 0, 1, 0, 0, 0, 0, 2, 0, 0, 1, 1}),
		"fragment_limit":  dtlsTestRecord(22, 0, 0, []byte{1, 4, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1}),
	} {
		t.Run(name, func(t *testing.T) {
			d, _ := newDTLSTest(t, true)
			if err := d.FeedClient(wire); err != nil {
				t.Fatal(err)
			}
			_ = d.Close()
			if err := d.Decrypt(); err == nil {
				t.Fatal("invalid DTLS accepted")
			}
		})
	}
	t.Run("overlap", func(t *testing.T) {
		d, _ := newDTLSTest(t, true)
		first := dtlsTestFragment(1, 0, hello, 0, 10)
		second := bytes.Clone(first)
		second[15] ^= 1
		if err := d.handshake(first, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := d.handshake(second, 0, 0); !errors.Is(err, errDTLS) {
			t.Fatal("conflicting overlap accepted")
		}
	})
	t.Run("total_fragments", func(t *testing.T) {
		d, _ := newDTLSTest(t, true)
		body := make([]byte, dtlsMessageLimit)
		for i := 0; i < 4; i++ {
			if err := d.handshake(dtlsTestFragment(11, uint16(i), body, 0, 1), 0, 0); err != nil {
				t.Fatal(err)
			}
		}
		if err := d.handshake(dtlsTestFragment(11, 5, body, 0, 1), 0, 0); !errors.Is(err, errDTLSLimit) {
			t.Fatal(err)
		}
	})
	t.Run("message_count", func(t *testing.T) {
		d, _ := newDTLSTest(t, true)
		for i := 0; i < 64; i++ {
			if err := d.handshake(dtlsTestFragment(14, uint16(i), nil, 0, 0), 0, 0); err != nil {
				t.Fatal(err)
			}
		}
		if err := d.handshake(dtlsTestFragment(14, 65, nil, 0, 0), 0, 0); !errors.Is(err, errDTLSLimit) {
			t.Fatal(err)
		}
	})
}
func TestDTLSWaitCloseAndLimits(t *testing.T) {
	t.Run("deadline", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			d, _ := newDTLSTest(t, false)
			var codes []string
			d.options.OnDiagnostic = func(x types.Diagnostic) { codes = append(codes, x.Code) }
			done := make(chan error, 1)
			go func() { done <- d.Decrypt() }()
			time.Sleep(time.Second)
			synctest.Wait()
			if err := <-done; err == nil || len(codes) != 1 || codes[0] != "key_wait_timeout" {
				t.Fatal("deadline not enforced", err, codes)
			}
		})
	})
	t.Run("close_without_input", func(t *testing.T) {
		d, _ := newDTLSTest(t, false)
		_ = d.Close()
		_ = d.Close()
		if err := d.Decrypt(); err == nil {
			t.Fatal("missing handshake silently succeeded")
		}
	})
	t.Run("queue_count", func(t *testing.T) {
		d, _ := newDTLSTest(t, false)
		for i := 0; i < dtlsRecordLimit; i++ {
			if err := d.FeedClient([]byte{1}); err != nil {
				t.Fatal(err)
			}
		}
		if err := d.FeedClient([]byte{1}); !errors.Is(err, errDTLSLimit) {
			t.Fatal(err)
		}
	})
	t.Run("deferred_count", func(t *testing.T) {
		d, _ := newDTLSTest(t, false)
		record := dtlsTestRecord(23, 1, 0, nil)
		for i := 0; i < dtlsRecordLimit; i++ {
			if err := d.datagram(dtlsDatagram{data: record}); err != nil {
				t.Fatal(err)
			}
		}
		if err := d.datagram(dtlsDatagram{data: record}); !errors.Is(err, errDTLSLimit) {
			t.Fatal(err)
		}
	})
	t.Run("incomplete_at_eof", func(t *testing.T) {
		d, _ := newDTLSTest(t, true)
		dtlsTestFeedHello(t, d, 0xc02f, false)
		fragment := dtlsTestFragment(11, 3, []byte{1, 2}, 0, 1)
		if err := d.FeedServer(dtlsTestRecord(22, 0, 10, fragment)); err != nil {
			t.Fatal(err)
		}
		_ = d.Close()
		if err := d.Decrypt(); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatal(err)
		}
	})
}
func TestDTLSBackpressureCloseDrains(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d, _ := newDTLSTest(t, true)
		d.out = make(chan *types.DecryptedPacket)
		dtlsTestFeedHello(t, d, 0xc02f, false)
		if err := d.FeedClient(dtlsTestSeal(t, 0xc02f, false, 23, 0, []byte("blocked"))); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- d.Decrypt() }()
		synctest.Wait()
		_ = d.Close()
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("close dropped blocked output")
		default:
		}
		p := <-d.out
		if !bytes.Equal(p.Data, []byte("blocked")) {
			t.Fatal("output altered")
		}
		synctest.Wait()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}
func FuzzDTLSRecordAndHandshake(f *testing.F) {
	f.Add(dtlsTestRecord(22, 0, 0, []byte{1}))
	f.Add(dtlsTestRecord(23, 1, 3, nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65535 {
			return
		}
		d, _ := newDTLSTest(t, false)
		_ = d.datagram(dtlsDatagram{data: data})
		_ = d.handshake(data, 0, 0)
	})
}

func TestDTLSByteLimitsAndMissingAssociation(t *testing.T) {
	t.Run("queue_bytes", func(t *testing.T) {
		d, _ := newDTLSTest(t, false)
		chunk := make([]byte, 65535)
		for d.queued+len(chunk) <= dtlsQueueLimit {
			if err := d.FeedClient(chunk); err != nil {
				t.Fatal(err)
			}
		}
		if err := d.FeedClient(chunk); !errors.Is(err, errDTLSLimit) {
			t.Fatal(err)
		}
	})
	t.Run("deferred_bytes", func(t *testing.T) {
		d, _ := newDTLSTest(t, false)
		record := dtlsTestRecord(23, 1, 0, make([]byte, 18000))
		for d.deferredBytes+len(record) <= dtlsQueueLimit {
			if err := d.datagram(dtlsDatagram{data: record}); err != nil {
				t.Fatal(err)
			}
		}
		if err := d.datagram(dtlsDatagram{data: record}); !errors.Is(err, errDTLSLimit) {
			t.Fatal(err)
		}
	})
	t.Run("no_random_scan", func(t *testing.T) {
		d, out := newDTLSTest(t, true)
		if err := d.FeedClient(dtlsTestSeal(t, 0xc02f, false, 23, 0, []byte("secret"))); err != nil {
			t.Fatal(err)
		}
		_ = d.Close()
		if err := d.Decrypt(); err == nil || len(out) != 0 {
			t.Fatal("decrypted without observed ClientHello")
		}
	})
	t.Run("suite_not_offered", func(t *testing.T) {
		d, _ := newDTLSTest(t, true)
		ch := dtlsTestHello(true, 0xc02f, nil)
		sh := dtlsTestHello(false, 0xc030, nil)
		for i, x := range [][]byte{dtlsTestFragment(1, 0, ch, 0, len(ch)), dtlsTestFragment(2, 0, sh, 0, len(sh))} {
			if err := d.feed(dtlsTestRecord(22, 0, 0, x), i); err != nil {
				t.Fatal(err)
			}
		}
		_ = d.Close()
		if err := d.Decrypt(); !errors.Is(err, errDTLS) {
			t.Fatal("unoffered suite accepted", err)
		}
	})
}

func TestDTLSCompletedHelloRetransmissionBinding(t *testing.T) {
	for _, client := range []bool{true, false} {
		typ, side := byte(2), 1
		if client {
			typ, side = 1, 0
		}
		body := dtlsTestHello(client, 0xc02f, nil)
		for _, fragmented := range []bool{false, true} {
			d, _ := newDTLSTest(t, true)
			original := dtlsTestFragment(typ, 0, body, 0, len(body))
			if err := d.handshake(original, side, 0); err != nil {
				t.Fatal(err)
			}
			retained := d.fragmentBytes
			// Identical retransmission may use different fragment boundaries/order.
			for _, part := range [][2]int{{8, len(body) - 8}, {0, 12}} {
				if err := d.handshake(dtlsTestFragment(typ, 0, body, part[0], part[1]), side, 0); err != nil {
					t.Fatal("valid retransmission rejected", err)
				}
			}
			if d.fragmentBytes != retained {
				t.Fatal("retransmission grew retained storage")
			}
			changed := bytes.Clone(body)
			changed[2] ^= 1
			offset, n := 0, len(changed)
			if fragmented {
				offset, n = 1, 3
			}
			if err := d.handshake(dtlsTestFragment(typ, 0, changed, offset, n), side, 0); !errors.Is(err, errDTLSUnsupported) {
				t.Fatal("changed random reused completed Hello", err)
			}
		}
	}
	// Changing a ServerHello suite is also caught, even in a fragment that
	// contains no random bytes.
	d, _ := newDTLSTest(t, true)
	sh := dtlsTestHello(false, 0xc02f, nil)
	if err := d.handshake(dtlsTestFragment(2, 0, sh, 0, len(sh)), 1, 0); err != nil {
		t.Fatal(err)
	}
	changed := dtlsTestHello(false, 0xc030, nil)
	if err := d.handshake(dtlsTestFragment(2, 0, changed, 35, 2), 1, 0); !errors.Is(err, errDTLSUnsupported) {
		t.Fatal("changed suite reused completed Hello", err)
	}
}

func TestDTLSRetainedHellosShareResourceBudget(t *testing.T) {
	d, _ := newDTLSTest(t, true)
	ch := dtlsTestHello(true, 0xc02f, nil)
	ch = ch[:len(ch)-2]
	// A legal opaque extension makes the complete Hello large enough to
	// exercise the byte cap before the independent 64-message identity cap.
	const payload = 60000
	const extlen = payload + 4
	ch = append(ch, byte(extlen>>8), byte(extlen&255), 0xfa, 0xce, byte(payload>>8), byte(payload&255))
	ch = append(ch, make([]byte, payload)...)
	for seq := uint16(0); seq < 64; seq++ {
		err := d.handshake(dtlsTestFragment(1, seq, ch, 0, len(ch)), 0, 0)
		if errors.Is(err, errDTLSLimit) {
			if seq == 0 || d.fragmentBytes > dtlsHandshakeLimit {
				t.Fatal("invalid retention accounting")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("completed Hellos bypassed retained-byte limit")
}

func TestDTLSConflictingHelloCannotReleaseOldKeyData(t *testing.T) {
	d, out := newDTLSTest(t, true)
	ch, sh := dtlsTestHello(true, 0xc02f, nil), dtlsTestHello(false, 0xc02f, nil)
	if err := d.handshake(dtlsTestFragment(1, 0, ch, 0, len(ch)), 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := d.handshake(dtlsTestFragment(2, 0, sh, 0, len(sh)), 1, 0); err != nil {
		t.Fatal(err)
	}
	if err := d.retry(); err != nil {
		t.Fatal(err)
	}
	changed := bytes.Clone(ch)
	changed[2] ^= 1
	wire := dtlsTestRecord(22, 0, 2, dtlsTestFragment(1, 0, changed, 0, len(changed)))
	wire = append(wire, dtlsTestSeal(t, 0xc02f, false, 23, 0, []byte("old association"))...)
	if err := d.datagram(dtlsDatagram{data: wire}); !errors.Is(err, errDTLSUnsupported) || len(out) != 0 {
		t.Fatal("conflicting Hello continued under previous keys", err)
	}
}
