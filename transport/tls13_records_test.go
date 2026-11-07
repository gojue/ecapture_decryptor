// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package transport

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gojue/ecapture_decryptor/crypto"
	"github.com/gojue/ecapture_decryptor/types"
)

func tls13StageHellos(t *testing.T, td *TLSDecryptor, early bool) {
	t.Helper()
	client, server := tlsUpgradeTestHellos(0x44)
	if early {
		client = append(client, 0, 42, 0, 0)
		binary.BigEndian.PutUint16(client[50:52], 11)
		binary.BigEndian.PutUint16(client[3:5], uint16(len(client)-5))
		client[8] += 4
	}
	if err := td.FeedClient(client); err != nil {
		t.Fatal(err)
	}
	if err := td.FeedServer(server); err != nil {
		t.Fatal(err)
	}
}

func tls13StageSecret(td *TLSDecryptor, label string, value []byte) {
	td.keyLog.AddSecret(label, hex.EncodeToString(bytes.Repeat([]byte{0x44}, 32)), value)
}

func tls13Finished() []byte {
	return append([]byte{20, 0, 0, 32}, bytes.Repeat([]byte{0x55}, 32)...)
}

func newTLS13StageTest(t *testing.T) (*TLSDecryptor, chan *types.DecryptedPacket, []byte, []byte) {
	t.Helper()
	td, out := newTLSRawTest(types.DecryptOptions{RawChunks: true})
	app, hs := make([]byte, 32), bytes.Repeat([]byte{0x33}, 32)
	for i := range app {
		app[i] = byte(i)
	}
	tls13StageHellos(t, td, false)
	for _, label := range []string{"CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"} {
		tls13StageSecret(td, label, app)
	}
	for _, label := range []string{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET"} {
		tls13StageSecret(td, label, hs)
	}
	if err := td.parseHandshake(); err != nil {
		t.Fatal(err)
	}
	return td, out, app, hs
}

func TestTLS13FinishedFragmentsAndDirectionalKeyUpdates(t *testing.T) {
	td, out, app, hs := newTLS13StageTest(t)
	// A coalesced EncryptedExtensions and Certificate followed by a split
	// Finished header must switch only when Finished is complete.
	finished := tls13Finished()
	prefix := append([]byte{8, 0, 0, 2, 0, 0, 11, 0, 0, 0}, finished[:2]...)
	_ = td.FeedServer(tls13RawTestRecord(t, hs, 0, prefix, 22))
	if td.tls13[1].phase != tls13Handshake || !td.tls13[1].handshake.Pending() {
		t.Fatal("partial Finished changed the key epoch")
	}
	_ = td.FeedServer(tls13RawTestRecord(t, hs, 1, finished[2:], 22))
	for i, fragment := range [][]byte{finished[:1], finished[1:2], finished[2:3], finished[3:4], finished[4:]} {
		_ = td.FeedClient(tls13RawTestRecord(t, hs, uint64(i), fragment, 22))
	}
	if td.tls13[0].phase != tls13Application || td.tls13[1].phase != tls13Application || len(out) != 0 {
		t.Fatal("complete Finished did not advance both directions without emitting it")
	}
	// Independent RFC 8446 traffic-update values (Python hashlib/hmac).
	next, _ := hex.DecodeString("2cecd0a17506ef5fa73edc062d6e7b5397cf074ec1b4d8f99a120772932f0b45")
	last, _ := hex.DecodeString("2d3fb1fe267c2e0126351cc169afb7ca25c0d8867167c55c5533e3715558a6b9")
	for _, client := range []bool{true, false} {
		feed := td.FeedServer
		i := 1
		if client {
			feed, i = td.FeedClient, 0
		}
		_ = feed(tls13RawTestRecord(t, app, 0, []byte{24, 0}, 22))
		if td.tls13[i].generation != 0 {
			t.Fatal("split KeyUpdate changed keys before its body authenticated")
		}
		_ = feed(tls13RawTestRecord(t, app, 1, []byte{0, 1, 1}, 22))
		_ = feed(tls13RawTestRecord(t, next, 0, []byte("first"), 23))
		_ = feed(tls13RawTestRecord(t, next, 1, []byte{24, 0, 0, 1, 0}, 22))
		_ = feed(tls13RawTestRecord(t, last, 0, []byte("second"), 23))
		if td.tls13[i].generation != 2 || td.aborted.Load() {
			t.Fatal("valid independent KeyUpdate chain failed", td.decryptErr)
		}
		if client && td.tls13[1].generation != 0 {
			t.Fatal("request_update inferred an unobserved peer key change")
		}
	}
	if len(out) != 4 {
		t.Fatalf("got %d app chunks, want 4", len(out))
	}
	for _, want := range []string{"first", "second", "first", "second"} {
		if p := <-out; string(p.Data) != want {
			t.Fatal("handshake bytes leaked or application bytes changed")
		}
	}
}

func TestTLS13RejectsInvalidKeyUpdateEpochAndFraming(t *testing.T) {
	for _, mode := range []string{"before_finished", "tampered", "invalid_request", "trailing_handshake", "interleaved_application", "future_key", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			td, out, app, hs := newTLS13StageTest(t)
			if mode != "before_finished" {
				_ = td.FeedClient(tls13RawTestRecord(t, hs, 0, tls13Finished(), 22))
			}
			update := []byte{24, 0, 0, 1, 0}
			secret := app
			switch mode {
			case "before_finished":
				secret = hs
			case "invalid_request":
				update[4] = 2
			case "trailing_handshake":
				update = append(update, 4, 0, 0, 0)
			case "interleaved_application", "truncated":
				update = update[:2]
			case "future_key":
				secret, _ = hex.DecodeString("2cecd0a17506ef5fa73edc062d6e7b5397cf074ec1b4d8f99a120772932f0b45")
			}
			record := tls13RawTestRecord(t, secret, 0, update, 22)
			if mode == "tampered" {
				record[len(record)-1] ^= 1
			}
			_ = td.FeedClient(record)
			if mode == "interleaved_application" {
				_ = td.FeedClient(tls13RawTestRecord(t, app, 1, []byte("must-not-emit"), 23))
			}
			td.finishTLS13()
			if td.decryptErr == nil || len(out) != 0 || td.tls13[0].generation != 0 {
				t.Fatalf("invalid KeyUpdate accepted: err=%v output=%d generation=%d", td.decryptErr, len(out), td.tls13[0].generation)
			}
			if mode == "truncated" && !errors.Is(td.decryptErr, io.ErrUnexpectedEOF) {
				t.Fatal("partial authenticated handshake was not reported at EOF")
			}
		})
	}
}

func TestTLS13LateEarlyAndHandshakeKeysWakeAfterFIN(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		td, out := newTLSRawTest(types.DecryptOptions{RawChunks: true, KeyWaitTimeout: time.Second})
		app, hs, early := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32), bytes.Repeat([]byte{0x33}, 32)
		tls13StageHellos(t, td, true)
		for _, label := range []string{"CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"} {
			tls13StageSecret(td, label, app)
		}
		_ = td.FeedClient(tls13RawTestRecord(t, early, 0, []byte("early"), 23))
		_ = td.FeedClient(tls13RawTestRecord(t, early, 1, []byte{5, 0, 0, 0}, 22))
		_ = td.FeedClient(tls13RawTestRecord(t, hs, 0, tls13Finished(), 22))
		_ = td.FeedClient(tls13RawTestRecord(t, app, 0, []byte("normal"), 23))
		ee := append([]byte{8, 0, 0, 6, 0, 4, 0, 42, 0, 0}, tls13Finished()...)
		_ = td.FeedServer(tls13RawTestRecord(t, hs, 0, ee, 22))
		_ = td.FeedServer(tls13RawTestRecord(t, app, 0, []byte("response"), 23))
		_ = td.CloseClient()
		_ = td.CloseServer()
		done := make(chan error, 1)
		go func() { done <- td.Decrypt() }()
		synctest.Wait()
		if len(out) != 0 {
			t.Fatal("missing keys emitted bytes")
		}
		tls13StageSecret(td, "CLIENT_EARLY_TRAFFIC_SECRET", early)
		tls13StageSecret(td, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", hs)
		synctest.Wait()
		if len(out) != 0 {
			t.Fatal("authenticated early data escaped acceptance wait")
		}
		tls13StageSecret(td, "SERVER_HANDSHAKE_TRAFFIC_SECRET", hs)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		var request []byte
		foundEarly := false
		for len(out) > 0 {
			p := <-out
			if p.Direction == "request" {
				if p.Metadata["offset"] != uint64(len(request)) {
					t.Fatal("accepted early and normal data lost contiguous offsets", p.Metadata)
				}
				request = append(request, p.Data...)
			}
			if p.Metadata["encryption_level"] == "0rtt" {
				foundEarly = p.Metadata["early_data"] == "accepted" && string(p.Data) == "early"
			}
		}
		if string(request) != "earlynormal" || !foundEarly || td.earlyBytes != 0 || len(td.earlyPending) != 0 {
			t.Fatal("late secrets lost early data or retained buffers")
		}
		assertTLSBuffersReleased(t, td)
	})
}

func tls13RetryFlight(t *testing.T, td *TLSDecryptor, earlyRecord []byte, change string) {
	t.Helper()
	first, final := tlsUpgradeTestHellos(0x44)
	second := bytes.Clone(first)
	first = append(first, 0, 42, 0, 0)
	binary.BigEndian.PutUint16(first[50:52], 11)
	binary.BigEndian.PutUint16(first[3:5], uint16(len(first)-5))
	first[8] += 4
	if change == "ech_early" || change == "ech_no_retry" {
		// Copy a GREASE-shaped ECH offer across HRR. Callers provide or omit
		// the actual Outer record keys to exercise the candidate boundary.
		ech := append([]byte{0xfe, 0x0d, 0, 58, 0, 0, 1, 0, 1, 7, 0, 32}, make([]byte, 32)...)
		ech = append(ech, 0, 16)
		ech = append(ech, make([]byte, 16)...)
		for _, target := range []*[]byte{&first, &second} {
			*target = append(*target, ech...)
			binary.BigEndian.PutUint16((*target)[50:52], uint16(len(*target)-52))
			binary.BigEndian.PutUint16((*target)[3:5], uint16(len(*target)-5))
			(*target)[8] = byte(len(*target) - 9)
		}
	}
	if change == "early_suites" {
		for _, target := range []*[]byte{&first, &second} {
			*target = append(append(bytes.Clone((*target)[:48]), 0x13, 2, 0x13, 3), (*target)[48:]...)
			binary.BigEndian.PutUint16((*target)[44:46], 6)
			binary.BigEndian.PutUint16((*target)[3:5], uint16(len(*target)-5))
			(*target)[8] += 4
		}
	}
	retry := bytes.Clone(final)
	random, _ := hex.DecodeString("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
	copy(retry[11:43], random)
	switch change {
	case "second_early":
		second = bytes.Clone(first)
	case "random":
		second[11] ^= 1
	case "repeat_hrr":
		final = bytes.Clone(retry)
	case "suite":
		final[45] = 2
	}
	_ = td.FeedClient(first)
	_ = td.FeedClient(earlyRecord)
	if change == "ech_no_retry" {
		_ = td.FeedServer(final)
		return
	}
	if change == "before_second" {
		_ = td.FeedServer(retry)
		return
	}
	_ = td.FeedClient([]byte{20, 3, 3, 0, 1, 1})
	// A split CH2 header must end early-data consumption at the first fragment.
	_ = td.FeedClient([]byte{22, 3, 3, 0, 2, second[5], second[6]})
	if change == "interleaved_early" {
		_ = td.FeedClient(earlyRecord)
	}
	tail := append([]byte{22, 3, 3, 0, byte(len(second) - 7)}, second[7:]...)
	_ = td.FeedClient(tail)
	_ = td.FeedServer(retry)
	_ = td.FeedServer(final)
}

// Independent Go standard crypto/HKDF records, with the traffic secret equal to
// 0x33 repeated to its hash length. No production key derivation generated them.
var tls13EarlySuiteRecords = []struct {
	name   string
	size   int
	first  string
	second string
}{
	{"aes128", 32, "1703030017938148b62e8f64da448edd348a8d4675692e5001e0cbe5", "1703030017e1136caebb52dc4d055c1563b9f666fe21ab42a4642f12"},
	{"aes256", 48, "1703030017c60381d69bc79d7a749b6d68ebde3ba8b14e9d4ec46622", "1703030017a699646eb3d70f3728f246112803305a94df0c3bec8fa8"},
	{"chacha", 32, "1703030017b036ba26cf83a412e9e5b6118ce0d30463615b083cc107", "1703030017d1c2242c6f187409bb0cf242a3365484df24bb5050f481"},
}

func TestTLS13RetryEarlyCipherIndependentOfFinalSuite(t *testing.T) {
	for _, vector := range tls13EarlySuiteRecords {
		for _, late := range []bool{false, true} {
			t.Run(vector.name+map[bool]string{false: "/ready", true: "/late"}[late], func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					td, out := newTLSRawTest(types.DecryptOptions{RawChunks: true, KeyWaitTimeout: time.Second})
					first, _ := hex.DecodeString(vector.first)
					second, _ := hex.DecodeString(vector.second)
					tls13RetryFlight(t, td, append(first, second...), "early_suites")
					app, hs := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)
					for _, label := range []string{"CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"} {
						tls13StageSecret(td, label, app)
					}
					for _, label := range []string{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET"} {
						tls13StageSecret(td, label, hs)
					}
					if !late {
						tls13StageSecret(td, "CLIENT_EARLY_TRAFFIC_SECRET", bytes.Repeat([]byte{0x33}, vector.size))
					}
					_ = td.FeedClient(tls13RawTestRecord(t, hs, 0, tls13Finished(), 22))
					_ = td.FeedClient(tls13RawTestRecord(t, app, 0, []byte("normal"), 23))
					_ = td.FeedServer(tls13RawTestRecord(t, hs, 0, append([]byte{8, 0, 0, 2, 0, 0}, tls13Finished()...), 22))
					_ = td.CloseClient()
					_ = td.CloseServer()
					done := make(chan error, 1)
					go func() { done <- td.Decrypt() }()
					if late {
						synctest.Wait()
						if len(out) != 0 {
							t.Fatal("late early key lost client ordering")
						}
						tls13StageSecret(td, "CLIENT_EARLY_TRAFFIC_SECRET", bytes.Repeat([]byte{0x33}, vector.size))
					}
					if err := <-done; err != nil {
						t.Fatal("old ticket cipher must authenticate rejected early data", err)
					}
					var early, normal []byte
					for len(out) > 0 {
						p := <-out
						if len(p.Data) == 0 {
							continue
						}
						if p.Metadata["early_data"] == "rejected" {
							if p.Metadata["encryption_level"] != "0rtt" || p.Metadata["offset"] != uint64(len(early)) {
								t.Fatal(p.Metadata)
							}
							early = append(early, p.Data...)
						} else {
							normal = append(normal, p.Data...)
						}
					}
					if string(early) != "early0early1" || string(normal) != "normal" {
						t.Fatalf("early=%q normal=%q", early, normal)
					}
					assertTLSBuffersReleased(t, td)
				})
			})
		}
	}
}

func TestTLS13EarlyCipherAuthenticationBoundaries(t *testing.T) {
	for _, mode := range []string{"tampered", "switch_cipher", "replay", "accepted_first", "accepted_late", "invalid_secret", "ech_rejected"} {
		t.Run(mode, func(t *testing.T) {
			td, out := newTLSRawTest(types.DecryptOptions{RawChunks: true})
			tls13StageHellos(t, td, true)
			app, hs, early := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32), bytes.Repeat([]byte{0x33}, 32)
			if mode == "invalid_secret" {
				early = early[:31]
			}
			for _, label := range []string{"CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"} {
				tls13StageSecret(td, label, app)
			}
			for _, label := range []string{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET"} {
				tls13StageSecret(td, label, hs)
			}
			tls13StageSecret(td, "CLIENT_EARLY_TRAFFIC_SECRET", early)
			if err := td.parseHandshake(); err != nil {
				t.Fatal(err)
			}
			accepted := tls13RawTestRecord(t, hs, 0, []byte{8, 0, 0, 6, 0, 4, 0, 42, 0, 0}, 22)
			if mode == "accepted_first" {
				_ = td.FeedServer(accepted)
			}
			first, _ := hex.DecodeString(tls13EarlySuiteRecords[2].first)
			if mode == "ech_rejected" {
				td.echRejected = true
				first, _ = hex.DecodeString(tls13EarlySuiteRecords[0].first)
			}
			if mode == "tampered" {
				first[len(first)-1] ^= 1
			}
			_ = td.FeedClient(first[:3])
			_ = td.FeedClient(first[3:])
			switch mode {
			case "switch_cipher":
				second, _ := hex.DecodeString(tls13EarlySuiteRecords[0].second)
				_ = td.FeedClient(second)
			case "replay":
				_ = td.FeedClient(first)
			case "accepted_late", "ech_rejected":
				_ = td.FeedServer(accepted)
			}
			if !td.aborted.Load() || td.decryptErr == nil || len(out) != 0 {
				t.Fatal("unauthenticated or incompatible early data escaped", td.decryptErr)
			}
			if mode == "tampered" && td.earlyCipherSuite != 0 {
				t.Fatal("failed authentication selected an early cipher")
			}
			td.releaseBuffers()
			if len(td.tls13[0].earlyCandidates) != 0 {
				t.Fatal("retained early candidate keys")
			}
		})
	}
}

func TestTLS13RejectedEarlyWaitsForItsOwnIdentity(t *testing.T) {
	for _, wrongIdentity := range []bool{false, true} {
		t.Run(map[bool]string{false: "late_inner", true: "outer_is_not_inner"}[wrongIdentity], func(t *testing.T) {
			td, out := newTLSRawTest(types.DecryptOptions{RawChunks: true})
			tls13StageHellos(t, td, true)
			app, hs, early := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32), bytes.Repeat([]byte{0x33}, 32)
			for _, label := range []string{"CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"} {
				tls13StageSecret(td, label, app)
			}
			for _, label := range []string{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET"} {
				tls13StageSecret(td, label, hs)
			}
			if err := td.parseHandshake(); err != nil {
				t.Fatal(err)
			}
			// The crypto layer separately proves this inner identity through
			// HPKE. Here only the transport's two key indexes are under test.
			td.earlyClientRandom = bytes.Repeat([]byte{0x66}, 32)
			td.echRejected = true
			tls13StageSecret(td, "CLIENT_EARLY_TRAFFIC_SECRET", early)
			_ = td.FeedClient(tls13RawTestRecord(t, early, 0, []byte("early"), 23))
			_ = td.FeedClient(tls13RawTestRecord(t, hs, 0, tls13Finished(), 22))
			_ = td.FeedClient(tls13RawTestRecord(t, app, 0, []byte("normal"), 23))
			_ = td.FeedServer(tls13RawTestRecord(t, hs, 0, append([]byte{8, 0, 0, 2, 0, 0}, tls13Finished()...), 22))
			td.processClientRecords()
			if len(out) != 0 || td.decryptErr != nil {
				t.Fatal("early ciphertext was discarded before its identity's key deadline", td.decryptErr)
			}
			if len(td.tls13[0].pendingRecord) != len("early")+22 || td.tls13[0].earlyKeysReady() {
				t.Fatal("early wait retained more than one record or used the outer key")
			}
			if wrongIdentity {
				td.tls13Finalizing.Store(true)
			} else {
				td.keyLog.AddSecret("CLIENT_EARLY_TRAFFIC_SECRET", hex.EncodeToString(td.earlyClientRandom), early)
			}
			td.processClientRecords()
			var earlyBytes, normal []byte
			for len(out) > 0 {
				p := <-out
				if p.Metadata["early_data"] == "rejected" {
					earlyBytes = append(earlyBytes, p.Data...)
				} else {
					normal = append(normal, p.Data...)
				}
			}
			if string(normal) != "normal" || (td.decryptErr != nil) != wrongIdentity || string(earlyBytes) != map[bool]string{false: "early", true: ""}[wrongIdentity] {
				t.Fatalf("wrongIdentity=%v early=%q normal=%q err=%v", wrongIdentity, earlyBytes, normal, td.decryptErr)
			}
			td.releaseBuffers()
			if td.tls13[0].pendingRecord != nil || td.tls13[0].earlyCandidates != nil || td.earlyClientRandom != nil {
				t.Fatal("early wait retained record/key identity after release")
			}
		})
	}
}

func TestTLS13EarlyOfferWithoutEarlyRecordsDoesNotWait(t *testing.T) {
	td, out := newTLSRawTest(types.DecryptOptions{RawChunks: true})
	tls13StageHellos(t, td, true)
	app, hs := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)
	for _, label := range []string{"CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"} {
		tls13StageSecret(td, label, app)
	}
	for _, label := range []string{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET"} {
		tls13StageSecret(td, label, hs)
	}
	if err := td.parseHandshake(); err != nil {
		t.Fatal(err)
	}
	_ = td.FeedClient(tls13RawTestRecord(t, hs, 0, tls13Finished(), 22))
	_ = td.FeedClient(tls13RawTestRecord(t, app, 0, []byte("normal"), 23))
	_ = td.FeedServer(tls13RawTestRecord(t, hs, 0, append([]byte{8, 0, 0, 2, 0, 0}, tls13Finished()...), 22))
	td.processClientRecords()
	if td.tls13Waiting() || td.decryptErr != nil || len(out) != 1 {
		t.Fatal("authenticated handshake needed an unused early secret", td.decryptErr)
	}
	if p := <-out; string(p.Data) != "normal" || p.Metadata["early_data"] != nil || p.Metadata["offset"] != uint64(0) {
		t.Fatal("normal output changed", p)
	}
	tls13StageSecret(td, "CLIENT_EARLY_TRAFFIC_SECRET", bytes.Repeat([]byte{0x33}, 32))
	td.processClientRecords()
	if td.tls13[0].earlyKeysReady() || td.tls13[0].phase != tls13Application {
		t.Fatal("late unused early key revived the early epoch")
	}
	td.releaseBuffers()
}

func TestTLS13RejectedEarlyForbidsEndOfEarlyData(t *testing.T) {
	for _, mode := range []string{"server_first", "client_first", "ech_rejected"} {
		t.Run(mode, func(t *testing.T) {
			td, out := newTLSRawTest(types.DecryptOptions{RawChunks: true})
			tls13StageHellos(t, td, true)
			app, hs, early := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32), bytes.Repeat([]byte{0x33}, 32)
			for _, label := range []string{"CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"} {
				tls13StageSecret(td, label, app)
			}
			for _, label := range []string{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET"} {
				tls13StageSecret(td, label, hs)
			}
			tls13StageSecret(td, "CLIENT_EARLY_TRAFFIC_SECRET", early)
			if err := td.parseHandshake(); err != nil {
				t.Fatal(err)
			}
			ee := tls13RawTestRecord(t, hs, 0, []byte{8, 0, 0, 2, 0, 0}, 22)
			if mode == "server_first" {
				_ = td.FeedServer(ee)
			}
			td.echRejected = mode == "ech_rejected"
			_ = td.FeedClient(tls13RawTestRecord(t, early, 0, []byte{5, 0, 0, 0}, 22))
			if mode == "client_first" {
				_ = td.FeedServer(ee)
			}
			if !td.aborted.Load() || td.decryptErr == nil || len(out) != 0 {
				t.Fatal("rejected early data accepted EndOfEarlyData", td.decryptErr)
			}
			td.releaseBuffers()
		})
	}
}

func TestTLS13GREASEEarlyAuthenticatesOnlyOuterCandidate(t *testing.T) {
	for _, mode := range []string{"normal", "accepted", "retry", "wrong_early"} {
		t.Run(mode, func(t *testing.T) {
			candidate, definitive := false, false
			td, out := newTLSRawTest(types.DecryptOptions{RawChunks: true, KeyWaitTimeout: time.Second, OnDiagnostic: func(d types.Diagnostic) {
				candidate = candidate || d.Code == "ech_not_accepted_or_grease"
				definitive = definitive || d.Code == "ech_accepted" || d.Code == "ech_rejected"
			}})
			app, hs, early := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32), bytes.Repeat([]byte{0x33}, 32)
			change := "ech_no_retry"
			if mode == "retry" {
				change = "ech_early"
			}
			tls13RetryFlight(t, td, tls13RawTestRecord(t, early, 0, []byte("early"), 23), change)
			for _, label := range []string{"CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"} {
				tls13StageSecret(td, label, app)
			}
			for _, label := range []string{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET"} {
				tls13StageSecret(td, label, hs)
			}
			if mode == "wrong_early" {
				early[0] ^= 1
			}
			tls13StageSecret(td, "CLIENT_EARLY_TRAFFIC_SECRET", early)
			if mode == "accepted" {
				_ = td.FeedClient(tls13RawTestRecord(t, early, 1, []byte{5, 0, 0, 0}, 22))
			}
			_ = td.FeedClient(tls13RawTestRecord(t, hs, 0, tls13Finished(), 22))
			_ = td.FeedClient(tls13RawTestRecord(t, app, 0, []byte("normal"), 23))
			ee := []byte{8, 0, 0, 2, 0, 0}
			if mode == "accepted" {
				ee = []byte{8, 0, 0, 6, 0, 4, 0, 42, 0, 0}
			}
			_ = td.FeedServer(tls13RawTestRecord(t, hs, 0, append(ee, tls13Finished()...), 22))
			_ = td.CloseClient()
			_ = td.CloseServer()
			if err := td.Decrypt(); (err != nil) != (mode == "wrong_early") {
				t.Fatal("outer candidate boundary", err)
			}
			var earlyBytes, normal []byte
			for len(out) > 0 {
				p := <-out
				if p.Metadata["early_data"] != nil {
					status := "rejected"
					if mode == "accepted" {
						status = "accepted"
					}
					if p.Metadata["early_data"] != status || p.Metadata["offset"] != uint64(len(earlyBytes)) {
						t.Fatal(p.Metadata)
					}
					earlyBytes = append(earlyBytes, p.Data...)
				} else {
					normal = append(normal, p.Data...)
				}
			}
			if definitive || mode != "wrong_early" && (!candidate || string(earlyBytes) != "early" || string(normal) != "normal") || mode == "wrong_early" && (len(earlyBytes) != 0 || len(normal) != 0) {
				t.Fatalf("candidate=%v definitive=%v early=%q normal=%q", candidate, definitive, earlyBytes, normal)
			}
		})
	}
}

func TestTLS13RetryRejectsEarlyAndWaitsForLateKeys(t *testing.T) {
	for _, delayed := range []string{"none", "early", "handshake", "missing_early"} {
		t.Run(delayed, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				td, out := newTLSRawTest(types.DecryptOptions{RawChunks: true, KeyWaitTimeout: time.Second})
				app, hs, early := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32), bytes.Repeat([]byte{0x33}, 32)
				tls13RetryFlight(t, td, tls13RawTestRecord(t, early, 0, []byte("early"), 23), "")
				for _, label := range []string{"CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"} {
					tls13StageSecret(td, label, app)
				}
				if delayed != "early" && delayed != "missing_early" {
					tls13StageSecret(td, "CLIENT_EARLY_TRAFFIC_SECRET", early)
				}
				if delayed != "handshake" {
					for _, label := range []string{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET"} {
						tls13StageSecret(td, label, hs)
					}
				}
				_ = td.FeedClient(tls13RawTestRecord(t, hs, 0, tls13Finished(), 22))
				_ = td.FeedClient(tls13RawTestRecord(t, app, 0, []byte("normal"), 23))
				_ = td.FeedServer(tls13RawTestRecord(t, hs, 0, append([]byte{8, 0, 0, 2, 0, 0}, tls13Finished()...), 22))
				_ = td.FeedServer(tls13RawTestRecord(t, app, 0, []byte("response"), 23))
				_ = td.CloseClient()
				_ = td.CloseServer()
				done := make(chan error, 1)
				go func() { done <- td.Decrypt() }()
				synctest.Wait()
				switch delayed {
				case "early":
					tls13StageSecret(td, "CLIENT_EARLY_TRAFFIC_SECRET", early)
				case "handshake":
					for _, label := range []string{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET"} {
						tls13StageSecret(td, label, hs)
					}
				case "missing_early":
					time.Sleep(time.Second)
				}
				if err := <-done; (err != nil) != (delayed == "missing_early") {
					t.Fatal("HRR early result", err)
				}
				var earlyBytes, normal, response []byte
				for len(out) > 0 {
					p := <-out
					if len(p.Data) == 0 {
						continue
					}
					if p.Metadata["encryption_level"] == "0rtt" {
						if p.Metadata["early_data"] != "rejected" || p.Metadata["offset"] != uint64(len(earlyBytes)) {
							t.Fatal(p.Metadata)
						}
						earlyBytes = append(earlyBytes, p.Data...)
					} else if p.Direction == "request" {
						if p.Metadata["offset"] != uint64(len(normal)) || p.Metadata["early_data"] != nil {
							t.Fatal(p.Metadata)
						}
						normal = append(normal, p.Data...)
					} else {
						response = append(response, p.Data...)
					}
				}
				wantEarly := "early"
				if delayed == "missing_early" {
					wantEarly = ""
				}
				if string(earlyBytes) != wantEarly || string(normal) != "normal" || string(response) != "response" || td.tlsEarlyStatus() != "rejected" {
					t.Fatalf("early=%q normal=%q response=%q", earlyBytes, normal, response)
				}
				if td.retryEarlyBytes != 0 || len(td.retryEarlyRecords) != 0 {
					t.Fatal("retained retry ciphertext")
				}
				assertTLSBuffersReleased(t, td)
			})
		})
	}
}

func TestTLS13RetryRejectsInvalidEarlyBoundaries(t *testing.T) {
	for _, change := range []string{"second_early", "random", "repeat_hrr", "suite", "interleaved_early", "post_retry_early", "end_of_early", "accepted", "wrong_early", "ech_early"} {
		t.Run(change, func(t *testing.T) {
			unavailable := false
			td, out := newTLSRawTest(types.DecryptOptions{RawChunks: true, OnDiagnostic: func(d types.Diagnostic) {
				unavailable = unavailable || d.Code == "ech_unavailable"
			}})
			app, hs, early := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32), bytes.Repeat([]byte{0x33}, 32)
			record := tls13RawTestRecord(t, early, 0, []byte("early"), 23)
			if change == "end_of_early" {
				record = tls13RawTestRecord(t, early, 0, []byte{5, 0, 0, 0}, 22)
			}
			if change == "wrong_early" {
				record[len(record)-1] ^= 1
			}
			tls13RetryFlight(t, td, record, change)
			for _, label := range []string{"CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"} {
				tls13StageSecret(td, label, app)
			}
			for _, label := range []string{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET"} {
				tls13StageSecret(td, label, hs)
			}
			if change != "ech_early" { // No HPKE material and no complete Outer candidate.
				tls13StageSecret(td, "CLIENT_EARLY_TRAFFIC_SECRET", early)
			}
			if change == "post_retry_early" {
				_ = td.FeedClient(tls13RawTestRecord(t, early, 1, []byte("forbidden"), 23))
			}
			if change == "accepted" {
				_ = td.FeedServer(tls13RawTestRecord(t, hs, 0, []byte{8, 0, 0, 6, 0, 4, 0, 42, 0, 0}, 22))
			}
			_ = td.Close()
			if err := td.Decrypt(); err == nil {
				t.Fatal("invalid HRR boundary accepted")
			}
			if change == "ech_early" && !unavailable {
				t.Fatal("ECH early identity without HPKE materials did not fail explicitly")
			}
			for len(out) > 0 {
				if p := <-out; string(p.Data) == "forbidden" {
					t.Fatal("early key remained usable after CH2")
				}
			}
			assertTLSBuffersReleased(t, td)
		})
	}
}

func TestTLS13RetryEarlyCiphertextLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		td, _ := newTLSRawTest(types.DecryptOptions{RawChunks: true})
		tls13RetryFlight(t, td, nil, "before_second")
		done := make(chan error, 1)
		go func() { done <- td.Decrypt() }()
		synctest.Wait()
		secret := bytes.Repeat([]byte{0x33}, 32)
		body := make([]byte, 16384)
		for i := 0; i < tlsPendingResponseLimit/(len(body)+22)+1; i++ {
			record := tls13RawTestRecord(t, secret, uint64(i), body, 23)
			if err := td.FeedClient(record); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
		}
		if err := <-done; !errors.Is(err, crypto.ErrHandshakeResourceLimit) {
			t.Fatal("pre-CH2 ciphertext exceeded its retained-byte limit", err)
		}
		if td.retryEarlyBytes != 0 || len(td.retryEarlyRecords) != 0 {
			t.Fatal("retry failure retained ciphertext")
		}
		assertTLSBuffersReleased(t, td)
	})
}

func TestTLS13UnknownEarlyAndMissingEarlySecret(t *testing.T) {
	for _, raw := range []bool{false, true} {
		for _, missing := range []string{"server_handshake", "early"} {
			t.Run(missing+map[bool]string{false: "/messages", true: "/raw"}[raw], func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					td, out := newTLSRawTest(types.DecryptOptions{RawChunks: raw, KeyWaitTimeout: time.Second})
					app, hs, early := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32), bytes.Repeat([]byte{0x33}, 32)
					tls13StageHellos(t, td, true)
					for _, label := range []string{"CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"} {
						tls13StageSecret(td, label, app)
					}
					tls13StageSecret(td, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", hs)
					if missing != "server_handshake" {
						tls13StageSecret(td, "SERVER_HANDSHAKE_TRAFFIC_SECRET", hs)
					}
					if missing != "early" {
						tls13StageSecret(td, "CLIENT_EARLY_TRAFFIC_SECRET", early)
					}
					_ = td.FeedClient(tls13RawTestRecord(t, early, 0, []byte("GET / HTTP/1.1\r\nHost: test\r\n\r\n"), 23))
					_ = td.FeedClient(tls13RawTestRecord(t, early, 1, []byte{5, 0, 0, 0}, 22))
					_ = td.FeedClient(tls13RawTestRecord(t, hs, 0, tls13Finished(), 22))
					_ = td.FeedServer(tls13RawTestRecord(t, hs, 0, append([]byte{8, 0, 0, 6, 0, 4, 0, 42, 0, 0}, tls13Finished()...), 22))
					done := make(chan error, 1)
					go func() { done <- td.Decrypt() }()
					synctest.Wait()
					_ = td.Close()
					if err := <-done; err == nil {
						t.Fatal("missing early acceptance/key returned complete success")
					}
					seen := 0
					for len(out) > 0 {
						p := <-out
						if p.Metadata["end"] == true {
							t.Fatal("incomplete capture emitted clean raw end")
						}
						if !raw || missing != "server_handshake" || p.Metadata["early_data"] != "unknown" {
							t.Fatal("unknown/unauthenticated early data was delivered to an application")
						}
						seen++
					}
					if raw && missing == "server_handshake" && seen != 1 {
						t.Fatal("authenticated unknown early bytes were not retained in raw mode")
					}
				})
			})
		}
	}
}

func TestTLS13HandshakeResourceLimit(t *testing.T) {
	td, out, _, hs := newTLS13StageTest(t)
	_ = td.FeedClient(tls13RawTestRecord(t, hs, 0, []byte{11, 0xff, 0xff, 0xff}, 22))
	if !errors.Is(td.decryptErr, crypto.ErrHandshakeResourceLimit) || len(out) != 0 {
		t.Fatal("authenticated handshake declared length was not bounded", td.decryptErr)
	}
}

func TestTLS13AuthenticatedAlertAndCloseDelimitedHTTP(t *testing.T) {
	for _, alert := range []string{"close_notify", "missing", "fatal", "malformed"} {
		t.Run(alert, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				td, out := newTLSRawTest(types.DecryptOptions{HTTPEvents: true})
				app := bytes.Repeat([]byte{0x11}, 32)
				tls13StageHellos(t, td, false)
				for _, label := range []string{"CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"} {
					tls13StageSecret(td, label, app)
				}
				_ = td.FeedClient(tls13RawTestRecord(t, app, 0, []byte("GET / HTTP/1.0\r\n\r\n"), 23))
				_ = td.FeedServer(tls13RawTestRecord(t, app, 0, []byte("HTTP/1.0 200 OK\r\n\r\nbody"), 23))
				if alert != "missing" {
					payload := map[string][]byte{"close_notify": {1, 0}, "fatal": {2, 40}, "malformed": {1}}[alert]
					_ = td.FeedServer(tls13RawTestRecord(t, app, 1, payload, 21))
				}
				done := make(chan error, 1)
				go func() { done <- td.Decrypt() }()
				synctest.Wait()
				_ = td.Close() // Capture EOF, without TCP FIN, must retain close_notify.
				err := <-done
				if (err == nil) != (alert == "close_notify") || td.serverEnded.Load() != (alert == "close_notify") {
					t.Fatalf("alert=%s err=%v serverEnded=%v", alert, err, td.serverEnded.Load())
				}
				var body []byte
				ended := false
				for len(out) > 0 {
					p := <-out
					if p.Direction == "response" {
						body = append(body, p.Data...)
						ended = ended || p.Metadata["kind"] == "end"
					}
				}
				if string(body) != "body" || ended != (alert == "close_notify") {
					t.Fatalf("body=%q clean end=%v", body, ended)
				}
			})
		})
	}
}

func TestTLS13AcceptedEarlyRequiresEndOfEarlyData(t *testing.T) {
	for _, serverFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "client_first", true: "server_first"}[serverFirst], func(t *testing.T) {
			td, out := newTLSRawTest(types.DecryptOptions{RawChunks: true})
			app, hs, early := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32), bytes.Repeat([]byte{0x33}, 32)
			tls13StageHellos(t, td, true)
			for _, label := range []string{"CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"} {
				tls13StageSecret(td, label, app)
			}
			for _, label := range []string{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET"} {
				tls13StageSecret(td, label, hs)
			}
			tls13StageSecret(td, "CLIENT_EARLY_TRAFFIC_SECRET", early)
			if err := td.parseHandshake(); err != nil {
				t.Fatal(err)
			}
			ee := tls13RawTestRecord(t, hs, 0, []byte{8, 0, 0, 6, 0, 4, 0, 42, 0, 0}, 22)
			if serverFirst {
				_ = td.FeedServer(ee)
			}
			// A validly encrypted handshake record cannot skip the required early
			// epoch terminator, even when the peer's acceptance arrives later.
			_ = td.FeedClient(tls13RawTestRecord(t, hs, 0, tls13Finished(), 22))
			if !serverFirst {
				_ = td.FeedServer(ee)
			}
			if !td.aborted.Load() || td.decryptErr == nil || len(out) != 0 {
				t.Fatal("accepted early epoch skipped EndOfEarlyData", td.decryptErr)
			}
		})
	}
}

func TestTLS13ServerFeedDoesNotOvertakeBufferedRequests(t *testing.T) {
	td, out := newTLSRawTest(types.DecryptOptions{ApplicationProtocol: "dot"})
	app := bytes.Repeat([]byte{0x11}, 32)
	tls13StageHellos(t, td, false)
	for _, label := range []string{"CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"} {
		tls13StageSecret(td, label, app)
	}
	dns := func(id byte, response bool) []byte {
		message := []byte{0, id, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a' + id, 0, 0, 1, 0, 1}
		if response {
			message[2] |= 0x80
		}
		return append([]byte{0, byte(len(message))}, message...)
	}
	// Both requests arrived during the key wait. FeedServer can resume between
	// publishing handshakeComplete and the worker's initial buffered drain.
	for i := byte(1); i <= 2; i++ {
		_ = td.FeedClient(tls13RawTestRecord(t, app, uint64(i-1), dns(i, false), 23))
	}
	if err := td.parseHandshake(); err != nil {
		t.Fatal(err)
	}
	_ = td.FeedServer(tls13RawTestRecord(t, app, 0, append(dns(1, true), dns(2, true)...), 23))
	td.processClientRecords()
	if len(out) != 4 {
		t.Fatalf("got %d DNS messages, want 4", len(out))
	}
	for len(out) > 0 {
		p := <-out
		if p.Direction == "response" && (p.Metadata["matched"] != true || p.Metadata["request_id"] == nil) {
			t.Fatal("response overtook a buffered request", p.Metadata)
		}
	}
}
