// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package transport

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gojue/ecapture_decryptor/crypto"
	"github.com/gojue/ecapture_decryptor/types"
)

// These packets exercise scheduling and lifecycle, not key derivation; the
// independent RFC vectors in quic_decryptor_test.go cover packet protection.
func quicLifecyclePacket(t *testing.T, secret []byte) []byte {
	t.Helper()
	keys, err := deriveQUICKeys(secret, quicVersion1, quicAES128)
	if err != nil {
		t.Fatal(err)
	}
	header := []byte{0x43, 0, 0, 0, 0} // Short header, no CID, four-byte packet number 0.
	packet := append(header, keys.aead.Seal(nil, keys.iv, []byte{0x0b, 0, 3, 1, 0, 0xff}, header)...)
	mask, err := keys.headerMask(packet[5:21])
	if err != nil {
		t.Fatal(err)
	}
	packet[0] ^= mask[0] & 0x1f
	for i := 0; i < 4; i++ {
		packet[1+i] ^= mask[1+i]
	}
	return packet
}

func assertQUICReleased(t *testing.T, q *QUICDecryptor) {
	t.Helper()
	if len(q.input) != 0 || q.inputBytes != 0 || len(q.flow.pending) != 0 || q.flow.pendingBytes != 0 ||
		!q.flow.pendingSince.IsZero() || len(q.flow.streams) != 0 || q.http3Parser != nil {
		t.Fatal("terminated connection retained queued or parsed data")
	}
	if err := q.FeedClient([]byte{0x40}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("feed after termination = %v, want ErrClosedPipe", err)
	}
}

func TestQUICKeyWaitDeadline(t *testing.T) {
	for _, mode := range []string{"missing", "partial_keys", "before_deadline", "new_wait_window"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var diagnostics []types.Diagnostic
				q, packets := newQUICOutputTest(t, types.DecryptOptions{
					RawChunks: true, KeyWaitTimeout: 10 * time.Second,
					OnDiagnostic: func(d types.Diagnostic) { diagnostics = append(diagnostics, d) },
				})
				q.version = quicVersion1
				q.flow.clientRandom = bytes.Repeat([]byte{0x44}, 32)
				q.flow.clientHelloDone = true // This test starts after a complete ClientHello.
				randomHex := hex.EncodeToString(q.flow.clientRandom)
				clientSecret, serverSecret := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)
				client, server := quicLifecyclePacket(t, clientSecret), quicLifecyclePacket(t, serverSecret)
				if err := q.FeedClient(client); err != nil {
					t.Fatal(err)
				}
				if mode == "partial_keys" {
					if err := q.FeedServer(server); err != nil {
						t.Fatal(err)
					}
				}
				done := make(chan error, 1)
				go func() { done <- q.Decrypt() }()
				defer func() { _ = q.Close(); synctest.Wait() }()
				synctest.Wait()
				started := time.Now()
				if len(packets) != 0 || q.flow.pendingSince.IsZero() {
					t.Fatal("packet did not enter the key wait")
				}
				time.Sleep(9 * time.Second)
				if mode != "missing" {
					q.keyLog.AddSecret("CLIENT_TRAFFIC_SECRET_0", randomHex, clientSecret)
					synctest.Wait()
					if len(packets) != 1 {
						t.Fatal("client secret arriving before deadline did not emit its stream")
					}
				}
				if mode == "missing" || mode == "partial_keys" {
					// A duplicate or unrelated update cannot extend the first wait.
					q.keyLog.AddSecret("CLIENT_TRAFFIC_SECRET_0", "aabb", clientSecret)
					time.Sleep(time.Second)
					synctest.Wait()
					select {
					case err := <-done:
						if err == nil {
							t.Fatal("key timeout returned success")
						}
					default:
						t.Fatal("missing or partial keys did not terminate at the original deadline")
					}
					stage, code := "keys", "key_wait_timeout"
					if mode == "missing" {
						stage, code = "handshake", "identity_timeout"
					}
					if time.Since(started) != 10*time.Second || len(diagnostics) != 1 ||
						diagnostics[0].Stage != stage || diagnostics[0].Code != code {
						t.Fatalf("timeout timing/diagnostics: elapsed=%s diagnostics=%+v", time.Since(started), diagnostics)
					}
				} else {
					// Once every pending packet has been decrypted, the original
					// deadline must be disarmed even while input stays open.
					time.Sleep(2 * time.Second)
					if mode == "new_wait_window" {
						if err := q.FeedServer(server); err != nil {
							t.Fatal(err)
						}
						synctest.Wait()
						time.Sleep(9 * time.Second)
						q.keyLog.AddSecret("SERVER_TRAFFIC_SECRET_0", randomHex, serverSecret)
						synctest.Wait()
						if len(packets) != 2 {
							t.Fatal("new pending data did not receive a fresh wait window")
						}
					}
					time.Sleep(20 * time.Second)
					synctest.Wait()
					select {
					case err := <-done:
						t.Fatalf("drained key wait terminated an open connection: %v", err)
					default:
					}
					_ = q.Close()
					if err := <-done; err != nil {
						t.Fatal(err)
					}
					if len(diagnostics) != 0 {
						t.Fatalf("successful late secrets reported diagnostics: %+v", diagnostics)
					}
				}
				assertQUICReleased(t, q)
			})
		})
	}
}

func TestQUICQueueLimitsTerminateAndRelease(t *testing.T) {
	for _, queue := range []string{"input", "deferred"} {
		for _, limit := range []string{"bytes", "packets"} {
			t.Run(queue+"_"+limit, func(t *testing.T) {
				var diagnostics []types.Diagnostic
				q, _ := newQUICOutputTest(t, types.DecryptOptions{OnDiagnostic: func(d types.Diagnostic) {
					diagnostics = append(diagnostics, d)
				}})
				data, count := []byte{0x40}, maxQUICQueuedPackets
				if limit == "bytes" {
					data = make([]byte, quicMaxPacketSize)
					data[0] = 0x40
					count = maxQUICBufferedBytes / len(data)
				}
				for i := 0; i < count; i++ {
					if queue == "input" {
						if err := q.FeedClient(data); err != nil {
							t.Fatalf("queue rejected data below its limit: %v", err)
						}
					} else {
						q.processQUICDatagram(quicDatagram{data: data, isClient: true})
					}
				}
				if len(diagnostics) != 0 {
					t.Fatal("queue limit fired before the limit was reached")
				}
				if queue == "input" {
					if err := q.FeedClient([]byte{0x40}); !errors.Is(err, errQUICInputLimit) {
						t.Fatalf("input overflow = %v", err)
					}
				} else {
					q.processQUICDatagram(quicDatagram{data: []byte{0x40}, isClient: true})
				}
				if err := q.Decrypt(); err == nil {
					t.Fatal("queue overflow returned success")
				}
				stage := "input"
				if queue == "deferred" {
					stage = "reassembly"
				}
				if len(diagnostics) != 1 || diagnostics[0].Stage != stage || diagnostics[0].Code != "resource_limit" {
					t.Fatalf("overflow diagnostics = %+v", diagnostics)
				}
				assertQUICReleased(t, q)
			})
		}
	}
}

func TestQUICCompletedStreamCountIsBounded(t *testing.T) {
	var diagnostics []types.Diagnostic
	q, _ := newQUICOutputTest(t, types.DecryptOptions{OnDiagnostic: func(d types.Diagnostic) {
		diagnostics = append(diagnostics, d)
	}})
	// Completed unknown HTTP/3 unidirectional streams retain de-duplication
	// markers and still consume the quota.
	for i := 0; i < maxQUICStreams; i++ {
		if err := q.feedQUICStream(uint64(i*4+2), 0, []byte{0x21}, true, true, time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.feedQUICStream(uint64(maxQUICStreams*4+2), 0, nil, true, true, time.Time{}); !errors.Is(err, errQUICStreamCountLimit) {
		t.Fatalf("stream count overflow = %v", err)
	}
	if len(q.flow.streams) != maxQUICStreams || len(diagnostics) != 1 || diagnostics[0].Code != "resource_limit" {
		t.Fatalf("stream count or diagnostic mismatch: count=%d diagnostics=%+v", len(q.flow.streams), diagnostics)
	}
	if err := q.Decrypt(); !errors.Is(err, errQUICStreamCountLimit) {
		t.Fatalf("stream count overflow termination = %v", err)
	}
	assertQUICReleased(t, q)
}

func TestQUICStreamPendingSegmentLimit(t *testing.T) {
	// Start one entry below the quota; repeatedly scanning an unfillable gap
	// for all 65,536 setup inserts would make this boundary test quadratic.
	stream := quicStreamAssembler{
		pending: make(map[uint64][]byte, maxQUICPendingSegments), pendingBytes: maxQUICPendingSegments - 1,
	}
	for i := 0; i < maxQUICPendingSegments-1; i++ {
		stream.pending[uint64(i+2)] = []byte{1}
	}
	parts, complete, err := stream.push(uint64(maxQUICPendingSegments+1), []byte{1}, false)
	if err != nil || complete || len(parts) != 0 {
		t.Fatalf("last permitted segment: parts=%d complete=%t err=%v", len(parts), complete, err)
	}
	if _, _, err := stream.push(uint64(maxQUICPendingSegments+2), []byte{1}, false); !errors.Is(err, errQUICBufferLimit) {
		t.Fatalf("pending segment overflow = %v, want buffer limit", err)
	}
	if len(stream.pending) != maxQUICPendingSegments || stream.pendingBytes != maxQUICPendingSegments {
		t.Fatal("rejected segment consumed the queue budget")
	}
	// A longer retransmission at an existing offset replaces one entry, so it
	// remains valid even when every pending-segment slot is occupied.
	if _, _, err := stream.push(2, []byte{1, 1}, false); err != nil {
		t.Fatalf("same-offset replacement was rejected: %v", err)
	}
	if len(stream.pending) != maxQUICPendingSegments || stream.pendingBytes != maxQUICPendingSegments+1 {
		t.Fatal("same-offset replacement changed the object count or lost byte accounting")
	}
	// Fill the gap and overlap the queued segments, as a retransmission may do.
	prefix := bytes.Repeat([]byte{1}, maxQUICPendingSegments+3)
	parts, complete, err = stream.push(0, prefix, true)
	if err != nil || !complete || len(parts) != 1 || !bytes.Equal(parts[0], prefix) {
		t.Fatalf("gap-fill failed: parts=%d complete=%t err=%v", len(parts), complete, err)
	}
	if len(stream.pending) != 0 || stream.pendingBytes != 0 {
		t.Fatal("filling the gap retained pending segments or their byte budget")
	}
}

func TestQUICEarlyAcceptanceDeadlineReleasesState(t *testing.T) {
	for _, frame := range [][]byte{{0x0b, 0, 3, 'a', 'b', 'c'}, {0x31, 1, 0xff}, {4, 0, 0, 0}} {
		synctest.Test(t, func(t *testing.T) {
			q, out := newQUICOutputTest(t, types.DecryptOptions{RawChunks: true, KeyWaitTimeout: 5 * time.Second})
			q.version = quicVersion1
			key, _ := deriveQUICKeys(bytes.Repeat([]byte{4}, 32), quicVersion1, quicAES128)
			q.flow.keys[0][quicLevelEarly] = []*QUICKeys{key}
			packet := quicLongTestPacket(t, quicVersion1, QUICPacketType0RTT, nil, nil, nil, key, 0, frame)
			if err := q.FeedClient(packet.data); err != nil {
				t.Fatal(err)
			}
			if frame[0] == 4 {
				q.flow.keys[0][quicLevelApplication] = []*QUICKeys{key}
				if err := q.FeedClient(quicKeyPhasePacket(t, key, 1, 0, frame).data); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, 1)
			go func() { done <- q.Decrypt() }()
			defer func() { _ = q.Close(); synctest.Wait() }()
			synctest.Wait()
			if len(out) != 0 {
				t.Fatal("early data escaped acceptance wait")
			}
			time.Sleep(5 * time.Second)
			synctest.Wait()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("unknown acceptance returned success")
				}
			default:
				t.Fatal("acceptance wait did not expire")
			}
			want := 1
			if frame[0] == 4 {
				want = 2
			}
			if len(out) != want || (<-out).Metadata["early_data"] != "unknown" {
				t.Fatal("raw unknown output was lost")
			}
			if want == 2 {
				if p := <-out; p.Metadata["kind"] != "stream_reset" || p.Metadata["encryption_level"] != "1rtt" || p.Metadata["early_data"] != nil {
					t.Fatal("queued application reset was lost or inherited early metadata", p.Metadata)
				}
			}
			assertQUICReleased(t, q)
			if len(q.flow.early.frames) != 0 || len(q.flow.early.streams) != 0 || q.routingHandler != nil || q.flow.handshake.retry != nil {
				t.Fatal("handshake/early/routing state retained")
			}
		})
	}
}

func TestQUICDatagramClosePreservesBackpressure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q, _ := newQUICOutputTest(t, types.DecryptOptions{RawChunks: true})
		q.packetChan = make(chan *types.DecryptedPacket)
		key, _ := deriveQUICKeys(bytes.Repeat([]byte{4}, 32), quicVersion1, quicAES128)
		q.flow.keys[0][quicLevelApplication] = []*QUICKeys{key}
		packet := quicKeyPhasePacket(t, key, 0, 0, []byte{0x31, 0, 0x31, 1, 0xff})
		if err := q.FeedClient(packet.data); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- q.Decrypt() }()
		synctest.Wait()
		if err := q.Close(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatal("Close dropped buffered output instead of preserving backpressure", err)
		default:
		}
		for _, want := range [][]byte{{}, {0xff}} {
			if p := <-q.packetChan; p.Metadata["kind"] != "datagram" || !bytes.Equal(p.Data, want) {
				t.Fatal("Close lost a datagram")
			}
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		assertQUICReleased(t, q)
		if len(q.flow.receivedPN[0]) != 0 {
			t.Fatal("Close retained packet-number history")
		}
	})
}

func TestQUICDatagramLateKeyWakesWithoutMorePackets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		q, out := newQUICOutputTest(t, types.DecryptOptions{RawChunks: true})
		q.version = quicVersion1
		q.flow.clientRandom = bytes.Repeat([]byte{0x44}, 32)
		secret := bytes.Repeat([]byte{4}, 32)
		key, _ := deriveQUICKeys(secret, quicVersion1, quicAES128)
		packet := quicKeyPhasePacket(t, key, 0, 0, []byte{0x31, 0, 0x31, 1, 0xff})
		for i := 0; i < 2; i++ {
			if err := q.FeedClient(packet.data); err != nil {
				t.Fatal(err)
			}
		}
		done := make(chan error, 1)
		go func() { done <- q.Decrypt() }()
		synctest.Wait()
		if len(out) != 0 || len(q.flow.pending) != 2 || len(q.flow.receivedPN[0]) != 0 {
			t.Fatal("unavailable keys emitted or reserved a packet number")
		}
		q.keyLog.AddSecret("CLIENT_TRAFFIC_SECRET_0", hex.EncodeToString(q.flow.clientRandom), secret)
		synctest.Wait()
		if len(out) != 2 || len(q.flow.pending) != 0 {
			t.Fatal("late key lost DATAGRAMs or emitted duplicate capture", len(out))
		}
		q.keyLog.AddSecret("CLIENT_TRAFFIC_SECRET_0", hex.EncodeToString(q.flow.clientRandom), secret)
		_ = q.Close()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		assertQUICReleased(t, q)
	})
}

func TestQUICDatagramBoundedEarlyAndPacketHistory(t *testing.T) {
	for _, limit := range []string{"early_frames", "early_bytes", "application_resets", "application_bytes", "packet_ranges"} {
		t.Run(limit, func(t *testing.T) {
			var diagnostics []types.Diagnostic
			q, out := newQUICOutputTest(t, types.DecryptOptions{RawChunks: true, OnDiagnostic: func(d types.Diagnostic) { diagnostics = append(diagnostics, d) }})
			if limit == "packet_ranges" {
				for i := uint64(0); i < maxQUICPendingSegments; i++ {
					if duplicate, err := q.markQUICPacketNumber(0, i*2); err != nil || duplicate {
						t.Fatal("packet range limit fired early", err)
					}
				}
				key, _ := deriveQUICKeys(bytes.Repeat([]byte{4}, 32), quicVersion1, quicAES128)
				q.flow.keys[0][quicLevelApplication] = []*QUICKeys{key}
				// A distant authenticated packet needs one more interval. Seed the
				// reconstruction context because this helper uses a one-byte PN.
				q.flow.largest[0][quicLevelApplication] = maxQUICPendingSegments * 2
				q.flow.haveLargest[0][quicLevelApplication] = true
				packet := quicKeyPhasePacket(t, key, maxQUICPendingSegments*2+2, 0, []byte{0x31, 1, 0xff})
				if _, err := q.processQUICPacket(packet, true, time.Time{}); !errors.Is(err, errQUICBufferLimit) {
					t.Fatal("packet interval overflow did not fail explicitly", err)
				}
			} else {
				count, data := maxQUICQueuedPackets, []byte{}
				if limit == "early_bytes" || limit == "application_bytes" {
					data = make([]byte, 32<<10)
					count = maxQUICBufferedBytes / len(data)
				}
				stream := append([]byte{0x08, 0}, data...)
				for i := 0; i < count; i++ {
					var err error
					if limit == "application_resets" {
						q.flow.pendingLevels[0][quicLevelEarly] = true
						err = q.parseQUICFrames([]byte{4, 0, 0, 0}, quicLevelApplication, true, time.Time{})
					} else if limit == "application_bytes" {
						q.flow.pendingLevels[0][quicLevelEarly] = true
						err = q.parseQUICFrames(stream, quicLevelApplication, true, time.Time{})
					} else {
						err = q.queueQUICEarly(quicEarlyFrame{datagram: true, data: data})
					}
					if err != nil {
						t.Fatal("early limit fired before the limit", err)
					}
				}
				if err := q.parseQUICFrames([]byte{0x31, 1, 0xff}, quicLevelEarly, true, time.Time{}); !errors.Is(err, errQUICBufferLimit) {
					t.Fatal("early limit was not enforced", err)
				}
			}
			if len(out) != 0 || len(diagnostics) != 1 || diagnostics[0].Code != "resource_limit" || q.flow.terminalErr == nil {
				t.Fatal("resource failure emitted output or lost diagnostic", diagnostics)
			}
			if err := q.Decrypt(); !errors.Is(err, errQUICBufferLimit) {
				t.Fatal("resource error lost on shutdown", err)
			}
			assertQUICReleased(t, q)
			if len(q.flow.early.frames) != 0 || q.flow.early.bytes != 0 || len(q.flow.receivedPN[0]) != 0 {
				t.Fatal("resource failure retained DATAGRAM state")
			}
		})
	}
}

func TestDoQRejectsAcceptedEarlyStreamAndReset(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame []byte
	}{
		{"stream", []byte{0x0b, 0, 1, 0}},
		{"reset", []byte{4, 0, 0, 0}},
	} {
		for _, status := range []string{"accepted", "rejected"} {
			t.Run(tc.name+"/"+status, func(t *testing.T) {
				q, out := newQUICOutputTest(t, types.DecryptOptions{ApplicationProtocol: "doq"})
				if err := q.parseQUICFrames(tc.frame, quicLevelEarly, true, time.Time{}); err != nil {
					t.Fatal(err)
				}
				if len(out) != 0 || len(q.flow.streams) != 0 {
					t.Fatal("DoQ early frame escaped acceptance wait")
				}
				// Authenticated EncryptedExtensions selects doq and resolves whether
				// queued early data was accepted before application dispatch.
				ee := []byte{8, 0, 0, 12, 0, 10, 0, 16, 0, 6, 0, 4, 3, 'd', 'o', 'q'}
				if status == "accepted" {
					ee[3], ee[5] = 16, 14
					ee = append(ee, 0, 42, 0, 0)
				}
				err := q.observeServerCrypto(quicLevelHandshake, 0, ee)
				if status == "accepted" {
					if err == nil || err.Error() != "DoQ early data is not supported" || q.flow.terminalErr != err {
						t.Fatalf("accepted early %s: %v, terminal=%v", tc.name, err, q.flow.terminalErr)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				if len(out) != 0 || len(q.flow.streams) != 0 || len(q.flow.early.frames) != 0 || q.flow.early.bytes != 0 {
					t.Fatal("DoQ early frame emitted output or retained stream state")
				}
				if status == "rejected" {
					// Rejection must leave the stream ID available for ordinary 1-RTT.
					if err := q.parseQUICFrames([]byte{4, 0, 0, 0}, quicLevelApplication, true, time.Time{}); err != nil {
						t.Fatal(err)
					}
					if len(out) != 1 || (<-out).Metadata["kind"] != "reset" {
						t.Fatal("1-RTT reset was lost after rejected early data")
					}
				}
				_ = q.Close()
				if err := q.Decrypt(); (err != nil) != (status == "accepted") {
					t.Fatalf("connection result after %s early data: %v", status, err)
				}
				assertQUICReleased(t, q)
				if q.doqParser != nil {
					t.Fatal("terminated connection retained DoQ parser")
				}
			})
		}
	}
}

func TestQUICCIDLimitsAndOutOfOrderRetirement(t *testing.T) {
	q, _ := newQUICOutputTest(t, types.DecryptOptions{})
	var adds, retires int
	q.SetConnectionIDHandler(func(_ []byte, _ bool, retire bool) ([]QUICRoutedPacket, error) {
		if retire {
			retires++
		} else {
			adds++
		}
		return nil, nil
	})
	if err := q.retireQUICCID(4, false); err != nil {
		t.Fatal(err)
	}
	if err := q.observeQUICCID(4, 0, []byte{4}, nil, false); err != nil {
		t.Fatal(err)
	}
	if adds != 0 {
		t.Fatal("reordered NEW resurrected retired CID")
	}
	for seq := uint64(5); seq < 1000; seq++ {
		cid := []byte{byte(seq >> 8), byte(seq)}
		if err := q.observeQUICCID(seq, seq, cid, nil, false); err != nil {
			t.Fatal(err)
		}
		if len(q.flow.cids[1]) != 1 {
			t.Fatal("retire_prior_to did not compact history")
		}
	}
	if retires != adds-1 {
		t.Fatal("CID index retirement missing")
	}
	before := adds
	if err := q.observeQUICCID(999, 0, []byte("conflict"), nil, false); err == nil || adds != before {
		t.Fatal("conflicting sequence installed")
	}
	bounded, _ := newQUICOutputTest(t, types.DecryptOptions{})
	for seq := uint64(0); seq < maxQUICConnectionIDs; seq++ {
		if err := bounded.observeQUICCID(seq, 0, []byte{byte(seq)}, nil, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := bounded.observeQUICCID(maxQUICConnectionIDs, 0, []byte{0xff}, nil, true); err == nil || bounded.flow.terminalErr == nil {
		t.Fatal("CID resource bound was not terminal")
	}
	if len(bounded.flow.cids[0]) != maxQUICConnectionIDs {
		t.Fatal("CID cap exceeded")
	}
}

func TestQUICQPACKWaitDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var diagnostics []types.Diagnostic
		q, _ := newQUICOutputTest(t, types.DecryptOptions{KeyWaitTimeout: 10 * time.Second, OnDiagnostic: func(d types.Diagnostic) { diagnostics = append(diagnostics, d) }})
		// Server SETTINGS: capacity 220, two blocked streams; client HEADERS waits
		// for two inserts. No key update, packet, or EOF is needed to enforce expiry.
		if err := q.feedQUICStream(3, 0, []byte{0, 4, 5, 1, 0x40, 220, 7, 2}, false, false, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := q.feedQUICStream(0, 0, []byte{1, 6, 3, 0x81, 0xd1, 0xd7, 0x10, 0x11}, true, true, time.Now()); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- q.Decrypt() }()
		synctest.Wait()
		time.Sleep(9 * time.Second)
		q.keyLog.AddSecret("CLIENT_TRAFFIC_SECRET_0", "aabb", []byte{1})
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("early exit: %v", err)
		default:
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if err := <-done; err == nil {
			t.Fatal("blocked QPACK succeeded")
		}
		if len(diagnostics) != 1 || diagnostics[0].Stage != "protocol" || diagnostics[0].Code != "parse_timeout" {
			t.Fatal(diagnostics)
		}
		assertQUICReleased(t, q)
	})
}

func TestQUICIdentityDeadlineDoesNotRenew(t *testing.T) {
	for _, mode := range []string{"partial_hello", "retry", "version_negotiation"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var diagnostics []types.Diagnostic
				q, _ := newQUICOutputTest(t, types.DecryptOptions{RawChunks: true, KeyWaitTimeout: 10 * time.Second,
					OnDiagnostic: func(d types.Diagnostic) { diagnostics = append(diagnostics, d) },
				})
				store := crypto.NewStreamingKeyLogStore(time.Minute)
				q.keyLog = store.NewConnectionScope()
				// A completed connection's secret is protected by this pending
				// worker until its absolute identity deadline, even with no keys
				// or encrypted application packets waiting in the QUIC queue.
				if _, err := fmt.Fprintln(store, "CLIENT_RANDOM aa 01"); err != nil {
					t.Fatal(err)
				}
				previous := store.NewConnectionScope()
				previous.GetSecrets([]byte{0xaa})
				previous.ReleaseKeyReferences()
				original := mustDecodeHex(t, "8394c8f03e515708")
				version := uint32(quicVersion1)
				if mode == "version_negotiation" {
					version = quicVersion2
				}
				key, _ := quicInitialKeys(version, original)
				initial := quicLongTestPacket(t, version, QUICPacketTypeInitial, original, nil, nil, key, 0, []byte{6, 0, 3, 1, 0, 0})
				if err := q.FeedClient(initial.data); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- q.Decrypt() }()
				defer func() { _ = q.Close(); synctest.Wait() }()
				synctest.Wait()
				if q.flow.clientCrypto.next != 3 || !q.flow.pendingSince.IsZero() || store.GetSecrets([]byte{0xaa}) == nil {
					t.Fatal("partial Initial did not retain discovery protection without a key wait")
				}
				time.Sleep(9 * time.Second)
				switch mode {
				case "retry":
					retry := mustDecodeHex(t, "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba")
					if err := q.FeedServer(retry); err != nil {
						t.Fatal(err)
					}
					synctest.Wait()
					if q.flow.handshake.retry == nil {
						t.Fatal("Retry was not observed")
					}
				case "version_negotiation":
					vn := append([]byte{0x80, 0, 0, 0, 0, 0, byte(len(original))}, original...)
					vn = append(vn, 0, 0, 0, 1)
					if err := q.FeedServer(vn); err != nil {
						t.Fatal(err)
					}
					key, _ = quicInitialKeys(quicVersion1, original)
					selected := quicLongTestPacket(t, quicVersion1, QUICPacketTypeInitial, original, nil, nil, key, 0, []byte{6, 0, 3, 1, 0, 0})
					if err := q.FeedClient(selected.data); err != nil {
						t.Fatal(err)
					}
					synctest.Wait()
					if q.version != quicVersion1 {
						t.Fatal("version switch was not authenticated")
					}
				default:
					if err := q.FeedClient(initial.data); err != nil {
						t.Fatal(err)
					}
				}
				// Duplicate unrelated DSBs also wake the worker but do not renew discovery.
				for i := 0; i < 2; i++ {
					if _, err := fmt.Fprintln(store, "CLIENT_RANDOM bb 02"); err != nil {
						t.Fatal(err)
					}
				}
				synctest.Wait()
				select {
				case err := <-done:
					t.Fatalf("exited before original deadline: %v", err)
				default:
				}
				time.Sleep(time.Second)
				synctest.Wait()
				if err := <-done; err == nil {
					t.Fatal("unidentified connection succeeded")
				}
				if len(diagnostics) != 1 || diagnostics[0].Stage != "handshake" || diagnostics[0].Code != "identity_timeout" {
					t.Fatal(diagnostics)
				}
				if store.GetSecrets([]byte{0xaa}) != nil {
					t.Fatal("expired discovery worker retained completed connection key")
				}
				assertQUICReleased(t, q)
			})
		})
	}
}

func TestQUICIdentityConfirmedWithoutServerInitial(t *testing.T) {
	for _, level := range []string{"handshake", "application", "identity_limit"} {
		t.Run(level, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var diagnostics []types.Diagnostic
				q, _ := newQUICOutputTest(t, types.DecryptOptions{RawChunks: true, KeyWaitTimeout: 10 * time.Second,
					OnDiagnostic: func(d types.Diagnostic) { diagnostics = append(diagnostics, d) },
				})
				store := crypto.NewStreamingKeyLogStore(time.Minute)
				q.keyLog = store.NewConnectionScope()
				if level == "identity_limit" {
					// Exercise the bounded scope's failure handshake at the actual
					// authenticated-packet transition, not just its return value.
					for i := 0; i < 9; i++ {
						q.keyLog.GetSecrets([]byte{byte(i)})
					}
				}
				client, _ := tlsUpgradeTestHellos(0x44)
				frame := append([]byte{6, 0, byte(len(client) - 5)}, client[5:]...)
				dcid := []byte("original")
				initialKey, _ := quicInitialKeys(quicVersion1, dcid)
				initial := quicLongTestPacket(t, quicVersion1, QUICPacketTypeInitial, dcid, nil, nil, initialKey, 0, frame)
				if err := q.FeedClient(initial.data); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- q.Decrypt() }()
				defer func() { _ = q.Close(); synctest.Wait() }()
				synctest.Wait()
				if !q.flow.clientHelloDone || q.identityResolved {
					t.Fatal("ClientHello did not enter unconfirmed identity state")
				}
				time.Sleep(9 * time.Second)
				random, secret := bytes.Repeat([]byte{0x44}, 32), bytes.Repeat([]byte{0x11}, 32)
				label := "SERVER_HANDSHAKE_TRAFFIC_SECRET"
				if level == "application" {
					label = "SERVER_TRAFFIC_SECRET_0"
				}
				if _, err := fmt.Fprintf(store, "%s %x %x\n", label, random, secret); err != nil {
					t.Fatal(err)
				}
				key, err := deriveQUICKeys(secret, quicVersion1, quicAES128)
				if err != nil {
					t.Fatal(err)
				}
				packet := quicLongTestPacket(t, quicVersion1, QUICPacketTypeHandshake, nil, nil, nil, key, 0, []byte{1, 0, 0}).data
				if level == "application" {
					packet = quicKeyPhasePacket(t, key, 0, 0, []byte{1, 0, 0}).data
				}
				if err := q.FeedServer(packet); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				if level == "identity_limit" {
					if err := <-done; err == nil {
						t.Fatal("identity overflow succeeded")
					}
					if len(diagnostics) != 1 || diagnostics[0].Stage != "keys" || diagnostics[0].Code != "resource_limit" {
						t.Fatal(diagnostics)
					}
				} else {
					if !q.identityResolved {
						t.Fatal("authenticated packet did not resolve identity without server Initial")
					}
					time.Sleep(2 * time.Minute)
					synctest.Wait()
					store.ReapUnusedKeys()
					if store.GetSecrets(random) == nil {
						t.Fatal("live identified connection lost its key after orphan retention expired")
					}
					select {
					case err := <-done:
						t.Fatalf("resolved identity still timed out: %v", err)
					default:
					}
					_ = q.Close()
					if err := <-done; err != nil {
						t.Fatal(err)
					}
					if store.GetSecrets(random) != nil || len(diagnostics) != 0 {
						t.Fatal("successful connection retained keys or reported failure")
					}
				}
				assertQUICReleased(t, q)
			})
		})
	}
}
