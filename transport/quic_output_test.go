// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package transport

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/gojue/ecapture_decryptor/crypto"
	"github.com/gojue/ecapture_decryptor/types"
)

func newQUICOutputTest(t *testing.T, options types.DecryptOptions) (*QUICDecryptor, chan *types.DecryptedPacket) {
	t.Helper()
	packets := make(chan *types.DecryptedPacket, 16)
	connection := types.ConnectionKey{
		SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"),
		SrcPort: 12345, DstPort: 443, Proto: types.TransportProtocolUDP, Generation: 1,
	}
	q := NewQUICDecryptor(connection, crypto.NewKeyLogStore(), log.New(io.Discard, "", 0), io.Discard, packets).(*QUICDecryptor)
	q.SetOptions(options)
	return q, packets
}

func TestQUICRawChunksReassembleWithoutDuplicates(t *testing.T) {
	q, packets := newQUICOutputTest(t, types.DecryptOptions{RawChunks: true})
	if q.http3Parser != nil {
		t.Fatal("raw output also enabled the HTTP/3 parser")
	}
	at := time.Unix(123, 456)
	// STREAM 4: a FIN-bearing suffix arrives before the prefix. Neither payload
	// is HTTP/3; the raw mode must preserve the binary bytes and stream offsets.
	suffix := []byte{0x0f, 4, 3, 3, 0xff, 0x00, 0xfe}
	prefix := []byte{0x0e, 4, 0, 3, 'a', 'b', 'c'}
	if err := q.parseQUICFrames(suffix, quicLevelApplication, true, at); err != nil {
		t.Fatal(err)
	}
	if len(packets) != 0 {
		t.Fatal("emitted bytes before the stream gap was filled")
	}
	for _, frame := range [][]byte{prefix, suffix, prefix} {
		if err := q.parseQUICFrames(frame, quicLevelApplication, true, at); err != nil {
			t.Fatal(err)
		}
	}
	prefix[4], suffix[4] = 'x', 'x'
	if len(packets) != 2 {
		t.Fatalf("emitted %d chunks, want two without retransmission duplicates", len(packets))
	}
	for i, want := range [][]byte{[]byte("abc"), {0xff, 0x00, 0xfe}} {
		packet := <-packets
		if packet.Protocol != "quic" || packet.Transport != "udp" || packet.Direction != "request" ||
			!bytes.Equal(packet.Data, want) || !packet.Timestamp.Equal(at) ||
			packet.ConnectionID() != q.connectionInfo.String() || packet.SrcIP != "192.0.2.1" {
			t.Fatalf("incorrect raw packet: protocol=%s transport=%s direction=%s data=%x", packet.Protocol, packet.Transport, packet.Direction, packet.Data)
		}
		metadata := map[string]interface{}{
			"kind": "stream_chunk", "stream_id": uint64(4), "offset": uint64(i * 3), "end": i == 1,
		}
		if !reflect.DeepEqual(packet.Metadata, metadata) {
			t.Fatalf("metadata = %v, want %v", packet.Metadata, metadata)
		}
	}
}

func TestQUICRawFINOnlyAndUnidirectionalStreams(t *testing.T) {
	q, packets := newQUICOutputTest(t, types.DecryptOptions{RawChunks: true})
	at := time.Unix(123, 0)
	// Server-initiated unidirectional streams are valid raw output even though
	// the HTTP/3 request parser intentionally ignores them.
	frames := [][]byte{
		{0x0e, 3, 0, 2, 0x00, 0xff},
		{0x0f, 3, 2, 0},
		{0x0f, 3, 2, 0}, // Duplicate FIN must not repeat the end event.
		{0x0f, 7, 0, 0}, // An entirely empty stream still has an end event.
	}
	for _, frame := range frames {
		if err := q.parseQUICFrames(frame, quicLevelApplication, false, at); err != nil {
			t.Fatal(err)
		}
	}
	if len(packets) != 3 {
		t.Fatalf("emitted %d events, want chunk and two stream ends", len(packets))
	}
	chunk := <-packets
	if !bytes.Equal(chunk.Data, []byte{0, 0xff}) || chunk.Metadata["end"] != false ||
		chunk.Direction != "response" || chunk.SrcIP != "192.0.2.2" || chunk.DstPort != 12345 {
		t.Fatalf("incorrect reverse-direction chunk: %+v", chunk)
	}
	for _, want := range []struct{ id, offset uint64 }{{3, 2}, {7, 0}} {
		packet := <-packets
		if len(packet.Data) != 0 || packet.DataLength != 0 || packet.Metadata["kind"] != "stream_end" ||
			packet.Metadata["end"] != true || packet.Metadata["stream_id"] != want.id || packet.Metadata["offset"] != want.offset {
			t.Fatalf("incorrect FIN-only event: %+v", packet)
		}
	}
}

func TestQUICDiagnosticsPreserveErrorsWithoutPayload(t *testing.T) {
	at := time.Unix(123, 0)
	for _, test := range []struct {
		name, stage, code string
		run               func(*QUICDecryptor) error
	}{
		{"packet", "input", "invalid_packet", func(q *QUICDecryptor) error {
			q.processQUICDatagram(quicDatagram{data: []byte{0xc0}, at: at})
			return errors.Join(q.flow.errors...)
		}},
		{"version", "decrypt", "unsupported_version", func(q *QUICDecryptor) error {
			_, err := q.processQUICPacket(quicPacket{long: true, version: 0x12345678}, true, at)
			return err
		}},
		{"authentication", "decrypt", "authentication_failed", func(q *QUICDecryptor) error {
			keys, err := deriveQUICKeys(make([]byte, 32), quicVersion1, quicAES128)
			if err != nil {
				return err
			}
			q.flow.keys[0][quicLevelApplication] = []*QUICKeys{keys}
			_, err = q.processQUICPacket(quicPacket{data: append([]byte{0x40}, bytes.Repeat([]byte{0x7f}, 40)...)}, true, at)
			return err
		}},
		{"frame", "protocol", "invalid_frame", func(q *QUICDecryptor) error {
			return q.parseQUICFrames([]byte{0x0a, 0, 3, 1}, quicLevelApplication, true, at)
		}},
		{"unsupported_frame", "protocol", "unsupported_frame", func(q *QUICDecryptor) error {
			return q.parseQUICFrames([]byte{0x1f}, quicLevelApplication, true, at)
		}},
		{"limit", "reassembly", "resource_limit", func(q *QUICDecryptor) error {
			return q.feedQUICStream(0, maxQUICStreamBytes+1, nil, false, true, at)
		}},
		{"conflicting_fin", "reassembly", "invalid_stream", func(q *QUICDecryptor) error {
			if err := q.feedQUICStream(0, 4, nil, true, true, at); err != nil {
				return err
			}
			return q.feedQUICStream(0, 5, nil, true, true, at)
		}},
		{"parser", "protocol", "parse_failed", func(q *QUICDecryptor) error {
			return q.feedQUICStream(0, 0, []byte{1, 1, 0xff}, true, true, at)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var diagnostics []types.Diagnostic
			q, packets := newQUICOutputTest(t, types.DecryptOptions{OnDiagnostic: func(d types.Diagnostic) {
				diagnostics = append(diagnostics, d)
			}})
			if err := test.run(q); err == nil {
				t.Fatal("failure lost its original error")
			}
			want := []types.Diagnostic{{ConnectionID: q.connectionInfo.String(), Transport: "udp", Stage: test.stage, Code: test.code}}
			if !reflect.DeepEqual(diagnostics, want) {
				t.Fatalf("diagnostics = %+v, want %+v", diagnostics, want)
			}
			if len(packets) != 0 {
				t.Fatal("failed input emitted application data")
			}
		})
	}
}

func TestQUICMissingSecretsDiagnosedOnClose(t *testing.T) {
	for _, haveClientHello := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing_client_hello", true: "missing_secret"}[haveClientHello], func(t *testing.T) {
			var diagnostics []types.Diagnostic
			q, _ := newQUICOutputTest(t, types.DecryptOptions{OnDiagnostic: func(d types.Diagnostic) {
				diagnostics = append(diagnostics, d)
			}})
			if haveClientHello {
				q.flow.clientRandom = make([]byte, 32)
			}
			q.processQUICDatagram(quicDatagram{data: []byte{0x40}})
			if len(diagnostics) != 0 {
				t.Fatal("waiting for a key was reported as a failure before close")
			}
			if err := q.Close(); err != nil {
				t.Fatal(err)
			}
			if err := q.Decrypt(); err == nil {
				t.Fatal("missing key did not preserve the close error")
			}
			stage, code := "handshake", "missing_client_hello"
			if haveClientHello {
				stage, code = "keys", "missing_secret"
			}
			want := []types.Diagnostic{{ConnectionID: q.connectionInfo.String(), Transport: "udp", Stage: stage, Code: code}}
			if !reflect.DeepEqual(diagnostics, want) {
				t.Fatalf("diagnostics = %+v, want %+v", diagnostics, want)
			}
		})
	}
}

func TestQUICRawIncompleteStreamDiagnosticOnClose(t *testing.T) {
	for _, test := range []struct {
		name       string
		offset     uint64
		data       []byte
		fin        bool
		incomplete bool
	}{
		{"open_contiguous_stream", 0, []byte{1, 2}, false, false},
		{"complete_stream", 0, []byte{1, 2}, true, false},
		{"gap_without_fin", 3, []byte{1, 2}, false, true},
		{"fin_with_missing_bytes", 3, nil, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var diagnostics []types.Diagnostic
			q, _ := newQUICOutputTest(t, types.DecryptOptions{RawChunks: true, OnDiagnostic: func(d types.Diagnostic) {
				diagnostics = append(diagnostics, d)
			}})
			if err := q.feedQUICStream(0, test.offset, test.data, test.fin, true, time.Unix(123, 0)); err != nil {
				t.Fatal(err)
			}
			if len(diagnostics) != 0 {
				t.Fatal("a gap was reported before remaining input could fill it")
			}
			if err := q.Close(); err != nil {
				t.Fatal(err)
			}
			if err := q.Decrypt(); (err != nil) != test.incomplete {
				t.Fatalf("close error = %v, want incomplete=%t", err, test.incomplete)
			}
			var want []types.Diagnostic
			if test.incomplete {
				want = []types.Diagnostic{{ConnectionID: q.connectionInfo.String(), Transport: "udp", Stage: "reassembly", Code: "incomplete_stream"}}
			}
			if !reflect.DeepEqual(diagnostics, want) {
				t.Fatalf("diagnostics = %+v, want %+v", diagnostics, want)
			}
		})
	}
}

func TestQUICEarlyDataAcceptanceAndReplay(t *testing.T) {
	for _, raw := range []bool{false, true} {
		for _, status := range []string{"accepted", "rejected", "unknown"} {
			t.Run(fmt.Sprintf("raw=%v/%s", raw, status), func(t *testing.T) {
				q, out := newQUICOutputTest(t, types.DecryptOptions{RawChunks: raw})
				// A literal/static QPACK GET request, duplicated across encryption levels.
				data := []byte{1, 5, 0, 0, 0xd1, 0xd7, 0xc1}
				frame := append([]byte{0x0f, 0, 0, byte(len(data))}, data...)
				if err := q.parseQUICFrames(frame, quicLevelEarly, true, time.Time{}); err != nil {
					t.Fatal(err)
				}
				if len(out) != 0 {
					t.Fatal("early data emitted before acceptance was known")
				}
				if status != "unknown" {
					ee := []byte{8, 0, 0, 2, 0, 0}
					if status == "accepted" {
						ee = []byte{8, 0, 0, 6, 0, 4, 0, 42, 0, 0}
					}
					// Deliberately reordered CRYPTO fragments.
					if err := q.observeServerCrypto(quicLevelHandshake, 3, ee[3:]); err != nil {
						t.Fatal(err)
					}
					if len(out) != 0 {
						t.Fatal("partial handshake confirmed early data")
					}
					if err := q.observeServerCrypto(quicLevelHandshake, 0, ee[:3]); err != nil {
						t.Fatal(err)
					}
				} else if err := q.finishQUICEarly(); err == nil {
					t.Fatal("unknown acceptance was not returned")
				}
				if err := q.parseQUICFrames(frame, quicLevelApplication, true, time.Time{}); err != nil {
					t.Fatal(err)
				}
				if err := q.parseQUICFrames(frame, quicLevelApplication, true, time.Time{}); err != nil {
					t.Fatal(err)
				}
				want := 1
				if raw && status != "accepted" {
					want = 2
				}
				if len(out) != want {
					t.Fatalf("outputs=%d want=%d", len(out), want)
				}
				if raw {
					p := <-out
					if p.Metadata["encryption_level"] != "0rtt" || p.Metadata["early_data"] != status || !bytes.Equal(p.Data, data) {
						t.Fatalf("early metadata %v", p.Metadata)
					}
				}
			})
		}
	}
}

func TestQUICEarlyPacketNumberAndMissingSecret(t *testing.T) {
	for _, version := range []uint32{quicVersion1, quicVersion2} {
		q, out := newQUICOutputTest(t, types.DecryptOptions{RawChunks: true})
		q.version = version
		key, _ := deriveQUICKeys(bytes.Repeat([]byte{7}, 32), version, quicAES128)
		q.flow.keys[0][quicLevelEarly] = []*QUICKeys{key}
		q.flow.keys[0][quicLevelApplication] = []*QUICKeys{key}
		q.flow.early.status = "accepted"
		early := quicLongTestPacket(t, version, QUICPacketType0RTT, nil, nil, nil, key, 255, []byte{0x0e, 0, 0, 3, 'a', 'b', 'c'})
		if _, err := q.processQUICPacket(early, true, time.Time{}); err != nil {
			t.Fatal(err)
		}
		later := quicKeyPhasePacket(t, key, 256, 0, []byte{0x0f, 0, 3, 3, 'd', 'e', 'f'})
		if _, err := q.processQUICPacket(later, true, time.Time{}); err != nil {
			t.Fatal(err)
		}
		if q.flow.largest[0][quicLevelApplication] != 256 || len(out) != 2 {
			t.Fatal("0/1-RTT did not share PN space")
		}
		rejected, _ := newQUICOutputTest(t, types.DecryptOptions{})
		rejected.version = version
		rejected.flow.early.status = "rejected"
		rejected.flow.keys[0][quicLevelEarly] = []*QUICKeys{key}
		rejected.flow.keys[0][quicLevelApplication] = []*QUICKeys{key}
		if _, err := rejected.processQUICPacket(early, true, time.Time{}); err != nil {
			t.Fatal(err)
		}
		ping := quicKeyPhasePacket(t, key, 256, 0, []byte{1, 0, 0})
		if _, err := rejected.processQUICPacket(ping, true, time.Time{}); err != nil || rejected.flow.largest[0][quicLevelApplication] != 256 {
			t.Fatal("rejected authenticated 0-RTT did not advance shared PN", err)
		}
		missing, _ := newQUICOutputTest(t, types.DecryptOptions{})
		missing.version = version
		if pending, err := missing.processQUICPacket(early, true, time.Time{}); err != nil || !pending {
			t.Fatal("missing early key was not deferred")
		}
		missing.flow.early.status = "rejected"
		if pending, err := missing.processQUICPacket(early, true, time.Time{}); err != nil || pending {
			t.Fatal("rejected early ciphertext blocked replay")
		}
	}
}

func TestQUICRejectedEarlyWithoutSecretClearsPending(t *testing.T) {
	q, _ := newQUICOutputTest(t, types.DecryptOptions{})
	q.version = quicVersion1
	key, _ := deriveQUICKeys(bytes.Repeat([]byte{5}, 32), quicVersion1, quicAES128)
	early := quicLongTestPacket(t, quicVersion1, QUICPacketType0RTT, nil, nil, nil, key, 0, []byte{0x0b, 0, 3, 'a', 'b', 'c'})
	q.processQUICDatagram(quicDatagram{data: early.data, isClient: true})
	if len(q.flow.pending) != 1 {
		t.Fatal("missing secret was not queued")
	}
	if err := q.observeServerCrypto(quicLevelHandshake, 0, []byte{8, 0, 0, 2, 0, 0}); err != nil {
		t.Fatal(err)
	}
	q.retryQUICPacketsWithNewKeys()
	if len(q.flow.pending) != 0 || !q.flow.pendingSince.IsZero() {
		t.Fatal("rejected early data still requires a secret")
	}
}

func TestQUICRejectedEarlyAtEOF(t *testing.T) {
	q, _ := newQUICOutputTest(t, types.DecryptOptions{})
	q.version = quicVersion1
	key, _ := deriveQUICKeys(bytes.Repeat([]byte{5}, 32), quicVersion1, quicAES128)
	early := quicLongTestPacket(t, quicVersion1, QUICPacketType0RTT, nil, nil, nil, key, 0, []byte{0x0b, 0, 3, 'a', 'b', 'c'})
	handshake := quicLongTestPacket(t, quicVersion1, QUICPacketTypeHandshake, nil, nil, nil, key, 0, []byte{6, 0, 6, 8, 0, 0, 2, 0, 0})
	q.processQUICDatagram(quicDatagram{data: early.data, isClient: true})
	q.processQUICDatagram(quicDatagram{data: handshake.data})
	if len(q.flow.pending) != 2 {
		t.Fatal("setup did not defer early data and handshake")
	}
	q.flow.keys[1][quicLevelHandshake] = []*QUICKeys{key}
	_ = q.Close()
	if err := q.Decrypt(); err != nil {
		t.Fatal("rejected early data still required secret at EOF", err)
	}
	assertQUICReleased(t, q)
}

func TestQUICRejectedRawGapAtEOF(t *testing.T) {
	q, out := newQUICOutputTest(t, types.DecryptOptions{RawChunks: true})
	q.flow.early.status = "rejected"
	if err := q.feedQUICEarly(0, 3, []byte("suffix"), true, time.Time{}); err != nil {
		t.Fatal(err)
	}
	_ = q.Close()
	if err := q.Decrypt(); err == nil {
		t.Fatal("rejected raw gap silently discarded")
	}
	if len(out) != 0 {
		t.Fatal("non-contiguous early raw bytes emitted")
	}
	assertQUICReleased(t, q)
}

func TestQUICResetReleasesBuffersAndValidatesFinalSize(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprint(raw), func(t *testing.T) {
			q, out := newQUICOutputTest(t, types.DecryptOptions{RawChunks: raw})
			at := time.Now()
			// A gap is allowed when RESET supplies the final size; it must not retain
			// pending bytes or fabricate a complete HTTP response at EOF.
			if err := q.feedQUICStream(0, 3, []byte("tail"), false, false, at); err != nil {
				t.Fatal(err)
			}
			reset := []byte{4, 0, 0x41, 0x0c, 7}
			for i := 0; i < 2; i++ {
				if err := q.parseQUICFrames(reset, quicLevelApplication, false, at); err != nil {
					t.Fatal(err)
				}
			}
			s := q.flow.streams[quicStreamKey{id: 0, isClient: false}]
			if !s.finished || s.pendingBytes != 0 || s.pending != nil {
				t.Fatal("reset retained buffered stream")
			}
			if raw {
				if len(out) != 1 {
					t.Fatal("reset missing or repeated")
				}
				p := <-out
				if p.Metadata["kind"] != "stream_reset" || p.Metadata["offset"] != uint64(7) || p.Metadata["error_code"] != uint64(0x10c) || p.Metadata["end"] != true || len(p.Data) != 0 {
					t.Fatal(p.Metadata)
				}
			} else if len(out) != 0 {
				t.Fatal("reset emitted incomplete HTTP message")
			}
			if err := q.Close(); err != nil {
				t.Fatal(err)
			}
			if err := q.Decrypt(); err != nil {
				t.Fatal(err)
			}
		})
	}
	q, _ := newQUICOutputTest(t, types.DecryptOptions{RawChunks: true})
	if err := q.feedQUICStream(0, 5, []byte("tail"), false, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := q.resetQUICStream(0, 8, 0, true, time.Now()); err == nil {
		t.Fatal("reset before already received tail accepted")
	}
}

func TestQUICEarlyResetUsesAcceptanceSpace(t *testing.T) {
	for _, status := range []string{"accepted", "rejected"} {
		for _, raw := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/raw=%v", status, raw), func(t *testing.T) {
				q, out := newQUICOutputTest(t, types.DecryptOptions{RawChunks: raw})
				if err := q.parseQUICFrames([]byte{4, 0, 0x41, 0x0c, 0}, quicLevelEarly, true, time.Now()); err != nil {
					t.Fatal(err)
				}
				if len(out) != 0 {
					t.Fatal("early reset before acceptance")
				}
				q.flow.early.status = status
				if err := q.flushQUICEarly(); err != nil {
					t.Fatal(err)
				}
				key := quicStreamKey{id: 0, isClient: true}
				if (q.flow.streams[key] != nil) != (status == "accepted") {
					t.Fatal("early reset used wrong stream space")
				}
				if raw {
					if len(out) != 1 {
						t.Fatal("missing raw reset")
					}
					packet := <-out
					if packet.Metadata["early_data"] != status || packet.Metadata["encryption_level"] != "0rtt" {
						t.Fatal(packet.Metadata)
					}
				} else if len(out) != 0 {
					t.Fatal("early reset emitted message")
				}
			})
		}
	}
}

func TestQUICResetFinalSizeAndDirection(t *testing.T) {
	for _, pending := range []bool{false, true} {
		var stream quicStreamAssembler
		offset := uint64(0)
		if pending {
			offset = 3
		}
		if _, _, err := stream.push(offset, []byte("tail"), false); err != nil {
			t.Fatal(err)
		}
		if _, _, err := stream.push(0, nil, true); err == nil {
			t.Fatal("FIN truncated previously received bytes")
		}
	}
	var diagnostics []types.Diagnostic
	q, _ := newQUICOutputTest(t, types.DecryptOptions{RawChunks: true, OnDiagnostic: func(d types.Diagnostic) { diagnostics = append(diagnostics, d) }})
	if err := q.resetQUICStream(2, 0, 0, false, time.Now()); err == nil {
		t.Fatal("server reset client's unidirectional stream")
	}
	if len(diagnostics) != 1 || diagnostics[0].Stage != "reassembly" || diagnostics[0].Code != "invalid_stream" {
		t.Fatal(diagnostics)
	}
}

func TestQUICRawLongOffsetsAndPendingBounds(t *testing.T) {
	q, out := newQUICOutputTest(t, types.DecryptOptions{RawChunks: true})
	block := make([]byte, 32<<10)
	const total = 17<<20 + 37
	for pos := 0; pos < total; {
		n := min(len(block), total-pos)
		for i := range block[:n] {
			block[i] = byte((pos + i) % 251)
		}
		if err := q.feedQUICStream(4, uint64(pos), block[:n], pos+n == total, true, time.Now()); err != nil {
			t.Fatal(err)
		}
		p := <-out
		if p.Metadata["offset"] != uint64(pos) || p.Metadata["end"] != (pos+n == total) || !bytes.Equal(p.Data, block[:n]) {
			t.Fatal(pos, p.Metadata)
		}
		pos += n
	}
	if err := q.feedQUICStream(4, total-2, block[:2], true, true, time.Now()); err != nil || len(out) != 0 {
		t.Fatal("retransmission after long FIN", err)
	}
	if err := q.feedQUICStream(8, 1<<62, nil, false, true, time.Now()); !errors.Is(err, errQUICStreamLimit) {
		t.Fatal(err)
	}
	q, _ = newQUICOutputTest(t, types.DecryptOptions{RawChunks: true})
	gap := make([]byte, 1<<20)
	for id := 0; id < 32; id++ {
		if err := q.feedQUICStream(uint64(id*4), 1<<30, gap, false, true, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.feedQUICStream(128, 1<<30, []byte{0}, false, true, time.Now()); !errors.Is(err, errQUICBufferLimit) {
		t.Fatal("aggregate out-of-order storage", err)
	}
}

func TestQUICApplicationSelectionAndALPN(t *testing.T) {
	q, _ := newQUICOutputTest(t, types.DecryptOptions{TLSUpgrade: "smtp"})
	if err := q.Decrypt(); err == nil {
		t.Fatal("TCP upgrade accepted on QUIC")
	}
	assertQUICReleased(t, q)

	for _, tc := range []struct {
		selected, alpn string
		raw, valid     bool
	}{
		{"doq", "doq", false, true}, {"doq", "h3", false, false}, {"", "doq", false, false}, {"doh", "h3", false, true}, {"", "other", false, false}, {"", "other", true, true},
	} {
		q := NewQUICDecryptor(types.ConnectionKey{}, crypto.NewKeyLogStore(), log.New(io.Discard, "", 0), nil, make(chan *types.DecryptedPacket, 4)).(*QUICDecryptor)
		q.SetOptions(types.DecryptOptions{ApplicationProtocol: tc.selected, RawChunks: tc.raw})
		if err := q.checkApplicationALPN(tc.alpn); (err == nil) != tc.valid {
			t.Fatalf("%+v: %v", tc, err)
		}
		if tc.selected == "doq" && (q.doqParser == nil || q.http3Parser != nil) {
			t.Fatal("DoQ routed into HTTP/3")
		}
	}
}
