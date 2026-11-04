// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package transport

import (
	"bytes"
	"errors"
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
