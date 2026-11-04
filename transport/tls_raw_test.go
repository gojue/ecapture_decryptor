// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package transport

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/gojue/ecapture_decryptor/crypto"
	"github.com/gojue/ecapture_decryptor/types"
	"golang.org/x/crypto/hkdf"
)

func newTLSRawTest(options types.DecryptOptions) (*TLSDecryptor, chan *types.DecryptedPacket) {
	packets := make(chan *types.DecryptedPacket, 16)
	connection := types.ConnectionKey{
		SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"),
		SrcPort: 12345, DstPort: 443, Proto: types.TransportProtocolTCP, Generation: 1,
	}
	decryptor := NewTLSDecryptor(connection, crypto.NewKeyLogStore(), io.Discard, io.Discard, log.New(io.Discard, "", 0), packets)
	decryptor.SetOptions(options)
	return decryptor, packets
}

func TestTLSRawChunksPreserveBinaryAndServerFirst(t *testing.T) {
	decryptor, packets := newTLSRawTest(types.DecryptOptions{RawChunks: true})
	at := time.Unix(123, 456)
	decryptor.SetPacketTime(at)
	serverData := []byte{0xff, 0, 0x80}
	decryptor.queueResponse(serverData)
	if len(packets) != 1 {
		t.Fatal("server-first bytes waited for a client request")
	}
	decryptor.queueRequest([]byte{0, 1})
	decryptor.queueResponse([]byte{2})
	decryptor.queueRequest([]byte{3, 0xff})
	serverData[0] = 0
	if decryptor.parser != nil {
		t.Fatal("raw output also selected an application parser")
	}
	for _, want := range []struct {
		direction string
		data      []byte
		offset    uint64
	}{
		{"response", []byte{0xff, 0, 0x80}, 0},
		{"request", []byte{0, 1}, 0},
		{"response", []byte{2}, 3},
		{"request", []byte{3, 0xff}, 2},
	} {
		packet := <-packets
		if packet.Protocol != "tls" || packet.Transport != "tcp" || packet.Direction != want.direction ||
			!bytes.Equal(packet.Data, want.data) || packet.DataLength != uint32(len(want.data)) ||
			packet.ConnectionID() != decryptor.ConnectionInfo.String() || !packet.Timestamp.Equal(at) ||
			packet.Metadata["kind"] != "stream_chunk" || packet.Metadata["offset"] != want.offset || packet.Metadata["end"] != false {
			t.Fatalf("incorrect raw packet: %+v", packet)
		}
		if want.direction == "response" && (packet.SrcIP != "192.0.2.2" || packet.DstPort != 12345) {
			t.Fatalf("server-first tuple was not reversed: %+v", packet)
		}
	}
}

func TestTLSDefaultOptionsKeepHTTPMessages(t *testing.T) {
	decryptor, packets := newTLSRawTest(types.DecryptOptions{})
	decryptor.queueRequest([]byte("POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\nab"))
	if len(packets) != 0 {
		t.Fatal("default output emitted an incomplete HTTP message")
	}
	decryptor.queueRequest([]byte("cd"))
	if len(packets) != 1 {
		t.Fatalf("got %d packets, want one complete HTTP message", len(packets))
	}
	packet := <-packets
	if packet.Protocol != "http/1.1" || !bytes.HasSuffix(packet.Data, []byte("\r\n\r\nabcd")) || packet.Metadata["kind"] != nil {
		t.Fatalf("default HTTP output changed: %+v", packet)
	}
}

func TestTLSUnsupportedProtocolDiagnosticExcludesPayload(t *testing.T) {
	var diagnostics []types.Diagnostic
	decryptor, packets := newTLSRawTest(types.DecryptOptions{OnDiagnostic: func(d types.Diagnostic) {
		diagnostics = append(diagnostics, d)
	}})
	payload := []byte("\x00\xffPRIVATE_APPLICATION_BYTES")
	decryptor.queueRequest(payload)
	if len(diagnostics) != 1 || diagnostics[0].Stage != "protocol" || diagnostics[0].Code != "unsupported_protocol" || len(packets) != 0 {
		t.Fatalf("unexpected unknown-protocol result: diagnostics=%+v packets=%d", diagnostics, len(packets))
	}
	encoded, err := json.Marshal(diagnostics)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("PRIVATE_APPLICATION_BYTES")) {
		t.Fatal("diagnostic leaked application bytes")
	}
}

func TestTLSRawApplicationSecretsDrainAndCloseOnce(t *testing.T) {
	diagnostics := make(chan types.Diagnostic, 16)
	decryptor, packets := newTLSRawTest(types.DecryptOptions{RawChunks: true, OnDiagnostic: func(d types.Diagnostic) {
		diagnostics <- d
	}})
	secret := bytes.Repeat([]byte{0x11}, 32)
	prepareTLS13RawHandshake(t, decryptor, secret)
	// A capture may contain encrypted handshake records but only application
	// secrets. Those records must not poison a subsequently authenticated stream.
	handshake := tls13RawTestRecord(t, bytes.Repeat([]byte{0x22}, 32), 0, []byte{0x14, 0, 0, 0}, 0x16)
	client := tls13RawTestRecord(t, secret, 0, []byte{0, 0xff, 'A'}, 0x17)
	server := tls13RawTestRecord(t, secret, 0, []byte{'B', 0}, 0x17)
	if err := decryptor.FeedClient(append(handshake, client...)); err != nil {
		t.Fatal(err)
	}
	if err := decryptor.FeedServer(append(handshake, server...)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- decryptor.Decrypt() }()
	closed := make(chan struct{})
	go func() {
		_ = decryptor.CloseClient()
		_ = decryptor.CloseServer()
		_ = decryptor.Close()
		_ = decryptor.Close()
		close(closed)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("application-only secrets rejected valid plaintext: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("raw EOF or concurrent close blocked")
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("close did not join record processing")
	}
	if len(packets) != 4 {
		t.Fatalf("got %d packets, want two chunks and exactly two stream ends", len(packets))
	}
	seen, ended := map[string]int{}, map[string]int{}
	wantData := map[string][]byte{"request": {0, 0xff, 'A'}, "response": {'B', 0}}
	for range 4 {
		packet := <-packets
		want, ok := wantData[packet.Direction]
		if !ok || ended[packet.Direction] != 0 {
			t.Fatalf("unexpected direction or event after stream end: %+v", packet)
		}
		if packet.Metadata["end"] == true {
			if len(packet.Data) != 0 || packet.Metadata["offset"] != uint64(len(want)) || packet.Metadata["kind"] != "stream_end" {
				t.Fatalf("incorrect stream end: %+v", packet)
			}
			ended[packet.Direction]++
		} else {
			if !bytes.Equal(packet.Data, want) || packet.Metadata["offset"] != uint64(0) {
				t.Fatalf("incorrect drained chunk: %+v", packet)
			}
			seen[packet.Direction]++
		}
	}
	for _, direction := range []string{"request", "response"} {
		if seen[direction] != 1 || ended[direction] != 1 {
			t.Fatalf("%s chunks=%d ends=%d, want one each", direction, seen[direction], ended[direction])
		}
	}
	close(diagnostics)
	for diagnostic := range diagnostics {
		if diagnostic.Code == "authentication_failed" {
			t.Fatal("missing handshake secrets were reported as corrupt application data")
		}
	}
}

func TestTLSMissingSecretDiagnosticUnblocksOnClose(t *testing.T) {
	diagnostics := make(chan types.Diagnostic, 8)
	decryptor, packets := newTLSRawTest(types.DecryptOptions{RawChunks: true, OnDiagnostic: func(d types.Diagnostic) {
		diagnostics <- d
	}})
	prepareTLS13RawHandshake(t, decryptor, nil)
	done := make(chan error, 1)
	go func() { done <- decryptor.Decrypt() }()
	select {
	case diagnostic := <-diagnostics:
		if diagnostic.Code != "waiting_secret" {
			t.Fatalf("first diagnostic = %+v", diagnostic)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("missing secret was not observable")
	}
	_ = decryptor.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("missing secrets returned success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close did not cancel the key wait")
	}
	if len(diagnostics) != 1 || (<-diagnostics).Code != "missing_secret" || len(packets) != 0 {
		t.Fatal("missing-secret flow emitted plaintext/end or lacked its terminal diagnostic")
	}
}

func TestTLSAuthenticationFailureAfterApplicationRecord(t *testing.T) {
	for _, raw := range []bool{false, true} {
		for _, empty := range []bool{false, true} {
			t.Run(fmt.Sprintf("raw_%t/empty_%t", raw, empty), func(t *testing.T) {
				diagnostics := make(chan types.Diagnostic, 8)
				decryptor, packets := newTLSRawTest(types.DecryptOptions{RawChunks: raw, OnDiagnostic: func(d types.Diagnostic) {
					diagnostics <- d
				}})
				secret := bytes.Repeat([]byte{0x11}, 32)
				prepareTLS13RawHandshake(t, decryptor, secret)
				valid := []byte("GET /valid HTTP/1.1\r\nHost: example.test\r\n\r\n")
				if empty {
					valid = nil
				}
				first := tls13RawTestRecord(t, secret, 0, valid, 0x17)
				bad := tls13RawTestRecord(t, secret, 1, []byte("GET /corrupt HTTP/1.1\r\nHost: private.test\r\n\r\n"), 0x17)
				bad[len(bad)-1] ^= 1 // Corrupt the authentication tag, preserving record framing.
				if err := decryptor.FeedClient(append(first, bad...)); err != nil {
					t.Fatal(err)
				}
				_ = decryptor.CloseClient()
				_ = decryptor.CloseServer()
				if err := decryptor.Decrypt(); err == nil {
					t.Fatal("authentication failure returned success")
				}
				if len(diagnostics) != 1 {
					t.Fatalf("got %d diagnostics, want one authentication failure", len(diagnostics))
				}
				if diagnostic := <-diagnostics; diagnostic.Stage != "decrypt" || diagnostic.Code != "authentication_failed" {
					t.Fatalf("authentication failure misclassified: %+v", diagnostic)
				}
				wantPackets := 1
				if empty {
					wantPackets = 0
				}
				if len(packets) != wantPackets {
					t.Fatalf("got %d packets, want %d authenticated messages without end markers", len(packets), wantPackets)
				}
				if wantPackets != 0 {
					packet := <-packets
					if !bytes.Equal(packet.Data, valid) || packet.Direction != "request" || packet.Metadata["end"] == true {
						t.Fatalf("corrupt data or terminal marker reached output: %+v", packet)
					}
					if raw && packet.Protocol != "tls" || !raw && packet.Protocol != "http/1.1" {
						t.Fatalf("output mode changed: %s", packet.Protocol)
					}
				}
			})
		}
	}
}

func TestTLSRawTruncatedRecordReportsIncompleteInput(t *testing.T) {
	for _, partial := range [][]byte{{0x17, 3}, {0x17, 3, 3, 0, 8, 1}} {
		t.Run(fmt.Sprintf("bytes_%d", len(partial)), func(t *testing.T) {
			diagnostics := make(chan types.Diagnostic, 8)
			decryptor, packets := newTLSRawTest(types.DecryptOptions{RawChunks: true, OnDiagnostic: func(d types.Diagnostic) {
				diagnostics <- d
			}})
			secret := bytes.Repeat([]byte{0x11}, 32)
			prepareTLS13RawHandshake(t, decryptor, secret)
			data := tls13RawTestRecord(t, secret, 0, []byte{0, 0xff}, 0x17)
			if err := decryptor.FeedClient(append(data, partial...)); err != nil {
				t.Fatal(err)
			}
			_ = decryptor.CloseClient()
			_ = decryptor.CloseServer()
			if err := decryptor.Decrypt(); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("truncated input returned %v", err)
			}
			if len(diagnostics) != 1 || (<-diagnostics).Code != "truncated_record" {
				t.Fatal("missing truncated-record diagnostic")
			}
			if len(packets) != 1 {
				t.Fatal("truncated input emitted end markers or lost authenticated bytes")
			}
			packet := <-packets
			if !bytes.Equal(packet.Data, []byte{0, 0xff}) || packet.Metadata["end"] != false {
				t.Fatalf("unexpected partial stream: %+v", packet)
			}
		})
	}
}

func TestTLSRawConcurrentFeedAndClose(t *testing.T) {
	decryptor, packets := newTLSRawTest(types.DecryptOptions{RawChunks: true})
	secret := bytes.Repeat([]byte{0x11}, 32)
	prepareTLS13RawHandshake(t, decryptor, secret)
	records := make([][]byte, 32)
	for i := range records {
		records[i] = tls13RawTestRecord(t, secret, uint64(i), []byte{byte(i)}, 0x17)
	}
	if err := decryptor.FeedClient(records[0]); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- decryptor.Decrypt() }()
	select {
	case <-packets: // The first authenticated chunk establishes inline processing.
	case <-time.After(2 * time.Second):
		t.Fatal("initial chunk did not arrive")
	}
	fed := make(chan error, 1)
	go func() {
		for _, record := range records[1:] {
			if err := decryptor.FeedClient(record); err != nil {
				fed <- err
				return
			}
		}
		fed <- nil
	}()
	go func() { _ = decryptor.Close() }()
	// Keep draining while Close joins the producer. Never infer a loss from bytes
	// fed after Close; instead require ordered bytes and no chunks after EOF.
	finished := make(chan error, 1)
	go func() {
		err := <-done
		if feedErr := <-fed; err == nil {
			err = feedErr
		}
		close(packets)
		finished <- err
	}()
	offsets := map[string]uint64{"request": 1}
	ended := map[string]bool{}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case packet, ok := <-packets:
			if !ok {
				if err := <-finished; err != nil || !ended["request"] || !ended["response"] {
					t.Fatalf("incomplete close: err=%v ended=%v", err, ended)
				}
				return
			}
			if ended[packet.Direction] || packet.Metadata["offset"] != offsets[packet.Direction] {
				t.Fatalf("raw ordering/EOF violation: %+v", packet)
			}
			offsets[packet.Direction] += uint64(len(packet.Data))
			ended[packet.Direction], _ = packet.Metadata["end"].(bool)
		case <-timer.C:
			t.Fatal("concurrent Feed/Close did not finish while output was drained")
		}
	}
}

func prepareTLS13RawHandshake(t *testing.T, decryptor *TLSDecryptor, secret []byte) {
	t.Helper()
	random := bytes.Repeat([]byte{0x44}, 32)
	clientHello := append([]byte{3, 3}, random...)
	clientHello = append(clientHello, 0, 0, 2, 0x13, 1, 1, 0, 0, 7, 0, 43, 0, 3, 2, 3, 4)
	serverHello := append([]byte{3, 3}, bytes.Repeat([]byte{0x55}, 32)...)
	serverHello = append(serverHello, 0, 0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4)
	for _, message := range []struct {
		kind byte
		body []byte
		feed func([]byte) error
	}{{1, clientHello, decryptor.FeedClient}, {2, serverHello, decryptor.FeedServer}} {
		header := []byte{0x16, 3, 3, 0, byte(4 + len(message.body)), message.kind, 0, 0, byte(len(message.body))}
		if err := message.feed(append(header, message.body...)); err != nil {
			t.Fatal(err)
		}
	}
	if secret != nil {
		keylog := fmt.Sprintf("CLIENT_TRAFFIC_SECRET_0 %x %x\nSERVER_TRAFFIC_SECRET_0 %x %x\n", random, secret, random, secret)
		if _, err := decryptor.keyLog.Write([]byte(keylog)); err != nil {
			t.Fatal(err)
		}
	}
}

// Construct an independent RFC 8446 AES-128-GCM record, without calling the
// production decryptor to derive the encryption key or record nonce.
func tls13RawTestRecord(t *testing.T, secret []byte, sequence uint64, data []byte, kind byte) []byte {
	t.Helper()
	expand := func(label string, size int) []byte {
		label = "tls13 " + label
		info := append([]byte{0, byte(size), byte(len(label))}, []byte(label)...)
		info = append(info, 0)
		value := make([]byte, size)
		if _, err := io.ReadFull(hkdf.Expand(sha256.New, secret, info), value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	block, err := aes.NewCipher(expand("key", 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := expand("iv", 12)
	binary.BigEndian.PutUint64(nonce[4:], binary.BigEndian.Uint64(nonce[4:])^sequence)
	plaintext := append(bytes.Clone(data), kind)
	header := []byte{0x17, 3, 3, 0, 0}
	binary.BigEndian.PutUint16(header[1:], tls.VersionTLS12)
	binary.BigEndian.PutUint16(header[3:], uint16(len(plaintext)+aead.Overhead()))
	return append(header, aead.Seal(nil, nonce, plaintext, header)...)
}
