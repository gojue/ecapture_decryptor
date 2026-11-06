// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package protocol

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/gojue/ecapture_decryptor/types"
)

const wsRequest = "GET /chat HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive, UpGrAdE\r\nUpgrade: WebSocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
const wsResponse = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"

func wsFrame(first byte, masked bool, data []byte) []byte {
	out := []byte{first, 0}
	n := len(data)
	switch {
	case n < 126:
		out[1] = byte(n)
	case n < 65536:
		out[1] = 126
		out = binary.BigEndian.AppendUint16(out, uint16(n))
	default:
		out[1] = 127
		out = binary.BigEndian.AppendUint64(out, uint64(n))
	}
	if masked {
		out[1] |= 128
		out = append(out, 1, 2, 3, 4)
	}
	for i, b := range data {
		if masked {
			b ^= byte(i%4 + 1)
		}
		out = append(out, b)
	}
	return out
}
func wsReady(t *testing.T, extension string) (*WebSocketStreamParser, chan *types.DecryptedPacket) {
	t.Helper()
	ch := make(chan *types.DecryptedPacket, 32)
	p := NewWebSocketStreamParser(types.ConnectionKey{}, ch)
	extra := ""
	if extension != "" {
		extra = "Sec-WebSocket-Extensions: " + extension + "\r\n"
	}
	p.FeedRequest([]byte(wsRequest + extra + "\r\n"))
	p.FeedResponse([]byte(wsResponse + extra + "\r\n"))
	if p.Err() != nil || !p.IsWebSocket() {
		t.Fatalf("handshake: %v", p.Err())
	}
	<-ch
	<-ch
	return p, ch
}
func TestWebSocketUpgradeFragmentationAndFallback(t *testing.T) {
	for _, firstResponse := range []bool{false, true} {
		ch := make(chan *types.DecryptedPacket, 8)
		parser, name := DetectProtocol([]byte("GET "), types.ConnectionKey{}, ch)
		if name != "HTTP/1.x" {
			t.Fatal(name)
		}
		resp := append([]byte(wsResponse+"\r\n"), wsFrame(0x81, false, []byte("server"))...)
		if firstResponse {
			parser.FeedResponse(resp)
		}
		for _, b := range []byte(wsRequest + "\r\n") {
			parser.FeedRequest([]byte{b})
		}
		parser.FeedRequest(wsFrame(0x81, true, []byte("client")))
		if !firstResponse {
			for _, b := range resp {
				parser.FeedResponse([]byte{b})
			}
		}
		parser.Flush()
		if err := parser.(*HTTPStreamParser).Err(); err != nil {
			t.Fatal(err)
		}
		if len(ch) != 4 {
			t.Fatalf("got %d packets", len(ch))
		}
		for i := 0; i < 2; i++ {
			if p := <-ch; p.Metadata["kind"] != "upgrade" {
				t.Fatal(p.Metadata)
			}
		}
		seen := map[string]string{}
		for len(ch) > 0 {
			p := <-ch
			seen[p.Direction] = string(p.Data)
		}
		if seen["request"] != "client" || seen["response"] != "server" {
			t.Fatal(seen)
		}
	}
	// A rejected upgrade remains ordinary HTTP and a later valid upgrade works.
	ch := make(chan *types.DecryptedPacket, 8)
	p := NewHTTPStreamParser(types.ConnectionKey{}, ch)
	p.FeedRequest([]byte(wsRequest + "\r\n"))
	p.FeedResponse([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno"))
	p.FeedRequest([]byte(wsRequest + "\r\n"))
	p.FeedResponse([]byte(wsResponse + "\r\n"))
	p.FeedResponse(wsFrame(0x81, false, []byte("after rejection")))
	p.Flush()
	if p.Err() != nil || len(ch) != 5 {
		t.Fatalf("fallback: %v, packets %d", p.Err(), len(ch))
	}
	if first := <-ch; first.Protocol != "http/1.1" {
		t.Fatal(first.Protocol)
	}
	// A prior keepalive request can precede the upgrade, including pipelining.
	ch = make(chan *types.DecryptedPacket, 8)
	p = NewHTTPStreamParser(types.ConnectionKey{}, ch)
	p.FeedRequest([]byte("GET / HTTP/1.1\r\nHost: test\r\n\r\n" + wsRequest + "\r\n"))
	p.FeedResponse([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" + wsResponse + "\r\n"))
	p.Flush()
	if p.Err() != nil || len(ch) != 4 {
		t.Fatalf("keepalive: %v, packets %d", p.Err(), len(ch))
	}
}
func TestWebSocketDuplexFragmentsControlsAndRelease(t *testing.T) {
	p, ch := wsReady(t, "")
	p.FeedRequest(wsFrame(0x01, true, []byte("cli")))
	p.FeedResponse(wsFrame(0x02, false, []byte{0, 1}))
	p.FeedResponse(wsFrame(0x89, false, []byte("ping")))
	p.FeedRequest(wsFrame(0x8a, true, []byte("ping")))
	p.FeedRequest(wsFrame(0x80, true, []byte("ent")))
	p.FeedResponse(wsFrame(0x80, false, []byte{2, 3}))
	for i, want := range []string{"ping", "ping", "client", string([]byte{0, 1, 2, 3})} {
		got := <-ch
		if string(got.Data) != want {
			t.Fatalf("packet %d: %q", i, got.Data)
		}
	}
	for i := 0; i < 2000; i++ {
		p.FeedRequest(wsFrame(0x81, true, []byte("bounded")))
		<-ch
	}
	for _, d := range p.sides {
		if len(d.message) != 0 || d.opcode != 0 {
			t.Fatal("retained completed message")
		}
	}
	p.FeedRequest(wsFrame(0x88, true, []byte{3, 232, 'b', 'y', 'e'}))
	p.FeedResponse(wsFrame(0x88, false, []byte{3, 232}))
	if got := <-ch; got.Metadata["close_code"] != uint16(1000) || got.Metadata["close_reason"] != "bye" {
		t.Fatal(got.Metadata)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestWebSocketRejectsMalformed(t *testing.T) {
	cases := map[string][]byte{
		"server mask":              wsFrame(0x81, true, []byte("x")),
		"continuation":             wsFrame(0x80, false, []byte("x")),
		"reserved opcode":          wsFrame(0x83, false, nil),
		"RSV2":                     wsFrame(0xa1, false, nil),
		"unnegotiated compression": wsFrame(0xc1, false, nil),
		"fragmented ping":          wsFrame(0x09, false, nil),
		"long ping":                wsFrame(0x89, false, make([]byte, 126)),
		"short close":              wsFrame(0x88, false, []byte{1}),
		"invalid close":            wsFrame(0x88, false, []byte{3, 237}),
		"invalid text":             wsFrame(0x81, false, []byte{255}),
		"nonminimal length":        {0x81, 126, 0, 1, 'a'},
		"integer overflow":         {0x82, 127, 255, 255, 255, 255, 255, 255, 255, 255},
		"oversize":                 {0x82, 127, 0, 0, 0, 0, 1, 0, 0, 1},
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			p, ch := wsReady(t, "")
			p.FeedResponse(data)
			if p.Err() == nil || len(ch) != 0 {
				t.Fatalf("accepted malformed frame: %v", p.Err())
			}
		})
	}
	p, _ := wsReady(t, "")
	p.FeedRequest(wsFrame(0x81, false, nil))
	if p.Err() == nil {
		t.Fatal("unmasked client accepted")
	}
	for _, change := range []struct{ old, new string }{
		{"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "wrong"}, {"Connection: Upgrade", "Connection: close"}, {"Upgrade: websocket", "Upgrade: other"},
	} {
		p := NewWebSocketStreamParser(types.ConnectionKey{}, nil)
		p.FeedRequest([]byte(wsRequest + "\r\n"))
		p.FeedResponse([]byte(strings.Replace(wsResponse, change.old, change.new, 1) + "\r\n"))
		if p.Err() == nil || p.IsWebSocket() {
			t.Fatal("invalid handshake accepted")
		}
	}
	for _, replacement := range []string{"Sec-WebSocket-Key: invalid", "Sec-WebSocket-Version: 12", "Connection: close"} {
		req := wsRequest
		key := strings.Split(replacement, ":")[0]
		lines := strings.Split(req, "\r\n")
		for i, l := range lines {
			if strings.HasPrefix(l, key+":") {
				lines[i] = replacement
			}
		}
		p := NewWebSocketStreamParser(types.ConnectionKey{}, nil)
		p.FeedRequest([]byte(strings.Join(lines, "\r\n") + "\r\n"))
		if p.Err() == nil {
			t.Fatal("invalid request accepted")
		}
	}
	p, _ = wsReady(t, "")
	p.FeedResponse(wsFrame(1, false, []byte("unfinished")))
	if err := p.Close(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
}
func TestWebSocketDeflateContexts(t *testing.T) {
	for _, noContext := range []bool{false, true} {
		ext := "permessage-deflate"
		if noContext {
			ext += "; client_no_context_takeover; server_no_context_takeover"
		}
		p, ch := wsReady(t, ext)
		for _, client := range []bool{true, false} {
			var compressed bytes.Buffer
			z, err := flate.NewWriter(&compressed, flate.BestCompression)
			if err != nil {
				t.Fatal(err)
			}
			text := bytes.Repeat([]byte("distinct direction dictionary "), 200)
			if !client {
				text = bytes.Repeat([]byte("server dictionary differs "), 200)
			}
			for i := 0; i < 3; i++ {
				compressed.Reset()
				if noContext {
					z.Reset(&compressed)
				}
				if _, err = z.Write(text); err != nil {
					t.Fatal(err)
				}
				if err = z.Flush(); err != nil {
					t.Fatal(err)
				}
				data := compressed.Bytes()[:compressed.Len()-4]
				split := len(data) / 2
				feed := p.FeedResponse
				if client {
					feed = p.FeedRequest
				}
				feed(wsFrame(0x41, client, data[:split]))
				feed(wsFrame(0x89, client, nil))
				feed(wsFrame(0x80, client, data[split:]))
				<-ch
				got := <-ch
				if !bytes.Equal(got.Data, text) || got.Metadata["compressed"] != true {
					t.Fatal("deflate mismatch")
				}
				if err := p.Err(); err != nil {
					t.Fatal(err)
				}
			}
			_ = z.Close()
		}
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
	}
	// RFC 7692 section 7.2.3.1 fixed independent vector, not our compressor.
	p, ch := wsReady(t, "permessage-deflate")
	p.FeedResponse(wsFrame(0xc1, false, []byte{0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00}))
	if p.Err() != nil {
		t.Fatal(p.Err())
	}
	if got := <-ch; string(got.Data) != "Hello" {
		t.Fatal(string(got.Data))
	}
	// Negotiation must match an offered alternative.
	for _, ext := range []string{"unknown", "permessage-deflate; client_max_window_bits=10", "permessage-deflate; server_no_context_takeover=1", "permessage-deflate; server_max_window_bits=7"} {
		p = NewWebSocketStreamParser(types.ConnectionKey{}, nil)
		p.FeedRequest([]byte(wsRequest + "Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n"))
		p.FeedResponse([]byte(wsResponse + "Sec-WebSocket-Extensions: " + ext + "\r\n\r\n"))
		if p.Err() == nil {
			t.Fatalf("accepted %s", ext)
		}
	}
	var buf bytes.Buffer
	z, _ := flate.NewWriter(&buf, flate.BestSpeed)
	_, _ = z.Write(bytes.Repeat([]byte{'x'}, maxHTTPMessageBytes+1))
	_ = z.Flush()
	p, _ = wsReady(t, "permessage-deflate")
	p.FeedResponse(wsFrame(0xc2, false, buf.Bytes()[:buf.Len()-4]))
	_ = z.Close()
	if !errors.Is(p.Err(), ErrHTTPEventLimit) {
		t.Fatalf("expansion bound: %v", p.Err())
	}
}
func TestWebSocketBackpressure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ch := make(chan *types.DecryptedPacket)
		p := NewHTTPStreamParser(types.ConnectionKey{}, ch)
		done := make(chan struct{})
		go func() {
			p.FeedRequest([]byte(wsRequest + "\r\n"))
			p.FeedResponse(append([]byte(wsResponse+"\r\n"), wsFrame(0x81, false, []byte("no loss"))...))
			close(done)
		}()
		for i := 0; i < 3; i++ {
			synctest.Wait()
			select {
			case <-done:
				t.Fatal("producer bypassed backpressure")
			default:
			}
			got := <-ch
			if i == 2 && string(got.Data) != "no loss" {
				t.Fatal("message lost")
			}
		}
		<-done
	})
}
func FuzzWebSocketFrames(f *testing.F) {
	f.Add([]byte{0x81, 1, 'a'})
	f.Add([]byte{0x82, 127, 255, 255, 255, 255, 255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			return
		}
		p := NewWebSocketStreamParser(types.ConnectionKey{}, nil)
		p.FeedRequest([]byte(wsRequest + "\r\n"))
		p.FeedResponse([]byte(wsResponse + "\r\n"))
		for len(data) > 0 {
			n := min(len(data), 7)
			p.FeedResponse(data[:n])
			data = data[n:]
		}
		_ = p.Close()
	})
}

func TestWebSocketRepeatedRejectionDoesNotRetainParsers(t *testing.T) {
	p := NewHTTPStreamParser(types.ConnectionKey{}, nil)
	for i := 0; i < 2000; i++ {
		p.FeedRequest([]byte(wsRequest + "\r\n"))
		p.FeedResponse([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
		if p.Err() != nil || p.websocket != nil || len(p.pendingReqs) != 0 {
			t.Fatal("rejected upgrade retained parser history")
		}
	}
}

func TestWebSocketFragmentAndHeaderBounds(t *testing.T) {
	p, ch := wsReady(t, "")
	p.FeedResponse(wsFrame(1, false, []byte{0xe4}))
	p.FeedResponse(wsFrame(0x80, false, []byte{0xb8, 0xad}))
	if p.Err() != nil {
		t.Fatal(p.Err())
	}
	if got := <-ch; string(got.Data) != "中" {
		t.Fatal(got.Data)
	}
	p.FeedRequest(wsFrame(2, true, make([]byte, maxHTTPMessageBytes)))
	p.FeedRequest(wsFrame(0x80, true, []byte{1}))
	if !errors.Is(p.Err(), ErrHTTPEventLimit) {
		t.Fatal("fragment total unbounded")
	}
	p = NewWebSocketStreamParser(types.ConnectionKey{}, nil)
	p.FeedRequest([]byte(wsRequest + "X-Fill: " + strings.Repeat("a", eventFieldLimit)))
	if !errors.Is(p.Err(), ErrHTTPEventLimit) {
		t.Fatal("handshake unbounded")
	}
}
