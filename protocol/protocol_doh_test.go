// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package protocol

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gojue/ecapture_decryptor/types"
	"github.com/quic-go/qpack"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func dohTestWire(t *testing.T, name string, reply bool) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatal(err)
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: 9, Response: reply}, Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestDoHHTTPFramingAndAssociation(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		for _, get := range []bool{false, true} {
			t.Run(fmt.Sprintf("h%d/get=%t", version, get), func(t *testing.T) {
				out := make(chan *types.DecryptedPacket, 4)
				query := dohTestWire(t, "example.test.", false)
				answer := dohTestWire(t, "example.test.", true)
				method, path, body := "POST", "/dns-query", query
				if get {
					method = "GET"
					path += "?dns=" + base64.RawURLEncoding.EncodeToString(query)
					body = nil
				}
				switch version {
				case 1:
					p := NewHTTPStreamParser(types.ConnectionKey{}, out)
					p.EnableDNSOverHTTP()
					request := append([]byte(fmt.Sprintf("%s %s HTTP/1.1\r\nHost: test\r\nContent-Type: application/dns-message\r\nContent-Length: %d\r\n\r\n", method, path, len(body))), body...)
					response := append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: %d\r\n\r\n", len(answer))), answer...)
					// Response arrives before request framing completes.
					p.FeedResponse(response)
					for _, v := range request {
						p.FeedRequest([]byte{v})
					}
					p.Flush()
					if p.Err() != nil {
						t.Fatal(p.Err())
					}
				case 2:
					p := NewHTTP2StreamParser(types.ConnectionKey{}, out)
					p.EnableDNSOverHTTP()
					p.FeedRequest([]byte(http2.ClientPreface))
					var client, server bytes.Buffer
					cf, sf := http2.NewFramer(&client, nil), http2.NewFramer(&server, nil)
					if err := cf.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, BlockFragment: encodeHTTP2Headers(t, hpack.HeaderField{Name: ":method", Value: method}, hpack.HeaderField{Name: ":scheme", Value: "https"}, hpack.HeaderField{Name: ":authority", Value: "test"}, hpack.HeaderField{Name: ":path", Value: path}, hpack.HeaderField{Name: "content-type", Value: "application/dns-message"})}); err != nil {
						t.Fatal(err)
					}
					if err := cf.WriteData(1, true, body); err != nil {
						t.Fatal(err)
					}
					if err := sf.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, BlockFragment: encodeHTTP2Headers(t, hpack.HeaderField{Name: ":status", Value: "200"}, hpack.HeaderField{Name: "content-type", Value: "application/dns-message"})}); err != nil {
						t.Fatal(err)
					}
					if err := sf.WriteData(1, true, answer); err != nil {
						t.Fatal(err)
					}
					p.FeedResponse(server.Bytes())
					for _, v := range client.Bytes() {
						p.FeedRequest([]byte{v})
					}
					p.Flush()
					if p.Err() != nil {
						t.Fatal(p.Err())
					}
				case 3:
					p := NewHTTP3StreamParser(types.ConnectionKey{}, out)
					p.EnableDNSOverHTTP()
					request := append(http3TestFrame(1, encodeQPACKTestHeaders(t, qpack.HeaderField{Name: ":method", Value: method}, qpack.HeaderField{Name: ":scheme", Value: "https"}, qpack.HeaderField{Name: ":authority", Value: "test"}, qpack.HeaderField{Name: ":path", Value: path}, qpack.HeaderField{Name: "content-type", Value: "application/dns-message"})), http3TestFrame(0, body)...)
					response := append(http3TestFrame(1, encodeQPACKTestHeaders(t, qpack.HeaderField{Name: ":status", Value: "200"}, qpack.HeaderField{Name: "content-type", Value: "application/dns-message"})), http3TestFrame(0, answer)...)
					http3Feed(t, p, 0, false, response, true)
					for i, v := range request {
						http3Feed(t, p, 0, true, []byte{v}, i == len(request)-1)
					}
					if err := p.Close(); err != nil {
						t.Fatal(err)
					}
				}
				if len(out) != 2 {
					t.Fatalf("got %d outputs", len(out))
				}
				req, resp := <-out, <-out
				if req.Protocol != "dns" || req.Metadata["transport"] != "doh" || req.Direction != "request" || !bytes.Equal(req.Data, query) || !bytes.Equal(resp.Data, answer) || resp.Metadata["matched"] != true || resp.Metadata["request_id"] != req.Metadata["request_id"] {
					t.Fatal("incorrect DNS message correlation")
				}
			})
		}
	}
}
func TestDoHValidationLimitsAndReset(t *testing.T) {
	q := dohTestWire(t, "example.test.", false)
	for name, path := range map[string]string{"missing": "/dns-query", "duplicate": "/?dns=AA&dns=AA", "padding": "/?dns=AAAA=", "invalid": "/?dns=%ff", "short": "/?dns=AA", "noncanonical": "/?dns=AB"} {
		t.Run(name, func(t *testing.T) {
			p := NewHTTPStreamParser(types.ConnectionKey{}, nil)
			p.EnableDNSOverHTTP()
			p.FeedRequest([]byte("GET " + path + " HTTP/1.1\r\nHost: test\r\n\r\n"))
			p.Flush()
			if p.Err() == nil {
				t.Fatal("bad DoH GET accepted")
			}
		})
	}
	for _, media := range []string{"text/plain", "application/dns-json", "application/dns-message; charset=utf-8"} {
		p := NewHTTPStreamParser(types.ConnectionKey{}, nil)
		p.EnableDNSOverHTTP()
		p.FeedRequest(append([]byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: test\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n", media, len(q))), q...))
		if p.Err() == nil {
			t.Fatal("unsupported media accepted")
		}
	}
	out := newEventOutput(types.ConnectionKey{}, nil, 0)
	out.doh = newDNSHTTP()
	b, err := out.headers("http/2", 1, true, time.Time{}, http.Header{"Content-Type": {"application/dns-message"}}, map[string]any{"method": "POST", "path": "/"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.write(make([]byte, 65536)); !errors.Is(err, ErrHTTPEventLimit) {
		t.Fatalf("body limit: %v", err)
	}
	out.abort()
	if out.doh.bytes != 0 {
		t.Fatal("retained body")
	}
	p := NewHTTPStreamParser(types.ConnectionKey{}, nil)
	p.EnableDNSOverHTTP()
	p.FeedRequest(append([]byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: test\r\nContent-Type: application/dns-message\r\nContent-Length: %d\r\n\r\n", len(q))), q...))
	p.FinishHTTPEvents("reset")
	p.Flush()
	if p.Err() != nil || p.events.output.doh.bytes != 0 {
		t.Fatal("reset did not release pending query")
	}
}
func TestDoHBackpressureAndHTTPError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		out := make(chan *types.DecryptedPacket)
		p := NewHTTPStreamParser(types.ConnectionKey{}, out)
		p.EnableDNSOverHTTP()
		q := dohTestWire(t, "example.test.", false)
		done := make(chan struct{})
		go func() {
			p.FeedRequest([]byte("GET /?dns=" + base64.RawURLEncoding.EncodeToString(q) + " HTTP/1.1\r\nHost: test\r\n\r\n"))
			p.FeedResponse([]byte("HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n"))
			p.Flush()
			close(done)
		}()
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("no backpressure")
		default:
		}
		if req := <-out; !bytes.Equal(req.Data, q) {
			t.Fatal("query altered")
		}
		if resp := <-out; resp.Metadata["kind"] != "http_error" || len(resp.Data) != 0 || resp.Metadata["status"] != 503 {
			t.Fatal("HTTP error misread as DNS")
		}
		<-done
		if p.Err() != nil {
			t.Fatal(p.Err())
		}
	})
}

func dohHTTP2Message(t *testing.T, p *HTTP2StreamParser, id uint32, client bool, status, media string, body []byte) {
	t.Helper()
	fields := []hpack.HeaderField{{Name: ":status", Value: status}}
	if client {
		fields = []hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "test"}, {Name: ":path", Value: "/dns-query"}}
	}
	fields = append(fields, hpack.HeaderField{Name: "content-type", Value: media})
	var wire bytes.Buffer
	f := http2.NewFramer(&wire, nil)
	if err := f.WriteHeaders(http2.HeadersFrameParam{StreamID: id, EndHeaders: true, BlockFragment: encodeHTTP2Headers(t, fields...)}); err != nil {
		t.Fatal(err)
	}
	if err := f.WriteData(id, true, body); err != nil {
		t.Fatal(err)
	}
	if client {
		p.FeedRequest(wire.Bytes())
	} else {
		p.FeedResponse(wire.Bytes())
	}
}
func TestDoHHTTP2ErrorBeforeRequestCleanup(t *testing.T) {
	query := dohTestWire(t, "error.test.", false)
	for _, serverFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(serverFirst), func(t *testing.T) {
			out := make(chan *types.DecryptedPacket, 4)
			p := NewHTTP2StreamParser(types.ConnectionKey{}, out)
			p.EnableDNSOverHTTP()
			p.FeedRequest([]byte(http2.ClientPreface))
			if !serverFirst {
				dohHTTP2Message(t, p, 1, true, "", "application/dns-message", query)
			}
			// A proxy's non-DNS failure body must not activate gRPC envelope/status rules.
			dohHTTP2Message(t, p, 1, false, "503", "application/grpc", []byte("not a gRPC message"))
			if serverFirst {
				if len(out) != 0 {
					t.Fatal("server-first error lost its request association")
				}
				dohHTTP2Message(t, p, 1, true, "", "application/dns-message", query)
			}
			if err := p.Err(); err != nil {
				t.Fatal(err)
			}
			if p.events.output.incompleteDoH() || p.events.output.doh.bytes != 0 {
				t.Fatal("completed HTTP failure retained DNS state")
			}
			p.Flush()
			p.Flush()
			if err := p.Err(); err != nil {
				t.Fatal(err)
			}
			if len(out) != 2 {
				t.Fatalf("got %d outputs", len(out))
			}
			req, resp := <-out, <-out
			if !bytes.Equal(req.Data, query) || resp.Metadata["kind"] != "http_error" || resp.Metadata["status"] != 503 || len(resp.Data) != 0 || req.Metadata["request_id"] != resp.Metadata["request_id"] {
				t.Fatal("HTTP failure correlation changed")
			}
		})
	}
}
func TestDoHUnmatchedCompletedResponseAtEOF(t *testing.T) {
	answer := dohTestWire(t, "unmatched.test.", true)
	for _, version := range []int{2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			out := make(chan *types.DecryptedPacket, 2)
			if version == 2 {
				p := NewHTTP2StreamParser(types.ConnectionKey{}, out)
				p.EnableDNSOverHTTP()
				p.FeedRequest([]byte(http2.ClientPreface))
				dohHTTP2Message(t, p, 1, false, "200", "application/dns-message", answer)
				if p.Err() != nil {
					t.Fatal(p.Err())
				}
				p.Flush()
				if p.Err() == nil || p.events.output.doh.bytes != 0 || p.events.output.incompleteDoH() {
					t.Fatal("unmatched completed response was silently discarded or retained")
				}
			} else {
				p := NewHTTP3StreamParser(types.ConnectionKey{}, out)
				p.EnableDNSOverHTTP()
				wire := append(http3TestFrame(1, encodeQPACKTestHeaders(t, qpack.HeaderField{Name: ":status", Value: "200"}, qpack.HeaderField{Name: "content-type", Value: "application/dns-message"})), http3TestFrame(0, answer)...)
				http3Feed(t, p, 0, false, wire, true)
				if err := p.Close(); err == nil || p.events.doh.bytes != 0 || p.events.incompleteDoH() {
					t.Fatal("unmatched completed H3 response was silently discarded or retained")
				}
			}
			if len(out) != 0 {
				t.Fatal("unmatched response emitted without its query")
			}
		})
	}
}
func TestDoHSameTransactionIDAcrossStreamsAndConnections(t *testing.T) {
	out := make(chan *types.DecryptedPacket, 16)
	parsers := []*HTTP2StreamParser{
		NewHTTP2StreamParser(types.ConnectionKey{SrcPort: 41001}, out),
		NewHTTP2StreamParser(types.ConnectionKey{SrcPort: 41002}, out),
	}
	expected := map[string][]byte{}
	for conn, p := range parsers {
		p.EnableDNSOverHTTP()
		p.FeedRequest([]byte(http2.ClientPreface))
		for _, id := range []uint32{1, 3} {
			name := fmt.Sprintf("c%d-s%d.test.", conn, id)
			// dohTestWire deliberately gives every query the same DNS transaction ID.
			dohHTTP2Message(t, p, id, true, "", "application/dns-message", dohTestWire(t, name, false))
			expected[fmt.Sprintf("%s/%d", p.addr.String(), id)] = dohTestWire(t, name, true)
		}
	}
	for conn := len(parsers) - 1; conn >= 0; conn-- {
		p := parsers[conn]
		for _, id := range []uint32{3, 1} {
			dohHTTP2Message(t, p, id, false, "200", "application/dns-message", dohTestWire(t, fmt.Sprintf("c%d-s%d.test.", conn, id), true))
		}
		p.Flush()
		if p.Err() != nil {
			t.Fatal(p.Err())
		}
	}
	replies := 0
	for len(out) > 0 {
		packet := <-out
		if packet.Direction != "response" {
			continue
		}
		key := fmt.Sprintf("%s/%d", packet.ConnectionID(), packet.Metadata["stream_id"])
		if !bytes.Equal(packet.Data, expected[key]) || packet.Metadata["matched"] != true {
			t.Fatalf("crossed query association: %s", key)
		}
		delete(expected, key)
		replies++
	}
	if replies != 4 || len(expected) != 0 {
		t.Fatal("lost concurrent DNS reply")
	}
}
func TestDoHResetReleasesCompletedAssociation(t *testing.T) {
	for _, version := range []int{2, 3} {
		for _, serverFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("h%d/server_first=%t", version, serverFirst), func(t *testing.T) {
				body := dohTestWire(t, "reset.test.", serverFirst)
				if version == 2 {
					p := NewHTTP2StreamParser(types.ConnectionKey{}, nil)
					p.EnableDNSOverHTTP()
					p.FeedRequest([]byte(http2.ClientPreface))
					dohHTTP2Message(t, p, 1, !serverFirst, "200", "application/dns-message", body)
					var wire bytes.Buffer
					if err := http2.NewFramer(&wire, nil).WriteRSTStream(1, http2.ErrCodeCancel); err != nil {
						t.Fatal(err)
					}
					p.FeedResponse(wire.Bytes())
					if p.Err() != nil {
						t.Fatal(p.Err())
					}
					if p.events.output.incompleteDoH() || p.events.output.doh.bytes != 0 {
						t.Fatal("RST retained a completed query/response association")
					}
					p.Flush()
					if p.Err() != nil {
						t.Fatal(p.Err())
					}
					return
				}
				p := NewHTTP3StreamParser(types.ConnectionKey{}, nil)
				p.EnableDNSOverHTTP()
				fields := []qpack.HeaderField{{Name: ":status", Value: "200"}}
				if !serverFirst {
					fields = []qpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "test"}, {Name: ":path", Value: "/dns-query"}}
				}
				fields = append(fields, qpack.HeaderField{Name: "content-type", Value: "application/dns-message"})
				wire := append(http3TestFrame(1, encodeQPACKTestHeaders(t, fields...)), http3TestFrame(0, body)...)
				http3Feed(t, p, 0, !serverFirst, wire, true)
				// Reset the unfinished peer half, which has not created an event body.
				if err := p.ResetQUICStreamWithCode(0, serverFirst, 0x10c); err != nil {
					t.Fatal(err)
				}
				if p.events.incompleteDoH() || p.events.doh.bytes != 0 {
					t.Fatal("RESET_STREAM retained a completed query/response association")
				}
				if err := p.Close(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
func TestDoHResetDuringPeerBody(t *testing.T) {
	for _, client := range []bool{false, true} {
		t.Run(fmt.Sprint(client), func(t *testing.T) {
			packets := make(chan *types.DecryptedPacket, 2)
			out := newEventOutput(types.ConnectionKey{}, packets, 0)
			out.doh = newDNSHTTP()
			b, err := out.headers("http/3", 0, client, time.Time{}, http.Header{"Content-Type": {"application/dns-message"}}, map[string]any{"method": "POST", "path": "/dns-query", "status": 200}, false)
			if err != nil {
				t.Fatal(err)
			}
			wire := dohTestWire(t, "reset.test.", !client)
			if err := b.write(wire[:8]); err != nil {
				t.Fatal(err)
			}
			if err := out.resetDoH(0); err != nil {
				t.Fatal(err)
			}
			if err := b.write(wire[8:]); err != nil {
				t.Fatal(err)
			}
			if err := b.finish("end", nil); err != nil {
				t.Fatal(err)
			}
			if out.incompleteDoH() || out.doh.bytes != 0 || len(packets) != 0 {
				t.Fatal("peer completion after reset recreated an association")
			}
			for id := uint64(0); id <= 1024; id++ {
				err := out.resetDoH(id)
				if (err != nil) != (id == 1024) || err != nil && !errors.Is(err, ErrHTTPEventLimit) {
					t.Fatalf("reset marker bound at %d: %v", id, err)
				}
			}
			out.abort()
			if len(out.doh.canceled) != 0 {
				t.Fatal("reset markers retained after abort")
			}
		})
	}
}
func TestDoHConnectionByteAndDeferredResponseBounds(t *testing.T) {
	out := newEventOutput(types.ConnectionKey{}, nil, 0)
	out.doh = newDNSHTTP()
	for i := 0; i < 65; i++ {
		b, err := out.headers("http/2", uint64(i), true, time.Time{}, http.Header{"Content-Type": {"application/dns-message"}}, map[string]any{"method": "POST", "path": "/dns-query"}, false)
		if err != nil {
			t.Fatal(err)
		}
		err = b.write(make([]byte, 65535))
		if (err != nil) != (i == 64) || err != nil && !errors.Is(err, ErrHTTPEventLimit) {
			t.Fatalf("aggregate body bound at %d: %v", i, err)
		}
	}
	out.abort()
	if out.doh.bytes != 0 || len(out.active) != 0 {
		t.Fatal("aborted bodies retained")
	}
	out = newEventOutput(types.ConnectionKey{}, nil, 0)
	out.doh = newDNSHTTP()
	for i := 0; i < 1025; i++ {
		b, err := out.headers("http/2", uint64(i), false, time.Time{}, http.Header{"Content-Type": {"application/grpc"}}, map[string]any{"status": 503}, false)
		if err != nil {
			t.Fatal(err)
		}
		err = b.finish("end", nil)
		if (err != nil) != (i == 1024) || err != nil && !errors.Is(err, ErrHTTPEventLimit) {
			t.Fatalf("deferred HTTP error bound at %d: %v", i, err)
		}
	}
	out.abort()
	if out.incompleteDoH() || out.doh.bytes != 0 {
		t.Fatal("deferred responses retained")
	}
}
