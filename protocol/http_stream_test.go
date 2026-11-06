package protocol

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/gojue/ecapture_decryptor/types"
)

func TestHTTPStreamParserPipelinedSplitMessages(t *testing.T) {
	output := make(chan *types.DecryptedPacket, 8)
	parser := NewHTTPStreamParser(types.ConnectionKey{SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2), SrcPort: 1234, DstPort: 443}, output)
	parser.SetPacketTime(time.Unix(1, 0))
	parser.FeedRequest([]byte("POST /one HTTP/1.1\r\nHost: first.example\r\nContent-Length: 5\r\n\r\nhe"))
	if len(output) != 0 {
		t.Fatal("emitted an incomplete request")
	}
	parser.FeedRequest([]byte("lloGET /two HTTP/1.1\r\nHost: second.example\r\n\r\n"))
	if len(output) != 2 {
		t.Fatalf("got %d requests, want 2", len(output))
	}
	first := <-output
	second := <-output
	if first.Metadata["host"] != "first.example" || !strings.HasSuffix(string(first.Data), "hello") || second.Metadata["host"] != "second.example" {
		t.Fatal("request association or body assembly failed")
	}
	parser.SetPacketTime(time.Unix(2, 0))
	parser.FeedResponse([]byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcHTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\n"))
	if len(output) != 1 {
		t.Fatalf("got %d responses before second body, want 1", len(output))
	}
	parser.FeedResponse([]byte("de"))
	if len(output) != 2 {
		t.Fatalf("got %d responses, want 2", len(output))
	}
	responseOne := <-output
	responseTwo := <-output
	if responseOne.Metadata["host"] != "first.example" || responseTwo.Metadata["host"] != "second.example" || !strings.HasSuffix(string(responseTwo.Data), "de") {
		t.Fatal("response association or body assembly failed")
	}
}

func TestHTTPStreamParserReportsMessageLimit(t *testing.T) {
	parser := NewHTTPStreamParser(types.ConnectionKey{}, nil)
	parser.FeedRequest(make([]byte, maxHTTPMessageBytes+1))
	if parser.Err() == nil {
		t.Fatal("oversized request was not reported")
	}
}

func TestHTTP10ShortConnectionWithCloseDelimitedResponse(t *testing.T) {
	output := make(chan *types.DecryptedPacket, 2)
	parser := NewHTTPStreamParser(types.ConnectionKey{SrcPort: 41000, DstPort: 443}, output)
	parser.FeedRequest([]byte("GET /legacy HTTP/1.0\r\nHost: legacy.example\r\n\r\n"))
	parser.FeedResponse([]byte("HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nclose-delimited"))
	if got := len(output); got != 1 {
		t.Fatalf("got %d messages before connection close, want only the request", got)
	}
	parser.Flush()
	if got := len(output); got != 2 {
		t.Fatalf("got %d messages after connection close, want request and response", got)
	}
	request, response := <-output, <-output
	if request.Protocol != "http/1.0" || request.Metadata["url"] != "/legacy" || request.Metadata["host"] != "legacy.example" {
		t.Fatalf("wrong HTTP/1.0 request: protocol=%q metadata=%v", request.Protocol, request.Metadata)
	}
	if response.Protocol != "http/1.0" || response.Metadata["status"] != 200 || !strings.HasSuffix(string(response.Data), "close-delimited") {
		t.Fatalf("wrong HTTP/1.0 response: protocol=%q metadata=%v data=%q", response.Protocol, response.Metadata, response.Data)
	}
}

func TestHTTP11KeepAliveReusesConnection(t *testing.T) {
	output := make(chan *types.DecryptedPacket, 4)
	parser := NewHTTPStreamParser(types.ConnectionKey{SrcPort: 41001, DstPort: 443}, output)
	parser.FeedRequest([]byte("GET /first HTTP/1.1\r\nHost: same.example\r\n\r\n"))
	parser.FeedResponse([]byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none"))
	parser.FeedRequest([]byte("GET /second HTTP/1.1\r\nHost: same.example\r\nConnection: close\r\n\r\n"))
	parser.FeedResponse([]byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo"))
	if got := len(output); got != 4 {
		t.Fatalf("got %d messages on reused connection, want 4", got)
	}
	firstRequest, firstResponse, secondRequest, secondResponse := <-output, <-output, <-output, <-output
	if firstRequest.Metadata["url"] != "/first" || secondRequest.Metadata["url"] != "/second" ||
		firstResponse.Metadata["host"] != "same.example" || secondResponse.Metadata["host"] != "same.example" ||
		!strings.HasSuffix(string(firstResponse.Data), "one") || !strings.HasSuffix(string(secondResponse.Data), "two") {
		t.Fatalf("requests or responses crossed on keep-alive connection: %v %v %v %v", firstRequest.Metadata, firstResponse.Metadata, secondRequest.Metadata, secondResponse.Metadata)
	}
	for _, packet := range []*types.DecryptedPacket{firstRequest, firstResponse, secondRequest, secondResponse} {
		if packet.Protocol != "http/1.1" || packet.Transport != types.TransportProtocolTCP {
			t.Fatalf("wrong protocol for reused connection: %q/%q", packet.Transport, packet.Protocol)
		}
	}
}

func TestHTTP11ChunkedRequestAndResponse(t *testing.T) {
	output := make(chan *types.DecryptedPacket, 2)
	parser := NewHTTPStreamParser(types.ConnectionKey{}, output)
	parser.FeedRequest([]byte("POST /upload HTTP/1.1\r\nHost: chunked.example\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n"))
	if len(output) != 0 {
		t.Fatal("emitted request before final chunk")
	}
	parser.FeedRequest([]byte("0\r\n\r\n"))
	parser.FeedResponse([]byte("HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nworld\r\n0\r\n\r\n"))
	if got := len(output); got != 2 {
		t.Fatalf("got %d chunked messages, want 2", got)
	}
	request, response := <-output, <-output
	if request.Metadata["method"] != "POST" || request.Metadata["url"] != "/upload" || !strings.Contains(string(request.Data), "hello") {
		t.Fatalf("wrong chunked request: %v %q", request.Metadata, request.Data)
	}
	if response.Metadata["status"] != 201 || response.Metadata["host"] != "chunked.example" || !strings.Contains(string(response.Data), "world") {
		t.Fatalf("wrong chunked response: %v %q", response.Metadata, response.Data)
	}
}

func TestHTTP1EventsDuplexTrailersAndTruncation(t *testing.T) {
	out := make(chan *types.DecryptedPacket, 32)
	p := NewHTTPStreamParser(types.ConnectionKey{Proto: "tcp"}, out)
	p.EnableHTTPEvents(0)
	p.FeedRequest([]byte("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nab"))
	p.FeedResponse([]byte("HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"))
	for _, c := range []byte("2;ext=y\r\nok\r\n0\r\nX-Last: yes\r\n\r\n") {
		p.FeedResponse([]byte{c})
	}
	p.FeedRequest([]byte("c"))
	p.Flush()
	p.Flush()
	if !errors.Is(p.Err(), io.ErrUnexpectedEOF) {
		t.Fatal(p.Err())
	}
	var got []string
	for len(out) > 0 {
		v := <-out
		k := v.Metadata["kind"].(string)
		got = append(got, v.Direction+"/"+k)
		if v.Metadata["stream_id"] != uint64(1) {
			t.Fatal(v.Metadata)
		}
		if k == "trailers" && v.Metadata["trailers"].(http.Header).Get("X-Last") != "yes" {
			t.Fatal(v.Metadata)
		}
		if k == "partial" && v.Metadata["offset"] != uint64(3) {
			t.Fatal(v.Metadata)
		}
	}
	want := []string{"request/headers", "request/body_chunk", "response/headers", "response/headers", "response/body_chunk", "response/body_chunk", "response/trailers", "response/end", "request/body_chunk", "request/partial"}
	if !slices.Equal(got, want) {
		t.Fatal(got)
	}
}

func TestHTTPEventsSSEAndGzip(t *testing.T) {
	for _, tc := range []struct {
		name      string
		limit     int64
		truncated bool
	}{{"encoded", 0, false}, {"streaming", 1024, false}, {"limit", 12, false}, {"truncated", 1024, true}} {
		t.Run(tc.name, func(t *testing.T) {
			var coded bytes.Buffer
			w := gzip.NewWriter(&coded)
			text := "\ufeff: comment\r\nid: 7\rretry: 123\revent: tick\rdata: ☕\rdata: two\r\r"
			_, _ = w.Write([]byte(text))
			if err := w.Flush(); err != nil {
				t.Fatal(err)
			}
			split := coded.Len()
			_, _ = w.Write([]byte("data: next\n\n"))
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			data := coded.Bytes()
			if tc.truncated {
				data = data[:len(data)-3]
			}
			ch := make(chan *types.DecryptedPacket, 64)
			p := NewHTTPStreamParser(types.ConnectionKey{Proto: "tcp"}, ch)
			p.EnableHTTPEvents(tc.limit)
			p.FeedRequest([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
			p.FeedResponse([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: text/event-stream\r\nContent-Encoding: gzip\r\n\r\n", len(data))))
			p.FeedResponse(data[:split])
			var events []string
			var body bytes.Buffer
			var partial, end int
			drain := func() {
				for len(ch) > 0 {
					v := <-ch
					if v.Direction != "response" {
						continue
					}
					switch v.Metadata["kind"] {
					case "sse":
						events = append(events, string(v.Data))
						if len(events) == 1 && (v.Metadata["last_event_id"] != "7" || v.Metadata["event"] != "tick") {
							t.Fatal(v.Metadata)
						}
					case "body_chunk":
						if v.Metadata["offset"] != uint64(body.Len()) {
							t.Fatal(v.Metadata)
						}
						body.Write(v.Data)
					case "partial":
						partial++
					case "end":
						end++
					}
				}
			}
			drain()
			if tc.limit == 1024 && !slices.Equal(events, []string{"☕\ntwo"}) {
				t.Fatalf("before gzip footer and HTTP end: %q", events)
			}
			p.FeedResponse(data[split:])
			p.Flush()
			p.Flush()
			drain()
			switch tc.name {
			case "encoded":
				if !bytes.Equal(body.Bytes(), data) || len(events) != 0 || end != 1 {
					t.Fatal("encoded mode changed bytes")
				}
			case "streaming":
				if body.String() != text+"data: next\n\n" || !slices.Equal(events, []string{"☕\ntwo", "next"}) || end != 1 {
					t.Fatal(events, body.String(), end)
				}
			case "limit":
				if !errors.Is(p.Err(), ErrHTTPEventLimit) || int64(body.Len()) > tc.limit || partial != 1 || end != 0 {
					t.Fatal(p.Err(), body.Len(), partial, end)
				}
			case "truncated":
				if p.Err() == nil || partial != 1 || end != 0 {
					t.Fatal(p.Err(), partial, end)
				}
			}
			if p.events.output.inflaters != 0 || len(p.events.output.active) != 0 {
				t.Fatal("decoder retained after close")
			}
		})
	}
}

func TestHTTPEventsBackpressure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		out := make(chan *types.DecryptedPacket)
		p := NewHTTPStreamParser(types.ConnectionKey{Proto: "tcp"}, out)
		p.EnableHTTPEvents(0)
		done := make(chan struct{})
		go func() {
			defer close(done)
			p.FeedRequest([]byte("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\nx"))
		}()
		for _, want := range []string{"headers", "body_chunk", "end"} {
			synctest.Wait()
			select {
			case <-done:
				t.Fatal("producer bypassed consumer")
			default:
			}
			if (<-out).Metadata["kind"] != want {
				t.Fatal(want)
			}
		}
		<-done
	})
}

func TestHTTPEventLongTCPBodies(t *testing.T) {
	const total = 17<<20 + 37
	for _, version := range []int{1, 2} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			ch := make(chan *types.DecryptedPacket, 8)
			conn := types.ConnectionKey{Proto: "tcp"}
			var feed func([]byte, bool)
			var flush func()
			var failure func() error
			if version == 1 {
				p := NewHTTPStreamParser(conn, ch)
				p.EnableHTTPEvents(0)
				p.FeedRequest([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
				p.FeedResponse([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", total)))
				feed = func(data []byte, _ bool) { p.FeedResponse(data) }
				flush = p.Flush
				failure = p.Err
			} else {
				p := NewHTTP2StreamParser(conn, ch)
				p.EnableHTTPEvents(0)
				var c, s bytes.Buffer
				c.WriteString(http2.ClientPreface)
				cf := http2.NewFramer(&c, nil)
				sf := http2.NewFramer(&s, nil)
				req := encodeHTTP2Headers(t, hpack.HeaderField{Name: ":method", Value: "GET"}, hpack.HeaderField{Name: ":scheme", Value: "https"}, hpack.HeaderField{Name: ":path", Value: "/"})
				if err := cf.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, EndStream: true, BlockFragment: req}); err != nil {
					t.Fatal(err)
				}
				p.FeedRequest(c.Bytes())
				if err := sf.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, BlockFragment: encodeHTTP2Headers(t, hpack.HeaderField{Name: ":status", Value: "200"})}); err != nil {
					t.Fatal(err)
				}
				p.FeedResponse(s.Bytes())
				feed = func(data []byte, end bool) {
					s.Reset()
					if err := sf.WriteData(1, end, data); err != nil {
						t.Fatal(err)
					}
					p.FeedResponse(s.Bytes())
				}
				flush = p.Flush
				failure = p.Err
			}
			if len(ch) != 3 {
				t.Fatal("missing initial events")
			}
			<-ch
			<-ch
			<-ch
			block := make([]byte, 16384)
			for pos := 0; pos < total; {
				n := min(len(block), total-pos)
				for i := range block[:n] {
					block[i] = byte((pos + i) % 251)
				}
				feed(block[:n], pos+n == total)
				if len(ch) == 0 {
					t.Fatal("no body progress", pos, failure())
				}
				got := <-ch
				if got.Metadata["kind"] != "body_chunk" || got.Metadata["offset"] != uint64(pos) || !bytes.Equal(got.Data, block[:n]) {
					t.Fatal(got.Metadata)
				}
				pos += n
			}
			flush()
			flush()
			if failure() != nil || len(ch) != 1 {
				t.Fatal(failure(), len(ch))
			}
			end := <-ch
			if end.Metadata["kind"] != "end" || end.Metadata["offset"] != uint64(total) {
				t.Fatal(end.Metadata)
			}
		})
	}
}

func TestHTTP1EventsCloseDelimitedTermination(t *testing.T) {
	for _, reason := range []string{"", "capture_eof", "reset"} {
		t.Run("close-"+reason, func(t *testing.T) {
			out := make(chan *types.DecryptedPacket, 8)
			p := NewHTTPStreamParser(types.ConnectionKey{Proto: "tcp"}, out)
			p.EnableHTTPEvents(0)
			p.FeedRequest([]byte("GET / HTTP/1.0\r\n\r\n"))
			p.FeedResponse([]byte("HTTP/1.0 200 OK\r\n\r\nprefix"))
			p.FinishHTTPEvents(reason)
			p.FinishHTTPEvents(reason)
			want := map[string]string{"": "end", "capture_eof": "partial", "reset": "reset"}[reason]
			if len(out) != 5 {
				t.Fatal(len(out))
			}
			for len(out) > 1 {
				<-out
			}
			pck := <-out
			if pck.Metadata["kind"] != want || pck.Metadata["offset"] != uint64(6) || (p.Err() != nil) != (reason == "capture_eof") {
				t.Fatal(pck.Metadata, p.Err())
			}
		})
	}
}

func FuzzHTTPEventFragments(f *testing.F) {
	f.Add([]byte("9\r\ndata: a\n\n\r\n0\r\nX-End: y\r\n\r\n"), uint8(1))
	f.Add([]byte("7fffffffffffffff\r\nshort"), uint8(3))
	f.Fuzz(func(t *testing.T, data []byte, width uint8) {
		if len(data) > eventFieldLimit {
			return
		}
		p := NewHTTPStreamParser(types.ConnectionKey{Proto: "tcp"}, nil)
		p.EnableHTTPEvents(4096)
		p.FeedRequest([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		p.FeedResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"))
		for len(data) > 0 && p.Err() == nil {
			n := min(len(data), int(width)+1)
			p.FeedResponse(data[:n])
			data = data[n:]
		}
		p.Flush()
		p.Flush()
		if len(p.events.output.active) != 0 {
			t.Fatal("retained stream after fragmented input")
		}
	})
}
