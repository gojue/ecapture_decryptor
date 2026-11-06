package protocol

import (
	"bytes"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/gojue/ecapture_decryptor/types"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func encodeHTTP2Headers(t *testing.T, fields ...hpack.HeaderField) []byte {
	t.Helper()
	var out bytes.Buffer
	encoder := hpack.NewEncoder(&out)
	for _, field := range fields {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	return out.Bytes()
}

func TestHTTP2ConcurrentStreamsAndSplitHeaders(t *testing.T) {
	key := types.ConnectionKey{SrcIP: net.ParseIP("127.0.0.1"), DstIP: net.ParseIP("127.0.0.1"), SrcPort: 41000, DstPort: 443}
	ch := make(chan *types.DecryptedPacket, 8)
	parser := NewHTTP2StreamParser(key, ch)
	var client, server bytes.Buffer
	client.WriteString(http2.ClientPreface)
	cf := http2.NewFramer(&client, nil)
	for _, id := range []uint32{1, 3} {
		header := encodeHTTP2Headers(t,
			hpack.HeaderField{Name: ":method", Value: "GET"},
			hpack.HeaderField{Name: ":scheme", Value: "https"},
			hpack.HeaderField{Name: ":authority", Value: "example.test"},
			hpack.HeaderField{Name: ":path", Value: "/item"},
		)
		split := len(header) / 2
		if err := cf.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: header[:split], EndStream: true}); err != nil {
			t.Fatal(err)
		}
		if err := cf.WriteContinuation(id, true, header[split:]); err != nil {
			t.Fatal(err)
		}
	}
	sf := http2.NewFramer(&server, nil)
	for _, id := range []uint32{3, 1} {
		header := encodeHTTP2Headers(t, hpack.HeaderField{Name: ":status", Value: "200"})
		if err := sf.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: header, EndHeaders: true, EndStream: true}); err != nil {
			t.Fatal(err)
		}
	}
	input := client.Bytes()
	parser.FeedRequest(input[:5])
	parser.FeedRequest(input[5:])
	parser.FeedResponse(server.Bytes())
	if got := len(ch); got != 4 {
		t.Fatalf("got %d complete messages, want 4", got)
	}
	requests, responses := map[uint32]bool{}, map[uint32]bool{}
	for len(ch) > 0 {
		packet := <-ch
		id := packet.Metadata["stream_id"].(uint32)
		if packet.Direction == "request" {
			requests[id] = true
			if packet.Metadata["authority"] != "example.test" || !strings.HasPrefix(string(packet.Data), "GET /item HTTP/2.0") {
				t.Fatalf("bad request on stream %d", id)
			}
		} else {
			responses[id] = true
			if packet.Metadata["authority"] != "example.test" || !strings.HasPrefix(string(packet.Data), "HTTP/2.0 200") {
				t.Fatalf("bad response on stream %d", id)
			}
		}
	}
	if !requests[1] || !requests[3] || !responses[1] || !responses[3] {
		t.Fatalf("missing streams: request=%v response=%v", requests, responses)
	}
}

func TestHTTP2StreamParserReportsFrameLimit(t *testing.T) {
	parser := NewHTTP2StreamParser(types.ConnectionKey{}, nil)
	parser.FeedRequest(make([]byte, maxHTTP2BufferedBytes+1))
	if parser.Err() == nil {
		t.Fatal("oversized client frame was not reported")
	}
}

func TestHTTP2MultiplexedBodiesOnOneConnection(t *testing.T) {
	output := make(chan *types.DecryptedPacket, 4)
	parser := NewHTTP2StreamParser(types.ConnectionKey{SrcPort: 41002, DstPort: 443}, output)
	var client, server bytes.Buffer
	client.WriteString(http2.ClientPreface)
	cf := http2.NewFramer(&client, nil)
	requestHeaders := func(method, path string) []byte {
		return encodeHTTP2Headers(t,
			hpack.HeaderField{Name: ":method", Value: method},
			hpack.HeaderField{Name: ":scheme", Value: "https"},
			hpack.HeaderField{Name: ":authority", Value: "multiplex.example"},
			hpack.HeaderField{Name: ":path", Value: path},
		)
	}
	if err := cf.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: requestHeaders("POST", "/upload"), EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
	if err := cf.WriteData(1, false, []byte("part-")); err != nil {
		t.Fatal(err)
	}
	if err := cf.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: requestHeaders("GET", "/small"), EndHeaders: true, EndStream: true}); err != nil {
		t.Fatal(err)
	}
	if err := cf.WriteData(1, true, []byte("one")); err != nil {
		t.Fatal(err)
	}
	sf := http2.NewFramer(&server, nil)
	responseHeaders := encodeHTTP2Headers(t, hpack.HeaderField{Name: ":status", Value: "200"})
	if err := sf.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: responseHeaders, EndHeaders: true, EndStream: true}); err != nil {
		t.Fatal(err)
	}
	if err := sf.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: responseHeaders, EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
	if err := sf.WriteData(1, false, []byte("part-")); err != nil {
		t.Fatal(err)
	}
	if err := sf.WriteData(1, true, []byte("two")); err != nil {
		t.Fatal(err)
	}
	parser.FeedRequest(client.Bytes())
	parser.FeedResponse(server.Bytes())
	if err := parser.Err(); err != nil {
		t.Fatal(err)
	}
	if got := len(output); got != 4 {
		t.Fatalf("got %d multiplexed messages, want 4", got)
	}
	got := make(map[uint32]map[string]*types.DecryptedPacket)
	for len(output) > 0 {
		packet := <-output
		id := packet.Metadata["stream_id"].(uint32)
		if got[id] == nil {
			got[id] = make(map[string]*types.DecryptedPacket)
		}
		got[id][packet.Direction] = packet
	}
	for _, id := range []uint32{1, 3} {
		if got[id]["request"] == nil || got[id]["response"] == nil {
			t.Fatalf("HTTP/2 stream %d is missing a request or response: %#v", id, got[id])
		}
	}
	if got[1]["request"].Metadata["method"] != "POST" || got[1]["request"].Metadata["path"] != "/upload" ||
		!strings.HasSuffix(string(got[1]["request"].Data), "part-one") ||
		!strings.HasSuffix(string(got[1]["response"].Data), "part-two") ||
		got[3]["request"].Metadata["method"] != "GET" || got[3]["request"].Metadata["path"] != "/small" ||
		got[3]["response"].Metadata["status"] != 200 {
		t.Fatalf("HTTP/2 streams crossed or lost data: %#v", got)
	}
}

func TestHTTP2EventsDirectionsResetAndContinuation(t *testing.T) {
	out := make(chan *types.DecryptedPacket, 24)
	p := NewHTTP2StreamParser(types.ConnectionKey{Proto: "tcp"}, out)
	p.EnableHTTPEvents(0)
	var c, s bytes.Buffer
	c.WriteString(http2.ClientPreface)
	cf := http2.NewFramer(&c, nil)
	sf := http2.NewFramer(&s, nil)
	req := encodeHTTP2Headers(t, hpack.HeaderField{Name: ":method", Value: "POST"}, hpack.HeaderField{Name: ":scheme", Value: "https"}, hpack.HeaderField{Name: ":path", Value: "/"})
	if err := cf.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: req[:2]}); err != nil {
		t.Fatal(err)
	}
	if err := cf.WriteContinuation(1, true, req[2:]); err != nil {
		t.Fatal(err)
	}
	if err := cf.WriteData(1, false, []byte("upload")); err != nil {
		t.Fatal(err)
	}
	p.FeedRequest(c.Bytes())
	resp := encodeHTTP2Headers(t, hpack.HeaderField{Name: ":status", Value: "200"})
	if err := sf.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, BlockFragment: resp}); err != nil {
		t.Fatal(err)
	}
	if err := sf.WriteDataPadded(1, false, []byte("ok"), make([]byte, 3)); err != nil {
		t.Fatal(err)
	}
	trail := encodeHTTP2Headers(t, hpack.HeaderField{Name: "x-last", Value: "done"})
	if err := sf.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndStream: true, BlockFragment: trail[:1]}); err != nil {
		t.Fatal(err)
	}
	if err := sf.WriteContinuation(1, true, trail[1:]); err != nil {
		t.Fatal(err)
	}
	for _, v := range s.Bytes() {
		p.FeedResponse([]byte{v})
	}
	c.Reset()
	if err := cf.WriteRSTStream(1, http2.ErrCodeCancel); err != nil {
		t.Fatal(err)
	}
	p.FeedRequest(c.Bytes())
	p.Flush()
	p.Flush()
	if p.Err() != nil {
		t.Fatal(p.Err())
	}
	var response bytes.Buffer
	var order []string
	for len(out) > 0 {
		v := <-out
		kind := v.Metadata["kind"].(string)
		if v.Direction == "response" {
			order = append(order, kind)
			if kind == "body_chunk" {
				response.Write(v.Data)
			}
			if kind == "trailers" && v.Metadata["trailers"].(http.Header).Get("X-Last") != "done" {
				t.Fatal(v.Metadata)
			}
		} else if kind == "reset" && (v.Metadata["offset"] != uint64(6) || v.Metadata["error_code"] != uint64(http2.ErrCodeCancel)) {
			t.Fatal(v.Metadata)
		}
	}
	if response.String() != "ok" || !slices.Equal(order, []string{"headers", "body_chunk", "body_chunk", "trailers", "end"}) {
		t.Fatal(order, response.String())
	}
}

func TestHTTP2EventsResetDuringData(t *testing.T) {
	out := make(chan *types.DecryptedPacket, 16)
	p := NewHTTP2StreamParser(types.ConnectionKey{Proto: "tcp"}, out)
	p.EnableHTTPEvents(0)
	var c, s bytes.Buffer
	c.WriteString(http2.ClientPreface)
	cf := http2.NewFramer(&c, nil)
	sf := http2.NewFramer(&s, nil)
	req := encodeHTTP2Headers(t, hpack.HeaderField{Name: ":method", Value: "POST"}, hpack.HeaderField{Name: ":scheme", Value: "https"}, hpack.HeaderField{Name: ":path", Value: "/"})
	if err := cf.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, BlockFragment: req}); err != nil {
		t.Fatal(err)
	}
	if err := cf.WriteData(1, true, []byte("abcd")); err != nil {
		t.Fatal(err)
	}
	p.FeedRequest(c.Bytes()[:c.Len()-2])
	if err := sf.WriteRSTStream(1, http2.ErrCodeCancel); err != nil {
		t.Fatal(err)
	}
	p.FeedResponse(s.Bytes())
	p.FeedRequest(c.Bytes()[c.Len()-2:])
	if p.Err() != nil {
		t.Fatal(p.Err())
	}
	p.Flush()
	if len(out) != 3 {
		t.Fatalf("events=%d", len(out))
	}
	<-out
	body, rst := <-out, <-out
	if string(body.Data) != "ab" || rst.Metadata["kind"] != "reset" || rst.Metadata["offset"] != uint64(2) {
		t.Fatal(body.Metadata, rst.Metadata)
	}
}
