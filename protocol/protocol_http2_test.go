package protocol

import (
	"bytes"
	"net"
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
