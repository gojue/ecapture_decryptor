package protocol

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/cfc4n/ecapture_decryptor/types"
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
