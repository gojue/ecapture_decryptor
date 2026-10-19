package protocol

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cfc4n/ecapture_decryptor/types"
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
