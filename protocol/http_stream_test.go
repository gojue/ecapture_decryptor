package protocol

import (
	"net"
	"strings"
	"testing"
	"time"

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
