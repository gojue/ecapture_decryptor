package protocol

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gojue/ecapture_decryptor/types"
	"github.com/quic-go/qpack"
)

// These are HTTP/3 frames on one already decrypted QUIC request stream. They
// do not exercise QUIC packet protection, STREAM frame decoding, or QPACK's
// dynamic table; those layers are separate from this parser.
func http3TestFrame(frameType byte, payload []byte) []byte {
	if len(payload) >= 64 {
		panic("test helper only encodes one-byte QUIC varints")
	}
	return append([]byte{frameType, byte(len(payload))}, payload...)
}

func TestHTTP3StaticQPACKAndSplitFrames(t *testing.T) {
	output := make(chan *types.DecryptedPacket, 2)
	parser := NewHTTP3StreamParser(types.ConnectionKey{
		SrcIP: net.IPv4(192, 0, 2, 10), DstIP: net.IPv4(192, 0, 2, 20),
		SrcPort: 41003, DstPort: 443, Proto: types.TransportProtocolUDP,
	}, output)
	// QPACK prefix, static :method GET, static :scheme https, literal
	// :path /index, and literal :authority example.test.
	requestHeaders := []byte{0, 0, 0xd1, 0xd7, 0x51, 6, '/', 'i', 'n', 'd', 'e', 'x', 0x50, 12}
	requestHeaders = append(requestHeaders, []byte("example.test")...)
	request := http3TestFrame(HTTP3FrameHeaders, requestHeaders)
	parser.FeedRequest(request[:1])
	parser.FeedRequest(request[1:3])
	if len(output) != 0 {
		t.Fatal("emitted an incomplete HTTP/3 HEADERS frame")
	}
	parser.FeedRequest(request[3:])
	if len(output) != 1 {
		t.Fatalf("got %d requests, want 1", len(output))
	}
	response := append(http3TestFrame(HTTP3FrameHeaders, []byte{0, 0, 0xd9}), http3TestFrame(HTTP3FrameData, []byte("ok"))...)
	parser.FeedResponse(response[:4])
	if len(output) != 1 {
		t.Fatal("emitted a response before its HTTP/3 DATA frame")
	}
	parser.FeedResponse(response[4:])
	if len(output) != 2 {
		t.Fatalf("got %d HTTP/3 messages, want 2", len(output))
	}
	gotRequest, gotResponse := <-output, <-output
	if gotRequest.Transport != types.TransportProtocolUDP || gotRequest.Protocol != "http/3" ||
		gotRequest.Metadata["method"] != "GET" || gotRequest.Metadata["path"] != "/index" ||
		gotRequest.Metadata["authority"] != "example.test" || !bytes.HasPrefix(gotRequest.Data, []byte("GET /index HTTP/3.0")) {
		t.Fatalf("wrong HTTP/3 request: transport=%q metadata=%v data=%q", gotRequest.Transport, gotRequest.Metadata, gotRequest.Data)
	}
	if gotResponse.Transport != types.TransportProtocolUDP || gotResponse.Protocol != "http/3" ||
		gotResponse.Metadata["status"] != 200 || !strings.HasSuffix(string(gotResponse.Data), "ok") {
		t.Fatalf("wrong HTTP/3 response: transport=%q metadata=%v data=%q", gotResponse.Transport, gotResponse.Metadata, gotResponse.Data)
	}
}

func TestHTTP3HeadersOnlyResponseFlush(t *testing.T) {
	output := make(chan *types.DecryptedPacket, 2)
	parser := NewHTTP3StreamParser(types.ConnectionKey{Proto: types.TransportProtocolUDP}, output)
	parser.FeedRequest(http3TestFrame(HTTP3FrameHeaders, []byte{0, 0, 0xd1, 0xd7, 0xc1}))
	// Static QPACK index 25 is :status 200.
	parser.FeedResponse(http3TestFrame(HTTP3FrameHeaders, []byte{0, 0, 0xd9}))
	if len(output) != 1 {
		t.Fatalf("got %d messages before stream end, want request only", len(output))
	}
	parser.Flush()
	if len(output) != 2 {
		t.Fatalf("got %d messages after stream flush, want request and response", len(output))
	}
	<-output
	response := <-output
	if response.Metadata["status"] != 200 || response.Protocol != "http/3" {
		t.Fatalf("wrong headers-only HTTP/3 response: %v", response.Metadata)
	}
}

func encodeQPACKTestHeaders(t *testing.T, fields ...qpack.HeaderField) []byte {
	t.Helper()
	var encoded bytes.Buffer
	encoder := qpack.NewEncoder(&encoded)
	for _, field := range fields {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	return encoded.Bytes()
}

func TestHTTP3QUICStreamsMultiplexedAndFragmented(t *testing.T) {
	output := make(chan *types.DecryptedPacket, 4)
	parser := NewHTTP3StreamParser(types.ConnectionKey{Proto: types.TransportProtocolUDP}, output)
	at := time.Unix(42, 0)
	request := func(method, path string) []byte {
		return http3TestFrame(HTTP3FrameHeaders, encodeQPACKTestHeaders(t,
			qpack.HeaderField{Name: ":method", Value: method},
			qpack.HeaderField{Name: ":scheme", Value: "https"},
			qpack.HeaderField{Name: ":authority", Value: "h3.example"},
			qpack.HeaderField{Name: ":path", Value: path},
		))
	}
	post := append(request("POST", "/upload"), http3TestFrame(HTTP3FrameData, []byte("request-body"))...)
	if err := parser.FeedQUICStream(0, true, post[:3], false, at); err != nil {
		t.Fatal(err)
	}
	if err := parser.FeedQUICStream(4, true, request("GET", "/small"), true, at); err != nil {
		t.Fatal(err)
	}
	if err := parser.FeedQUICStream(0, true, post[3:], true, at); err != nil {
		t.Fatal(err)
	}
	response := func(body string) []byte {
		return append(http3TestFrame(HTTP3FrameHeaders, encodeQPACKTestHeaders(t,
			qpack.HeaderField{Name: ":status", Value: "200"},
		)), http3TestFrame(HTTP3FrameData, []byte(body))...)
	}
	if err := parser.FeedQUICStream(4, false, response("small-body"), true, at); err != nil {
		t.Fatal(err)
	}
	large := response("response-body")
	if err := parser.FeedQUICStream(0, false, large[:4], false, at); err != nil {
		t.Fatal(err)
	}
	if err := parser.FeedQUICStream(0, false, large[4:], true, at); err != nil {
		t.Fatal(err)
	}
	if len(output) != 4 {
		t.Fatalf("got %d HTTP/3 messages, want 4", len(output))
	}
	got := map[uint64]map[string]*types.DecryptedPacket{}
	for len(output) > 0 {
		packet := <-output
		id := packet.Metadata["stream_id"].(uint64)
		if got[id] == nil {
			got[id] = map[string]*types.DecryptedPacket{}
		}
		got[id][packet.Direction] = packet
	}
	for _, id := range []uint64{0, 4} {
		if got[id]["request"] == nil || got[id]["response"] == nil {
			t.Fatalf("missing HTTP/3 exchange on stream %d: %v", id, got[id])
		}
	}
	if got[0]["request"].Metadata["method"] != "POST" || !strings.HasSuffix(string(got[0]["request"].Data), "request-body") ||
		!strings.HasSuffix(string(got[0]["response"].Data), "response-body") || got[4]["request"].Metadata["path"] != "/small" ||
		!strings.HasSuffix(string(got[4]["response"].Data), "small-body") {
		t.Fatalf("HTTP/3 stream data crossed: %v", got)
	}
}
