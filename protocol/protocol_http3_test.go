package protocol

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"reflect"
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
	return append(append([]byte{frameType}, http3TestVarint(uint64(len(payload)))...), payload...)
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

// RFC 9204 Appendix B vectors are independent of this decoder. They exercise
// both index origins, duplicate, literal names, name references, and eviction.
func TestQPACKRFC9204DynamicTable(t *testing.T) {
	decodeHex := func(s string) []byte {
		b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var table qpackDynamicTable
	insert := func(s string) {
		b := decodeHex(s)
		for len(b) > 0 {
			n, err := table.encoderInstruction(b, 220)
			if err != nil {
				t.Fatal(err)
			}
			b = b[n:]
		}
	}
	section := func(s string, want []qpackField) {
		b := decodeHex(s)
		prefix, err := table.sectionPrefix(b, 220, true)
		if err != nil {
			t.Fatal(err)
		}
		got, err := table.decodeSection(b, prefix)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("fields=%v err=%v want=%v", got, err, want)
		}
	}
	section("0000 510b2f696e6465782e68746d6c", []qpackField{{":path", "/index.html"}})
	insert("3fbd01 c00f7777772e6578616d706c652e636f6d c10c2f73616d706c652f70617468")
	section("0381 10 11", []qpackField{{":authority", "www.example.com"}, {":path", "/sample/path"}})
	insert("4a637573746f6d2d6b65790c637573746f6d2d76616c7565")
	insert("02")
	section("0500 80 c1 81", []qpackField{{":authority", "www.example.com"}, {":path", "/"}, {"custom-key", "custom-value"}})
	insert("810d637573746f6d2d76616c756532")
	if table.size != 215 || table.inserted != 5 {
		t.Fatalf("table size=%d inserted=%d", table.size, table.inserted)
	}
	if _, err := table.at(0); err == nil {
		t.Fatal("evicted entry remained addressable")
	}
	// Literal values using a dynamic name, before and after Base.
	section("0600 400178", []qpackField{{"custom-key", "x"}})
	section("0680 000179", []qpackField{{"custom-key", "y"}})
}

func http3TestVarint(n uint64) []byte {
	switch {
	case n < 64:
		return []byte{byte(n)}
	case n < 16384:
		return []byte{byte(n>>8) | 0x40, byte(n)}
	default:
		return []byte{byte(n>>24) | 0x80, byte(n >> 16), byte(n >> 8), byte(n)}
	}
}
func http3TestSettings(capacity, blocked uint64) []byte {
	b := append([]byte{1}, http3TestVarint(capacity)...)
	b = append(b, 7)
	b = append(b, http3TestVarint(blocked)...)
	return append([]byte{0}, http3TestFrame(HTTP3FrameSettings, b)...)
}
func http3Feed(t *testing.T, p *HTTP3StreamParser, id uint64, client bool, b []byte, fin bool) {
	t.Helper()
	if err := p.FeedQUICStream(id, client, b, fin, time.Unix(42, 0)); err != nil {
		t.Fatal(err)
	}
}
func http3DynamicRequest() []byte {
	// Required count 2, Base 0; static GET/https; post-Base authority/path.
	return http3TestFrame(HTTP3FrameHeaders, []byte{3, 0x81, 0xd1, 0xd7, 0x10, 0x11})
}
func http3RFCEncoder(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString("3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHTTP3DynamicBlockedAndLateSettings(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(fmt.Sprint(late), func(t *testing.T) {
			out := make(chan *types.DecryptedPacket, 4)
			p := NewHTTP3StreamParser(types.ConnectionKey{}, out)
			if !late {
				http3Feed(t, p, 3, false, http3TestSettings(220, 4), false)
			}
			encoder := http3RFCEncoder(t)
			// First insertion before HEADERS, remaining insertion after both request FINs.
			http3Feed(t, p, 6, true, append([]byte{2}, encoder[:20]...), false)
			for _, id := range []uint64{0, 4} {
				http3Feed(t, p, id, true, http3DynamicRequest(), true)
			}
			if len(out) != 0 || p.PendingSince().IsZero() {
				t.Fatal("blocked sections emitted or missing deadline")
			}
			if late {
				http3Feed(t, p, 3, false, http3TestSettings(220, 4), false)
			}
			for _, b := range encoder[20:] {
				http3Feed(t, p, 6, true, []byte{b}, false)
			}
			if len(out) != 2 || !p.PendingSince().IsZero() {
				t.Fatalf("unblock messages=%d pending=%v", len(out), p.PendingSince())
			}
			for len(out) > 0 {
				packet := <-out
				if packet.Metadata["path"] != "/sample/path" || packet.Metadata["authority"] != "www.example.com" || packet.Direction != "request" {
					t.Fatal(packet.Metadata)
				}
			}
			if err := p.Close(); err != nil {
				t.Fatal(err)
			}
			if p.quicStreams != nil || p.quicUni != nil || p.quicState[0].table.entries != nil {
				t.Fatal("close retained state")
			}
		})
	}
}

func TestHTTP3InformationalTrailersAndUnknownFrames(t *testing.T) {
	out := make(chan *types.DecryptedPacket, 4)
	p := NewHTTP3StreamParser(types.ConnectionKey{}, out)
	http3Feed(t, p, 0, true, http3TestFrame(HTTP3FrameHeaders, []byte{0, 0, 0xd1, 0xd7, 0xc1}), true)
	http3Feed(t, p, 0, false, http3TestFrame(HTTP3FrameHeaders, []byte{0, 0, 0xd8}), false)
	headers := http3TestFrame(HTTP3FrameHeaders, encodeQPACKTestHeaders(t, qpack.HeaderField{Name: ":status", Value: "200"}, qpack.HeaderField{Name: "x-test", Value: "initial"}))
	http3Feed(t, p, 0, false, append(headers, http3TestFrame(HTTP3FrameData, []byte("body"))...), false)
	// Unknown frame is streamed through even when split across calls.
	unknown := http3TestFrame(0x21, []byte("ignored"))
	http3Feed(t, p, 0, false, unknown[:3], false)
	http3Feed(t, p, 0, false, unknown[3:], false)
	trailers := http3TestFrame(HTTP3FrameHeaders, encodeQPACKTestHeaders(t, qpack.HeaderField{Name: "x-test", Value: "trailer"}))
	http3Feed(t, p, 0, false, trailers, true)
	if len(out) != 3 {
		t.Fatalf("messages=%d", len(out))
	}
	<-out
	info, final := <-out, <-out
	if info.Metadata["kind"] != "informational" || info.Metadata["status"] != 103 || final.Metadata["status"] != 200 || final.Metadata["kind"] != nil {
		t.Fatalf("info=%v final=%v", info.Metadata, final.Metadata)
	}
	if final.Metadata["headers"].(http.Header).Get("x-test") != "initial" || final.Metadata["trailers"].(http.Header).Get("x-test") != "trailer" || !bytes.HasSuffix(final.Data, []byte("\r\n\r\nbody")) {
		t.Fatal(final.Metadata)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHTTP3PushBeforePromiseAndCancel(t *testing.T) {
	out := make(chan *types.DecryptedPacket, 4)
	p := NewHTTP3StreamParser(types.ConnectionKey{}, out)
	http3Feed(t, p, 2, true, append(http3TestSettings(0, 0), http3TestFrame(HTTP3FrameMaxPushID, []byte{2})...), false)
	http3Feed(t, p, 15, false, append([]byte{1, 0}, append(http3TestFrame(HTTP3FrameHeaders, []byte{0, 0, 0xd9}), http3TestFrame(HTTP3FrameData, []byte("pushed"))...)...), true)
	if len(out) != 0 {
		t.Fatal("push emitted without promise")
	}
	promise := http3TestFrame(HTTP3FramePushPromise, []byte{0, 0, 0, 0xd1, 0xd7, 0xc1})
	http3Feed(t, p, 0, false, append(promise, http3TestFrame(HTTP3FrameHeaders, []byte{0, 0, 0xd9})...), true)
	if len(out) != 2 {
		t.Fatalf("messages=%d", len(out))
	}
	push := <-out
	<-out
	if push.Metadata["kind"] != "push_response" || push.Metadata["push_id"] != uint64(0) || push.Metadata["stream_id"] != uint64(15) || push.Metadata["parent_stream_id"] != uint64(0) || push.Metadata["path"] != "/" || !bytes.HasSuffix(push.Data, []byte("pushed")) {
		t.Fatal(push.Metadata)
	}
	// A canceled push does not become an incomplete or duplicate final response.
	http3Feed(t, p, 2, true, http3TestFrame(HTTP3FrameCancelPush, []byte{1}), false)
	http3Feed(t, p, 19, false, []byte{1, 1}, false)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHTTP3InvalidStateAndLimits(t *testing.T) {
	cases := []struct {
		name     string
		feed     func(*HTTP3StreamParser) error
		resource bool
	}{
		{"duplicate control", func(p *HTTP3StreamParser) error {
			http3Feed(t, p, 2, true, http3TestSettings(0, 0), false)
			return p.FeedQUICStream(6, true, []byte{0}, false, time.Now())
		}, false},
		{"duplicate setting", func(p *HTTP3StreamParser) error {
			return p.FeedQUICStream(2, true, append([]byte{0}, http3TestFrame(4, []byte{1, 0, 1, 0})...), false, time.Now())
		}, false},
		{"forbidden setting", func(p *HTTP3StreamParser) error {
			return p.FeedQUICStream(2, true, append([]byte{0}, http3TestFrame(4, []byte{2, 0})...), false, time.Now())
		}, false},
		{"critical fin", func(p *HTTP3StreamParser) error { return p.FeedQUICStream(6, true, []byte{2}, true, time.Now()) }, false},
		{"capacity", func(p *HTTP3StreamParser) error {
			http3Feed(t, p, 3, false, http3TestSettings(0, 0), false)
			return p.FeedQUICStream(6, true, []byte{2, 0x21}, false, time.Now())
		}, false},
		{"blocked limit", func(p *HTTP3StreamParser) error {
			http3Feed(t, p, 3, false, http3TestSettings(220, 1), false)
			http3Feed(t, p, 0, true, http3DynamicRequest(), true)
			return p.FeedQUICStream(4, true, http3DynamicRequest(), true, time.Now())
		}, true},
		{"local blocked limit", func(p *HTTP3StreamParser) error {
			for i := uint64(0); i < maxHTTP3BlockedStreams; i++ {
				http3Feed(t, p, i*4, true, http3DynamicRequest(), true)
			}
			return p.FeedQUICStream(4*maxHTTP3BlockedStreams, true, http3DynamicRequest(), true, time.Now())
		}, true},
		{"missing inserts at EOF", func(p *HTTP3StreamParser) error {
			http3Feed(t, p, 3, false, http3TestSettings(220, 1), false)
			http3Feed(t, p, 0, true, http3DynamicRequest(), true)
			return p.Close()
		}, false},
		{"DATA before final", func(p *HTTP3StreamParser) error {
			http3Feed(t, p, 0, false, http3TestFrame(1, []byte{0, 0, 0xd8}), false)
			return p.FeedQUICStream(0, false, http3TestFrame(0, []byte("x")), true, time.Now())
		}, false},
		{"DATA after trailers", func(p *HTTP3StreamParser) error {
			http3Feed(t, p, 0, false, http3TestFrame(1, []byte{0, 0, 0xd9}), false)
			http3Feed(t, p, 0, false, http3TestFrame(1, []byte{0, 0}), false)
			return p.FeedQUICStream(0, false, http3TestFrame(0, []byte("x")), true, time.Now())
		}, false},
		{"decoder zero increment", func(p *HTTP3StreamParser) error { return p.FeedQUICStream(10, true, []byte{3, 0}, false, time.Now()) }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewHTTP3StreamParser(types.ConnectionKey{}, nil)
			err := tc.feed(p)
			if err == nil || errors.Is(err, ErrHTTP3ResourceLimit) != tc.resource {
				t.Fatalf("err=%v resource=%v", err, tc.resource)
			}
			_ = p.Close()
		})
	}
}

func TestHTTP3BlockedResetAndIsolation(t *testing.T) {
	first := NewHTTP3StreamParser(types.ConnectionKey{}, nil)
	second := NewHTTP3StreamParser(types.ConnectionKey{}, nil)
	for _, p := range []*HTTP3StreamParser{first, second} {
		http3Feed(t, p, 3, false, http3TestSettings(220, 2), false)
	}
	http3Feed(t, first, 6, true, append([]byte{2}, http3RFCEncoder(t)...), false)
	http3Feed(t, second, 0, true, http3DynamicRequest(), true)
	if second.PendingSince().IsZero() {
		t.Fatal("compression table leaked between connections")
	}
	if err := second.ResetQUICStream(0, true); err != nil {
		t.Fatal(err)
	}
	if !second.PendingSince().IsZero() {
		t.Fatal("reset retained blocked state")
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.ResetQUICStream(6, true); err == nil {
		t.Fatal("reset critical stream accepted")
	}
}

func TestHTTP3OutputBackpressure(t *testing.T) {
	out := make(chan *types.DecryptedPacket)
	p := NewHTTP3StreamParser(types.ConnectionKey{}, out)
	done := make(chan error, 1)
	go func() {
		done <- p.FeedQUICStream(0, true, http3TestFrame(1, []byte{0, 0, 0xd1, 0xd7, 0xc1}), true, time.Now())
	}()
	select {
	case err := <-done:
		t.Fatalf("output dropped: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case <-out:
	case <-time.After(time.Second):
		t.Fatal("missing output")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestHTTP3ResourceBoundsAndRelease(t *testing.T) {
	t.Run("table capacity", func(t *testing.T) {
		p := NewHTTP3StreamParser(types.ConnectionKey{}, nil)
		http3Feed(t, p, 3, false, http3TestSettings(131072, 64), false)
		// Prefixed integer 65537: actual table capacity exceeds the local bound.
		err := p.FeedQUICStream(6, true, []byte{2, 0x3f, 0xe2, 0xff, 3}, false, time.Now())
		if !errors.Is(err, ErrHTTP3ResourceLimit) {
			t.Fatal(err)
		}
	})
	t.Run("blocked bytes", func(t *testing.T) {
		p := NewHTTP3StreamParser(types.ConnectionKey{}, nil)
		http3Feed(t, p, 3, false, http3TestSettings(220, 64), false)
		b := append(http3DynamicRequest(), make([]byte, 9<<20)...)
		for _, id := range []uint64{0, 4, 8} {
			http3Feed(t, p, id, true, b, false)
		}
		if err := p.FeedQUICStream(12, true, b, false, time.Now()); !errors.Is(err, ErrHTTP3ResourceLimit) {
			t.Fatal(err)
		}
		if err := p.Close(); !errors.Is(err, ErrHTTP3ResourceLimit) {
			t.Fatal(err)
		}
		if p.quicStreams != nil {
			t.Fatal("closed parser retained blocked bytes")
		}
	})
	t.Run("unknown frame storage", func(t *testing.T) {
		p := NewHTTP3StreamParser(types.ConnectionKey{}, nil)
		frame := http3TestFrame(0x21, make([]byte, 1<<20))
		for id := uint64(0); id < 16; id += 4 {
			http3Feed(t, p, id, true, frame, false)
			if p.quicStreams[id].request.buffer.Cap() != 0 {
				t.Fatal("consumed unknown payload retained")
			}
		}
	})
	t.Run("zero field section setting", func(t *testing.T) {
		p := NewHTTP3StreamParser(types.ConnectionKey{}, nil)
		http3Feed(t, p, 3, false, []byte{0, 4, 2, 6, 0}, false)
		if err := p.FeedQUICStream(0, true, http3TestFrame(1, []byte{0, 0, 0xd1, 0xd7, 0xc1}), true, time.Now()); err == nil {
			t.Fatal("zero field size limit ignored")
		}
	})
}

func TestQPACKRequiredCountWrapAndMalformed(t *testing.T) {
	// The max table holds two entries, so the wire Required Insert Count wraps
	// modulo four. Freeze the reconstructed count while waiting for an insertion.
	table := qpackDynamicTable{capacity: 64}
	for i := 0; i < 6; i++ {
		if err := table.insert(qpackField{"x", "y"}); err != nil {
			t.Fatal(err)
		}
	}
	block := []byte{4, 0, 0x80} // Required Insert Count 7, Base 7.
	section, err := table.sectionPrefix(block, 64, true)
	if err != nil || section.required != 7 {
		t.Fatal(section, err)
	}
	if _, err := table.decodeSection(block, section); !errors.Is(err, errQPACKBlocked) {
		t.Fatal(err)
	}
	if err := table.insert(qpackField{"x", "z"}); err != nil {
		t.Fatal(err)
	}
	fields, err := table.decodeSection(block, section)
	if err != nil || len(fields) != 1 || fields[0].value != "z" {
		t.Fatal(fields, err)
	}
	for _, block := range [][]byte{{}, {0}, {0, 0, 0xff, 0xff, 0x7f}, {0, 0, 0x29, 0xff, 0}, {0, 0, 0x80}, {2, 0x82}} {
		prefix, err := table.sectionPrefix(block, 64, true)
		if err == nil {
			_, err = table.decodeSection(block, prefix)
		}
		if err == nil {
			t.Fatalf("accepted malformed field section %x", block)
		}
	}
	if _, _, err := qpackInteger(bytes.Repeat([]byte{0xff}, 12), 8); err == nil {
		t.Fatal("integer overflow accepted")
	}
}

func TestHTTP3PushInformationalBeforePromise(t *testing.T) {
	out := make(chan *types.DecryptedPacket, 4)
	p := NewHTTP3StreamParser(types.ConnectionKey{}, out)
	http3Feed(t, p, 2, true, append(http3TestSettings(0, 0), http3TestFrame(13, []byte{0})...), false)
	response := append([]byte{1, 0}, http3TestFrame(1, []byte{0, 0, 0xd8})...)
	response = append(response, http3TestFrame(1, []byte{0, 0, 0xd9})...)
	http3Feed(t, p, 15, false, response, true)
	if len(out) != 0 {
		t.Fatal("unidentified informational push emitted")
	}
	http3Feed(t, p, 4, false, http3TestFrame(5, []byte{0, 0, 0, 0xd1, 0xd7, 0xc1}), false)
	if len(out) != 2 {
		t.Fatalf("outputs=%d", len(out))
	}
	for len(out) > 0 {
		packet := <-out
		if packet.Metadata["parent_stream_id"] != uint64(4) || packet.Metadata["path"] != "/" {
			t.Fatal(packet.Metadata)
		}
	}
}

func FuzzHTTP3QPACK(f *testing.F) {
	f.Add([]byte{3, 0x81, 0xd1, 0xd7, 0x10, 0x11}, []byte{0x3f, 0xbd, 1, 0xc0, 1, 'x', 0xc1, 1, '/'})
	f.Add([]byte{0, 0, 0xd1, 0xd7, 0xc1}, []byte{})
	f.Fuzz(func(t *testing.T, section, encoder []byte) {
		if len(section) > maxHTTP3FieldBytes || len(encoder) > maxHTTP3FieldBytes {
			return
		}
		p := NewHTTP3StreamParser(types.ConnectionKey{}, nil)
		_ = p.FeedQUICStream(3, false, http3TestSettings(220, 64), false, time.Time{})
		_ = p.FeedQUICStream(0, true, http3TestFrame(1, section), true, time.Time{})
		_ = p.FeedQUICStream(6, true, append([]byte{2}, encoder...), false, time.Time{})
		_ = p.Close()
	})
}

func TestQPACKStaticTableCompatibility(t *testing.T) {
	// The existing independent decoder supports all 99 static entries. Reusing
	// the legacy table for dynamic decoding must preserve their exact semantics.
	var table qpackDynamicTable
	for i := 0; i < 99; i++ {
		wire := []byte{0, 0}
		if i < 63 {
			wire = append(wire, 0xc0|byte(i))
		} else {
			wire = append(wire, 0xff, byte(i-63))
		}
		expected, err := qpack.NewDecoder().Decode(wire)()
		if err != nil {
			t.Fatal(err)
		}
		prefix, err := table.sectionPrefix(wire, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		got, err := table.decodeSection(wire, prefix)
		if err != nil || len(got) != 1 || got[0].name != expected.Name || got[0].value != expected.Value {
			t.Fatalf("static index=%d fields=%v err=%v", i, got, err)
		}
	}
	// An oversized declared literal value remains a resource error even when
	// there are too few bytes to decode it; no allocation follows that length.
	wire := []byte{0, 0, 0x21, 'x', 0x7f, 0x82, 0xff, 3}
	prefix, err := table.sectionPrefix(wire, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := table.decodeSection(wire, prefix); !errors.Is(err, ErrHTTP3ResourceLimit) {
		t.Fatal(err)
	}
}

func TestHTTP3PushMetadataDoesNotExposeParserState(t *testing.T) {
	out := make(chan *types.DecryptedPacket, 4)
	p := NewHTTP3StreamParser(types.ConnectionKey{}, out)
	http3Feed(t, p, 2, true, append(http3TestSettings(0, 0), http3TestFrame(13, []byte{0})...), false)
	promise := http3TestFrame(5, []byte{0, 0, 0, 0xd1, 0xd7, 0xc1})
	http3Feed(t, p, 0, false, promise, false)
	http3Feed(t, p, 15, false, append([]byte{1, 0}, http3TestFrame(1, []byte{0, 0, 0xd9})...), true)
	packet := <-out
	packet.Metadata["promise_headers"].(http.Header).Set("x-consumer", "changed")
	// A consumer can edit its metadata without changing duplicate-promise checks.
	http3Feed(t, p, 0, false, append(promise, http3TestFrame(1, []byte{0, 0, 0xd9})...), true)
	if len(out) != 1 {
		t.Fatal("duplicate promise repeated push")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}
