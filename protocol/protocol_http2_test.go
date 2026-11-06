package protocol

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

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

// gRPC envelopes deliberately cross HTTP/2 DATA boundaries in both directions.
func grpcEnvelope(t *testing.T, message []byte, compressed bool) []byte {
	t.Helper()
	flag := byte(0)
	if compressed {
		var out bytes.Buffer
		z := gzip.NewWriter(&out)
		if _, err := z.Write(message); err != nil {
			t.Fatal(err)
		}
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
		message = out.Bytes()
		flag = 1
	}
	out := binary.BigEndian.AppendUint32([]byte{flag}, uint32(len(message)))
	return append(out, message...)
}
func grpcH2Headers(t *testing.T, p *HTTP2StreamParser, id uint32, client, fin bool, extra ...hpack.HeaderField) {
	t.Helper()
	fields := []hpack.HeaderField{{Name: ":status", Value: "200"}}
	if client {
		fields = []hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/test.Service/Call"}, {Name: ":authority", Value: "example.test"}}
	}
	fields = append(fields, hpack.HeaderField{Name: "content-type", Value: "application/grpc+proto"}, hpack.HeaderField{Name: "grpc-encoding", Value: "gzip"})
	fields = append(fields, extra...)
	var out bytes.Buffer
	f := http2.NewFramer(&out, nil)
	if err := f.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: encodeHTTP2Headers(t, fields...), EndHeaders: true, EndStream: fin}); err != nil {
		t.Fatal(err)
	}
	if client {
		p.FeedRequest(out.Bytes())
	} else {
		p.FeedResponse(out.Bytes())
	}
}
func grpcH2Data(t *testing.T, p *HTTP2StreamParser, id uint32, client, fin bool, data []byte) {
	t.Helper()
	var out bytes.Buffer
	if err := http2.NewFramer(&out, nil).WriteData(id, fin, data); err != nil {
		t.Fatal(err)
	}
	if client {
		p.FeedRequest(out.Bytes())
	} else {
		p.FeedResponse(out.Bytes())
	}
}
func grpcH2Trailers(t *testing.T, p *HTTP2StreamParser, id uint32, status string) {
	t.Helper()
	var out bytes.Buffer
	if err := http2.NewFramer(&out, nil).WriteHeaders(http2.HeadersFrameParam{StreamID: id, EndHeaders: true, EndStream: true, BlockFragment: encodeHTTP2Headers(t, hpack.HeaderField{Name: "grpc-status", Value: status}, hpack.HeaderField{Name: "grpc-message", Value: "not%20found+literal"})}); err != nil {
		t.Fatal(err)
	}
	p.FeedResponse(out.Bytes())
}
func TestGRPCStreamingMessages(t *testing.T) {
	for _, counts := range [][2]int{{1, 1}, {3, 1}, {1, 3}, {3, 3}} {
		t.Run(fmt.Sprint(counts), func(t *testing.T) {
			ch := make(chan *types.DecryptedPacket, 4096)
			p := NewHTTP2StreamParser(types.ConnectionKey{}, ch)
			p.EnableHTTPEvents(0)
			p.FeedRequest([]byte(http2.ClientPreface))
			for _, id := range []uint32{1, 3} {
				grpcH2Headers(t, p, id, true, false)
				grpcH2Headers(t, p, id, false, false)
			}
			wanted := map[string][][]byte{}
			for _, id := range []uint32{3, 1} {
				for direction, n := range counts {
					client := direction == 0
					var input []byte
					key := fmt.Sprintf("%d/%t", id, client)
					for i := 0; i < n; i++ {
						data := []byte{0x0a, 3, byte(id), byte(direction), byte(i)} // Opaque protobuf-like bytes, no descriptor.
						if i == 1 {
							data = nil
						}
						input = append(input, grpcEnvelope(t, data, i%2 == 0)...)
						wanted[key] = append(wanted[key], data)
					}
					// One-byte DATA frames split prefixes and gzip trailers, and leave stream open.
					for _, b := range input {
						grpcH2Data(t, p, id, client, false, []byte{b})
					}
					if p.Err() != nil {
						t.Fatal(p.Err())
					}
				}
			}
			got := map[string][][]byte{}
			for len(ch) > 0 {
				packet := <-ch
				if packet.Metadata["kind"] == "end" {
					t.Fatal("ended before EOS")
				}
				if packet.Metadata["kind"] == "grpc_message" {
					key := fmt.Sprintf("%d/%t", packet.Metadata["stream_id"], packet.Direction == "request")
					if packet.Metadata["message_index"] != uint64(len(got[key])) {
						t.Fatal(packet.Metadata)
					}
					got[key] = append(got[key], packet.Data)
				}
			}
			if !reflect.DeepEqual(got, wanted) {
				t.Fatalf("messages got %v want %v", got, wanted)
			}
			for _, id := range []uint32{1, 3} {
				grpcH2Data(t, p, id, true, true, nil)
				grpcH2Trailers(t, p, id, "5")
			}
			p.Flush()
			if p.Err() != nil || len(p.events.streams) != 0 || p.events.output.grpcBuffered != 0 {
				t.Fatalf("finish: %v", p.Err())
			}
			statuses := 0
			for len(ch) > 0 {
				packet := <-ch
				if packet.Metadata["grpc_status"] == uint32(5) {
					if packet.Metadata["grpc_message"] != "not found+literal" {
						t.Fatal(packet.Metadata)
					}
					statuses++
				}
			}
			if statuses != 4 {
				t.Fatalf("got %d trailer/end statuses", statuses)
			}
		})
	}
}
func TestGRPCBoundsTruncationAndStatus(t *testing.T) {
	for name, data := range map[string][]byte{
		"partial prefix": {0, 0}, "partial body": {0, 0, 0, 0, 5, 1}, "bad flag": {2, 0, 0, 0, 0},
		"length overflow": {0, 255, 255, 255, 255}, "invalid gzip": {1, 0, 0, 0, 1, 0},
	} {
		t.Run(name, func(t *testing.T) {
			ch := make(chan *types.DecryptedPacket, 16)
			p := NewHTTP2StreamParser(types.ConnectionKey{}, ch)
			p.EnableHTTPEvents(0)
			p.FeedRequest([]byte(http2.ClientPreface))
			grpcH2Headers(t, p, 1, true, false)
			grpcH2Data(t, p, 1, true, true, data)
			p.Flush()
			p.Flush()
			if p.Err() == nil || p.events.output.grpcBuffered != 0 {
				t.Fatal("truncated/malformed message accepted or retained")
			}
			for len(ch) > 0 {
				if got := <-ch; got.Metadata["kind"] == "grpc_message" || got.Metadata["kind"] == "end" {
					t.Fatal(got.Metadata)
				}
			}
		})
	}
	for _, status := range []string{"0", "13", "invalid", "01", "-1", ""} {
		p := NewHTTP2StreamParser(types.ConnectionKey{}, nil)
		p.EnableHTTPEvents(0)
		p.FeedRequest([]byte(http2.ClientPreface))
		grpcH2Headers(t, p, 1, true, true)
		grpcH2Headers(t, p, 1, false, true, hpack.HeaderField{Name: "grpc-status", Value: status})
		p.Flush()
		if (p.Err() == nil) != (status == "0" || status == "13") {
			t.Fatalf("trailers-only status %q: %v", status, p.Err())
		}
	}
	// Limit decoded bytes independently of the wire length and release partial data.
	p := NewHTTP2StreamParser(types.ConnectionKey{}, nil)
	p.EnableHTTPEvents(0)
	p.FeedRequest([]byte(http2.ClientPreface))
	grpcH2Headers(t, p, 1, true, false)
	grpcH2Data(t, p, 1, true, false, grpcEnvelope(t, bytes.Repeat([]byte{'x'}, maxHTTPMessageBytes+1), true))
	p.Flush()
	if !errors.Is(p.Err(), ErrHTTPEventLimit) || p.events.output.grpcBuffered != 0 {
		t.Fatalf("gzip expansion: %v", p.Err())
	}
	// A connection's unfinished messages share a 32 MiB byte budget.
	out := newEventOutput(types.ConnectionKey{}, nil, 0)
	for i := 0; i < 5; i++ {
		b, err := out.headers("http/2", uint64(i), true, time.Time{}, http.Header{"Content-Type": {"application/grpc"}}, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		envelope := binary.BigEndian.AppendUint32([]byte{0}, maxHTTPMessageBytes)
		envelope = append(envelope, make([]byte, 8<<20)...)
		err = b.write(envelope)
		if (err != nil) != (i == 4) {
			t.Fatalf("connection bound on %d: %v", i, err)
		}
	}
	out.abort()
	if out.grpcBuffered != 0 {
		t.Fatal("retained reset message")
	}
}
func TestGRPCCoalescedLongStreamAndBackpressure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ch := make(chan *types.DecryptedPacket)
		p := NewHTTP2StreamParser(types.ConnectionKey{}, ch)
		p.EnableHTTPEvents(0)
		// 257 * 64 KiB exceeds 16 MiB cumulatively while each message is bounded.
		payload := bytes.Repeat([]byte{0x42}, 64<<10)
		input := append(grpcEnvelope(t, payload, false), grpcEnvelope(t, nil, false)...)
		done := make(chan struct{})
		go func() {
			p.FeedRequest([]byte(http2.ClientPreface))
			grpcH2Headers(t, p, 1, true, false)
			for i := 0; i < 257; i++ {
				grpcH2Data(t, p, 1, true, false, input)
			}
			grpcH2Data(t, p, 1, true, true, nil)
			close(done)
		}()
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("no backpressure")
		default:
		}
		messages := 0
		for packet := range ch {
			if packet.Metadata["kind"] == "grpc_message" {
				want := payload
				if messages%2 == 1 {
					want = nil
				}
				if !bytes.Equal(packet.Data, want) {
					t.Fatal("message mismatch")
				}
				if packet.Metadata["offset"] != uint64(messages/2*len(input)+(messages%2)*(len(payload)+5)) {
					t.Fatal(packet.Metadata)
				}
				messages++
			}
			if packet.Metadata["kind"] == "end" {
				break
			}
		}
		<-done
		if messages != 514 || p.events.output.grpcBuffered != 0 {
			t.Fatalf("messages=%d", messages)
		}
	})
}

func TestGRPCResetCompressionErrorsAndIsolation(t *testing.T) {
	// Same stream IDs in two connections must keep independent envelopes.
	var parsers []*HTTP2StreamParser
	for conn := 0; conn < 2; conn++ {
		p := NewHTTP2StreamParser(types.ConnectionKey{SrcPort: uint16(40000 + conn)}, nil)
		p.EnableHTTPEvents(0)
		p.FeedRequest([]byte(http2.ClientPreface))
		grpcH2Headers(t, p, 1, true, false)
		grpcH2Headers(t, p, 1, false, false)
		grpcH2Data(t, p, 1, true, false, []byte{0, 0, 0, 0, 9, byte(conn)})
		parsers = append(parsers, p)
	}
	var reset bytes.Buffer
	if err := http2.NewFramer(&reset, nil).WriteRSTStream(1, http2.ErrCodeCancel); err != nil {
		t.Fatal(err)
	}
	parsers[0].FeedResponse(reset.Bytes())
	if parsers[0].events.output.grpcBuffered != 0 || parsers[1].events.output.grpcBuffered != 1 {
		t.Fatal("reset crossed connection boundary")
	}
	for _, p := range parsers {
		p.FinishHTTPEvents("reset")
		if p.events.output.grpcBuffered != 0 {
			t.Fatal("retained reset buffer")
		}
	}
	for _, encoding := range []string{"identity", "snappy", "gzip"} {
		out := newEventOutput(types.ConnectionKey{}, nil, 0)
		b, err := out.headers("http/2", 1, true, time.Time{}, http.Header{"Content-Type": {"application/grpc"}, "Grpc-Encoding": {encoding}}, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		wire := grpcEnvelope(t, []byte("crc"), true)
		if encoding == "gzip" {
			wire[len(wire)-8] ^= 1
		}
		if err = b.write(wire); err == nil {
			t.Fatalf("accepted broken %s message", encoding)
		}
		out.abort()
		if out.grpcBuffered != 0 {
			t.Fatal("error retained data")
		}
	}
}
func FuzzGRPCEnvelopes(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 1, 42})
	f.Add([]byte{0, 255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			return
		}
		o := newEventOutput(types.ConnectionKey{}, nil, 0)
		b, err := o.headers("http/2", 1, true, time.Time{}, http.Header{"Content-Type": {"application/grpc"}, "Grpc-Encoding": {"gzip"}}, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		for len(data) > 0 {
			n := min(len(data), 7)
			if err = b.write(data[:n]); err != nil {
				break
			}
			data = data[n:]
		}
		_ = b.finish("end", nil)
		if o.grpcBuffered != 0 || len(o.active) != 0 {
			t.Fatal("unfinished envelope retained")
		}
	})
}
