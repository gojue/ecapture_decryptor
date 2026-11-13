package ecapture_decryptor

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/gojue/ecapture_decryptor/types"
)

func TestRawOutputFileAndStreamAgree(t *testing.T) {
	for _, tc := range []struct{ capture, protocol string }{
		{"http10_ecapture_dsb.pcapng", "tls"},
		{"http3_loopback_ecapture_dsb.pcapng", "quic"},
	} {
		t.Run(tc.protocol, func(t *testing.T) {
			var outputs [2]map[string][]byte
			for mode := range outputs {
				input, err := os.Open("test/testdata/" + tc.capture)
				if err != nil {
					t.Fatal(err)
				}
				output := make(map[string][]byte)
				emit := func(p *types.DecryptedPacket) error {
					if p.Protocol != tc.protocol {
						return fmt.Errorf("protocol %q", p.Protocol)
					}
					key := fmt.Sprintf("%s/%s/%v", p.ConnectionID(), p.Direction, p.Metadata["stream_id"])
					if p.Metadata["offset"] != uint64(len(output[key])) {
						return errors.New("non-contiguous raw output")
					}
					output[key] = append(output[key], p.Data...)
					return nil
				}
				options := types.DecryptOptions{RawChunks: true}
				if mode == 0 {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					err = DecryptPcapngStreamWithOptions(ctx, input, emit, options)
					cancel()
				} else {
					packets := make(chan *types.DecryptedPacket, 16)
					done := make(chan error, 1)
					go func() {
						var first error
						for p := range packets {
							if e := emit(p); first == nil {
								first = e
							}
						}
						done <- first
					}()
					err = DecryptWithConfig(NewDecryptorConfig().WithPcapReader(input).WithPacketChan(packets).
						WithLogger(log.New(io.Discard, "", 0)).WithOptions(options))
					close(packets)
					err = errors.Join(err, <-done)
				}
				_ = input.Close()
				if err != nil {
					t.Fatal(err)
				}
				if len(output) < 2 {
					t.Fatal("missing bidirectional raw output")
				}
				outputs[mode] = output
			}
			if len(outputs[0]) != len(outputs[1]) {
				t.Fatal("different stream counts")
			}
			for key, data := range outputs[0] {
				if !bytes.Equal(data, outputs[1][key]) {
					t.Fatal("file and streaming raw bytes differ")
				}
			}
		})
	}
}

func TestRawStreamCallbackFailureDrainsProducers(t *testing.T) {
	input, err := os.Open("test/testdata/http10_ecapture_dsb.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	want := errors.New("consumer stopped")
	calls := 0
	err = DecryptPcapngStreamWithOptions(ctx, input, func(*types.DecryptedPacket) error {
		calls++
		return want
	}, types.DecryptOptions{RawChunks: true})
	if !errors.Is(err, want) || !errors.Is(err, ErrEmitFailed) || errors.Is(err, ErrStreamCanceled) || errors.Is(err, context.DeadlineExceeded) || calls != 1 {
		t.Fatalf("callback failure: calls=%d err=%v", calls, err)
	}
}

func TestHTTPEventsCaptureBeforeEOF(t *testing.T) {
	const base = "test/testdata/http_events_sse"
	packets, clientKeys, serverKeys := quicDSBBlocks(t, base+".pcapng", base+".keys")
	// Feed real packet blocks one at a time. Two distinct dispatches must already
	// be visible before the third SSE record and the HTTP response end arrive.
	synctest.Test(t, func(t *testing.T) {
		stream := newLiveStreamWithOptions(t, types.DecryptOptions{HTTPEvents: true})
		data := packets
		idx := 0
		checked := 0
		seen := map[string][]string{}
		openAtTwo := map[string]bool{}
		for len(data) > 0 {
			n := int(binary.LittleEndian.Uint32(data[4:8]))
			stream.write(t, data[:n])
			data = data[n:]
			idx++
			if idx == 2 {
				stream.write(t, clientKeys)
				stream.write(t, serverKeys)
			}
			synctest.Wait()
			for _, p := range stream.packets[checked:] {
				if p.Direction == "response" && p.Metadata["kind"] == "sse" {
					seen[p.Protocol] = append(seen[p.Protocol], string(p.Data))
				}
			}
			checked = len(stream.packets)
			for proto, events := range seen {
				if len(events) == 2 {
					openAtTwo[proto] = true
				}
			}
		}
		stream.assertOpen(t)
		for _, proto := range []string{"http/1.1", "http/2", "http/3"} {
			if !openAtTwo[proto] || !slices.Equal(seen[proto], []string{"one", "two", "three"}) {
				t.Fatalf("%s open=%v events=%v", proto, openAtTwo[proto], seen)
			}
		}
		if err := stream.writer.Close(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if err := <-stream.done; err != nil {
			t.Fatal(err)
		}
	})
}

func TestHTTPEventCaptureAPIs(t *testing.T) {
	cases := []struct {
		base string
		long bool
	}{{"test/testdata/http_events_sse", false}}
	if path := os.Getenv("HTTP_EVENT_LONG_FIXTURE"); path != "" {
		t.Run("raw_QUIC_long", func(t *testing.T) { checkRawLongCapture(t, path) })
		cases = append(cases, struct {
			base string
			long bool
		}{path, true})
	}
	for _, tc := range cases {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("long=%t/stream=%t", tc.long, stream), func(t *testing.T) {
				keylog, err := os.ReadFile(tc.base + ".keys")
				if err != nil {
					t.Fatal(err)
				}
				f, err := os.Open(tc.base + ".pcapng")
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				type bodyState struct {
					n          uint64
					sse, ended bool
					events     []string
				}
				bodies := map[string]*bodyState{}
				protocols := map[string]int{}
				check := func(p *types.DecryptedPacket) error {
					if p.Direction == "request" {
						return nil
					}
					id, ok := p.Metadata["stream_id"].(uint64)
					if !ok {
						return errors.New("missing stream ID")
					}
					key := fmt.Sprintf("%s/%d", p.ConnectionID(), id)
					b := bodies[key]
					kind := p.Metadata["kind"]
					if kind == "headers" {
						if b != nil {
							return errors.New("duplicate headers")
						}
						h := p.Metadata["headers"].(http.Header)
						b = &bodyState{sse: h.Get("Content-Type") == "text/event-stream"}
						bodies[key] = b
						protocols[p.Protocol]++
					}
					if b == nil || b.ended {
						return fmt.Errorf("event %v outside message", kind)
					}
					switch kind {
					case "body_chunk":
						if p.Metadata["offset"] != b.n {
							return errors.New("noncontiguous HTTP body")
						}
						for i, v := range p.Data {
							pos := int(b.n) + i
							if b.sse {
								const want = "data: one\n\ndata: two\n\ndata: three\n\n"
								if pos >= len(want) || v != want[pos] {
									return errors.New("SSE body mismatch")
								}
							} else if v != byte(pos%251) {
								return fmt.Errorf("long body mismatch at %d", pos)
							}
						}
						b.n += uint64(len(p.Data))
					case "sse":
						b.events = append(b.events, string(p.Data))
					case "end":
						b.ended = true
						if p.Metadata["offset"] != b.n {
							return errors.New("wrong terminal offset")
						}
						if b.sse {
							if b.n != uint64(len("data: one\n\ndata: two\n\ndata: three\n\n")) || !slices.Equal(b.events, []string{"one", "two", "three"}) {
								return fmt.Errorf("SSE end: bytes=%d events=%v", b.n, b.events)
							}
						} else if b.n != 17<<20+37 {
							return fmt.Errorf("long body length %d", b.n)
						}
					case "headers", "trailers":
					default:
						return fmt.Errorf("unexpected event %v", kind)
					}
					return nil
				}
				options := types.DecryptOptions{HTTPEvents: true}
				if stream {
					// Add a DSB immediately after the section header. Replay the large file
					// without seeking or copying it into a second in-memory capture.
					var first [12]byte
					if _, err := io.ReadFull(f, first[:]); err != nil {
						t.Fatal(err)
					}
					size := int(binary.LittleEndian.Uint32(first[4:8]))
					if size < 12 || size > 1<<20 {
						t.Fatal("invalid fixture section")
					}
					rest := make([]byte, size-12)
					if _, err := io.ReadFull(f, rest); err != nil {
						t.Fatal(err)
					}
					var dsb bytes.Buffer
					var w *pcapgo.NgWriter
					w, err = pcapgo.NewNgWriter(&dsb, layers.LinkTypeEthernet)
					if err != nil {
						t.Fatal(err)
					}
					if err = w.Flush(); err != nil {
						t.Fatal(err)
					}
					dsb.Reset()
					if err = w.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, keylog); err != nil {
						t.Fatal(err)
					}
					if err = w.Flush(); err != nil {
						t.Fatal(err)
					}
					input := io.MultiReader(bytes.NewReader(first[:]), bytes.NewReader(rest), &dsb, f)
					err = DecryptPcapngStreamWithOptions(context.Background(), io.NopCloser(input), check, options)
				} else {
					ch := make(chan *types.DecryptedPacket, 8)
					done := make(chan error, 1)
					go func() {
						var first error
						for p := range ch {
							if first == nil {
								first = check(p)
							}
						}
						done <- first
					}()
					err = DecryptWithConfig(NewDecryptorConfig().WithSSLKeyLog(bytes.NewReader(keylog)).WithPcapReader(f).WithPacketChan(ch).WithOptions(options).WithLogger(log.New(io.Discard, "", 0)))
					close(ch)
					err = errors.Join(err, <-done)
				}
				if err != nil {
					t.Fatal(err)
				}
				want := 1
				if tc.long {
					want = 2
				}
				for _, proto := range []string{"http/1.1", "http/2", "http/3"} {
					if protocols[proto] != want {
						t.Fatalf("%s: got %d responses", proto, protocols[proto])
					}
				}
				for _, b := range bodies {
					if !b.ended {
						t.Fatal("missing end")
					}
				}
			})
		}
	}
}

func TestHTTPEventsCancelAndCallbackFailure(t *testing.T) {
	const base = "test/testdata/http_events_sse"
	packets, clientKeys, serverKeys := quicDSBBlocks(t, base+".pcapng", base+".keys")
	for _, cancelled := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelled), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r, w := io.Pipe()
				defer w.Close()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				want := errors.New("stop on SSE")
				done := make(chan error, 1)
				calls := 0
				go func() {
					done <- DecryptPcapngStreamWithOptions(ctx, r, func(p *types.DecryptedPacket) error {
						if p.Metadata["kind"] == "sse" {
							calls++
							if cancelled {
								cancel()
							} else {
								return want
							}
						}
						return nil
					}, types.DecryptOptions{HTTPEvents: true})
				}()
				go func() { _, _ = w.Write(packets); _, _ = w.Write(clientKeys); _, _ = w.Write(serverKeys) }()
				synctest.Wait()
				select {
				case err := <-done:
					if cancelled {
						want = context.Canceled
					}
					if !errors.Is(err, want) || calls != 1 {
						t.Fatalf("calls=%d err=%v", calls, err)
					}
				default:
					t.Fatal("open capture did not stop")
				}
			})
		})
	}
}

func TestHTTPEventOptionsConflict(t *testing.T) {
	for _, options := range []types.DecryptOptions{{HTTPEvents: true, RawChunks: true}, {MaxDecodedBodyBytes: 1}, {HTTPEvents: true, MaxDecodedBodyBytes: -1}} {
		if err := DecryptWithConfig(NewDecryptorConfig().WithOptions(options)); err == nil {
			t.Fatal("file API accepted conflicting output options")
		}
		if err := DecryptPcapngStreamWithOptions(context.Background(), io.NopCloser(bytes.NewReader(nil)), func(*types.DecryptedPacket) error { return nil }, options); err == nil {
			t.Fatal("stream API accepted conflicting output options")
		}
	}
}

// Verify the raw path independently of the HTTP parser: strip HTTP/3 framing
// from the long response and check every DATA byte sent by the fixture peer.
func checkRawLongCapture(t *testing.T, base string) {
	f, err := os.Open(base + ".pcapng")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	keys, err := os.Open(base + ".keys")
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Close()
	ch := make(chan *types.DecryptedPacket, 8)
	done := make(chan error, 1)
	go func() {
		done <- DecryptWithConfig(NewDecryptorConfig().WithPcapReader(f).WithSSLKeyLog(keys).WithPacketChan(ch).WithOptions(types.DecryptOptions{RawChunks: true}).WithLogger(log.New(io.Discard, "", 0)))
		close(ch)
	}()
	var wire bytes.Buffer
	ended := false
	invalid := false
	for p := range ch {
		if p.Protocol == "quic" && p.Direction == "response" && p.Metadata["stream_id"] == uint64(4) {
			if ended || p.Metadata["offset"] != uint64(wire.Len()) || wire.Len()+len(p.Data) > 18<<20 {
				invalid = true
				continue
			}
			wire.Write(p.Data)
			ended = p.Metadata["end"] == true
		}
	}
	if err := <-done; err != nil || invalid || !ended {
		t.Fatalf("raw: err=%v invalid=%v fin=%v", err, invalid, ended)
	}
	readInt := func() uint64 {
		b, err := wire.ReadByte()
		if err != nil {
			t.Fatal(err)
		}
		n := 1 << (b >> 6)
		v := uint64(b & 63)
		for i := 1; i < n; i++ {
			b, err = wire.ReadByte()
			if err != nil {
				t.Fatal(err)
			}
			v = v<<8 | uint64(b)
		}
		return v
	}
	pos := 0
	for wire.Len() > 0 {
		typ, n := readInt(), readInt()
		if n > uint64(wire.Len()) {
			t.Fatal("truncated raw HTTP/3 frame")
		}
		payload := wire.Next(int(n))
		if typ == 0 {
			for _, v := range payload {
				if v != byte(pos%251) {
					t.Fatal("raw DATA mismatch at", pos)
				}
				pos++
			}
		}
	}
	if pos != 17<<20+37 {
		t.Fatal("raw DATA length", pos)
	}
}

func TestWebSocketGRPCCaptureAPIs(t *testing.T) {
	const keyPath = "test/testdata/websocket_grpc.keys"
	for _, name := range []string{"websocket", "grpc_h2"} {
		for _, streaming := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", name, streaming), func(t *testing.T) {
				options := types.DecryptOptions{HTTPEvents: name == "grpc_h2"}
				var packets []*types.DecryptedPacket
				path := "test/testdata/" + name + ".pcapng"
				if streaming {
					capture, client, server := quicDSBBlocks(t, path, keyPath)
					// Non-seek input, with both secrets arriving after the last network packet.
					capture = append(capture, client...)
					capture = append(capture, server...)
					err := DecryptPcapngStreamWithOptions(context.Background(), io.NopCloser(bytes.NewBuffer(capture)), func(p *types.DecryptedPacket) error { packets = append(packets, p); return nil }, options)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					keys, err := os.ReadFile(keyPath)
					if err != nil {
						t.Fatal(err)
					}
					f, err := os.Open(path)
					if err != nil {
						t.Fatal(err)
					}
					defer f.Close()
					ch := make(chan *types.DecryptedPacket)
					done := make(chan struct{})
					go func() {
						for p := range ch {
							packets = append(packets, p)
						}
						close(done)
					}()
					err = DecryptWithConfig(NewDecryptorConfig().WithSSLKeyLog(bytes.NewReader(keys)).WithPcapReader(f).WithPacketChan(ch).WithOptions(options).WithLogger(log.New(io.Discard, "", 0)))
					close(ch)
					<-done
					if err != nil {
						t.Fatal(err)
					}
				}
				counts := map[string]int{}
				connections := map[string]bool{}
				messages, ends, controls := 0, 0, 0
				for _, p := range packets {
					connections[p.ConnectionID()] = true
					if name == "websocket" {
						switch p.Metadata["kind"] {
						case "upgrade":
						case "control":
							controls++
						case "message":
							key := p.ConnectionID() + "/" + p.Direction
							want := strings.Repeat(fmt.Sprintf("websocket-%s-%d-", p.Direction, counts[key]), 100)
							if string(p.Data) != want || p.Metadata["compressed"] != true {
								t.Fatalf("WebSocket body mismatch: %v", p.Metadata)
							}
							counts[key]++
							messages++
						default:
							t.Fatal(p.Metadata)
						}
					} else {
						id := p.Metadata["stream_id"].(uint64)
						key := fmt.Sprintf("%s/%d/%s", p.ConnectionID(), id, p.Direction)
						switch p.Metadata["kind"] {
						case "grpc_message":
							text := fmt.Sprintf("%s-%d-%d", p.Direction, id, counts[key])
							want := append([]byte{0x0a, byte(len(text))}, []byte(text)...)
							if !bytes.Equal(p.Data, want) || p.Metadata["message_index"] != uint64(counts[key]) {
								t.Fatalf("gRPC message mismatch: %v", p.Metadata)
							}
							counts[key]++
							messages++
						case "end":
							ends++
							if p.Direction == "response" {
								want := uint32(0)
								if id == 3 {
									want = 5
								}
								if id == 9 {
									want = 13
								}
								if p.Metadata["grpc_status"] != want {
									t.Fatalf("status mismatch: %v", p.Metadata)
								}
							}
						case "headers", "body_chunk", "trailers":
						default:
							t.Fatal(p.Metadata)
						}
					}
				}
				if name == "websocket" {
					if len(connections) != 2 || messages != 12 || controls < 16 {
						t.Fatalf("connections=%d messages=%d controls=%d", len(connections), messages, controls)
					}
				} else if len(connections) != 1 || messages != 16 || ends != 10 {
					t.Fatalf("connections=%d messages=%d ends=%d", len(connections), messages, ends)
				}
			})
		}
	}
}

func TestGRPCCaptureMessagesBeforeEOF(t *testing.T) {
	packets, client, server := quicDSBBlocks(t, "test/testdata/grpc_h2.pcapng", "test/testdata/websocket_grpc.keys")
	synctest.Test(t, func(t *testing.T) {
		stream := newLiveStreamWithOptions(t, types.DecryptOptions{HTTPEvents: true})
		data := packets
		block, checked := 0, 0
		early := false
		messages := 0
		ended := map[string]bool{}
		for len(data) > 0 {
			n := int(binary.LittleEndian.Uint32(data[4:8]))
			stream.write(t, data[:n])
			data = data[n:]
			block++
			if block == 2 {
				stream.write(t, client)
				stream.write(t, server)
			}
			synctest.Wait()
			for _, p := range stream.packets[checked:] {
				key := fmt.Sprintf("%v/%s", p.Metadata["stream_id"], p.Direction)
				if p.Metadata["kind"] == "end" {
					ended[key] = true
				}
				if p.Metadata["kind"] == "grpc_message" {
					if ended[key] {
						t.Fatal("message after end")
					}
					messages++
				}
			}
			checked = len(stream.packets)
			if messages > 0 && messages < 16 {
				early = true
			}
		}
		stream.assertOpen(t)
		if !early || messages != 16 {
			t.Fatalf("incremental=%t messages=%d", early, messages)
		}
		_ = stream.writer.Close()
		synctest.Wait()
		if err := <-stream.done; err != nil {
			t.Fatal(err)
		}
	})
}

func TestApplicationProtocolOptionsBeforeInput(t *testing.T) {
	for _, options := range []types.DecryptOptions{
		{UDPProtocol: "auto"}, {UDPProtocol: "dtls", ApplicationProtocol: "dot"}, {UDPProtocol: "dtls", TLSUpgrade: "smtp"}, {UDPProtocol: "dtls", HTTPEvents: true}, {UDPProtocol: "dtls", MaxDecodedBodyBytes: 1},
		{TLSUpgrade: "auto"}, {TLSUpgrade: "smtp", ApplicationProtocol: "doq"},
		{ApplicationProtocol: "smtp"}, {ApplicationProtocol: "mqtt", RawChunks: true}, {ApplicationProtocol: "doh", HTTPEvents: true}, {ApplicationProtocol: "redis", MaxDecodedBodyBytes: 1},
	} {
		calls := 0
		err := DecryptPcapngStreamWithOptions(context.Background(), io.NopCloser(nil), func(*types.DecryptedPacket) error { calls++; return nil }, options)
		if err == nil || calls != 0 {
			t.Fatalf("invalid options consumed input: %+v", options)
		}
	}
	for _, options := range []types.DecryptOptions{{UDPProtocol: "dtls"}, {ApplicationProtocol: "dot"}, {TLSUpgrade: "smtp"}, {TLSUpgrade: "https-connect", RawChunks: true}} {
		if err := DecryptWithConfig(NewDecryptorConfig().WithOptions(options)); err == nil || !strings.Contains(err.Error(), "requires a packet channel") {
			t.Fatal("explicit parsing without output accepted", err)
		}
	}
}

func TestD08ApplicationCaptureAPIs(t *testing.T) {
	for _, tc := range []struct {
		name, selected, keys, protocol string
		count, connections             int
	}{
		{"mqtt", "mqtt", "mqtt_redis", "mqtt", 20, 1}, {"redis", "redis", "mqtt_redis", "redis", 28, 2},
		{"dot", "dot", "dns", "dns", 8, 2}, {"doh1", "doh", "dns", "dns", 4, 1},
		{"doh2", "doh", "dns", "dns", 4, 1}, {"doq", "doq", "dns", "dns", 8, 2},
		{"doh3", "doh", "dns", "dns", 4, 1},
	} {
		for _, mode := range []int{0, 1, 2} {
			t.Run(fmt.Sprintf("%s/mode=%d", tc.name, mode), func(t *testing.T) {
				options := types.DecryptOptions{ApplicationProtocol: tc.selected}
				path := "test/testdata/d08_" + tc.name + ".pcapng"
				keyPath := "test/testdata/d08_" + tc.keys + ".keys"
				var packets []*types.DecryptedPacket
				if mode != 0 {
					capture, client, server := quicDSBBlocks(t, path, keyPath)
					if mode == 2 {
						client, server = server, client
					} // Server secrets may precede client secrets.
					synctest.Test(t, func(t *testing.T) {
						stream := newLiveStreamWithOptions(t, options)
						stream.write(t, capture)
						synctest.Wait()
						if len(stream.packets) != 0 {
							t.Fatal("output without keys")
						}
						stream.write(t, client)
						stream.write(t, server)
						synctest.Wait()
						stream.assertOpen(t)
						if len(stream.packets) != tc.count {
							t.Fatalf("before EOF: %d messages", len(stream.packets))
						}
						stream.write(t, client)
						stream.write(t, server)
						if err := stream.writer.Close(); err != nil {
							t.Fatal(err)
						}
						synctest.Wait()
						if err := <-stream.done; err != nil {
							t.Fatal(err)
						}
						packets = stream.packets
					})
				} else {
					keys, err := os.ReadFile(keyPath)
					if err != nil {
						t.Fatal(err)
					}
					f, err := os.Open(path)
					if err != nil {
						t.Fatal(err)
					}
					defer f.Close()
					ch := make(chan *types.DecryptedPacket)
					done := make(chan struct{})
					go func() {
						for p := range ch {
							packets = append(packets, p)
						}
						close(done)
					}()
					err = DecryptWithConfig(NewDecryptorConfig().WithSSLKeyLog(bytes.NewReader(keys)).WithPcapReader(f).WithPacketChan(ch).WithOptions(options).WithLogger(log.New(io.Discard, "", 0)))
					close(ch)
					<-done
					if err != nil {
						t.Fatal(err)
					}
				}
				connections := map[string]bool{}
				publications, duplicates, push, attribute := 0, 0, 0, 0
				dnsRequests := map[string]string{}
				dnsResponses := map[string]bool{}
				for _, p := range packets {
					if p.Protocol != tc.protocol {
						t.Fatalf("wrong parser: %s", p.Protocol)
					}
					connections[p.ConnectionID()] = true
					if tc.protocol == "dns" {
						if p.Metadata["transport"] != tc.selected || p.Metadata["kind"] != "message" {
							t.Fatal(p.Metadata)
						}
						questions := p.Metadata["questions"].([]map[string]any)
						if len(questions) != 1 || questions[0]["type"] != uint16(1) || questions[0]["class"] != uint16(1) {
							t.Fatal(p.Metadata)
						}
						name := questions[0]["name"].(string)
						if !strings.HasPrefix(name, tc.name+"-") || !strings.HasSuffix(name, ".example.") {
							t.Fatal(name)
						}
						key := fmt.Sprintf("%s/%v", p.ConnectionID(), p.Metadata["request_id"])
						if p.Direction == "request" {
							if _, exists := dnsRequests[key]; exists {
								t.Fatal("duplicate DNS request association")
							}
							dnsRequests[key] = name
							if p.Metadata["qr"] != false || binary.BigEndian.Uint16(p.Data[2:4])&0x8000 != 0 {
								t.Fatal("query wire QR changed")
							}
						} else {
							if p.Metadata["matched"] != true || dnsRequests[key] != name || dnsResponses[key] {
								t.Fatal("incorrect DNS response association", p.Metadata)
							}
							dnsResponses[key] = true
							answers := p.Metadata["answers"].([]map[string]any)
							if len(answers) != 1 || answers[0]["address"] != "192.0.2.1" || answers[0]["ttl"] != uint32(60) || p.Metadata["qr"] != true || !bytes.Equal(p.Data[len(p.Data)-4:], []byte{192, 0, 2, 1}) {
								t.Fatal("DNS answer changed", p.Metadata)
							}
						}
					}
					if tc.name == "mqtt" && p.Metadata["packet_name"] == "PUBLISH" {
						publications++
						offset := p.Metadata["payload_offset"].(int)
						payload := p.Data[offset:]
						if p.Metadata["dup"] == true {
							duplicates++
							if string(payload) != "qos1" {
								t.Fatal("DUP payload changed")
							}
						}
						switch p.Metadata["qos"] {
						case uint8(0):
							if len(payload) != 512 {
								t.Fatal("MQTT long payload truncated")
							}
							for i, v := range payload {
								if v != byte(i%256) {
									t.Fatal("MQTT payload changed")
								}
							}
						case uint8(1), uint8(2):
							if string(payload) != "qos1" && string(payload) != "qos2" && string(payload) != "push" {
								t.Fatal("MQTT payload changed")
							}
						default:
							t.Fatal(p.Metadata)
						}
					}
					if tc.name == "redis" {
						if p.Metadata["kind"] == "push" {
							push++
							if p.Metadata["push_type"] == "message" && !bytes.Contains(p.Data, []byte("server-push")) {
								t.Fatal("Redis push changed")
							}
						}
						if p.Metadata["kind"] == "attribute" {
							attribute++
						}
						if p.Metadata["kind"] == "response" && p.Metadata["command"] == "GET" && !bytes.Contains(p.Data, []byte{0, 'f', 'i', 'x', 't', 'u', 'r', 'e', '\r', '\n', 255}) {
							t.Fatal("Redis binary response changed")
						}
					}
				}
				if len(packets) != tc.count || len(connections) != tc.connections {
					t.Fatalf("packets=%d connections=%d", len(packets), len(connections))
				}
				if tc.protocol == "dns" && (len(dnsRequests) != tc.count/2 || len(dnsResponses) != len(dnsRequests)) {
					t.Fatal("missing DNS transactions")
				}
				if tc.name == "mqtt" && (publications != 5 || duplicates != 1) {
					t.Fatalf("publishes %d DUP %d", publications, duplicates)
				}
				if tc.name == "redis" && (push != 9 || attribute != 1) {
					t.Fatalf("push %d attributes %d", push, attribute)
				}
			})
		}
	}
}

func TestD08CancelAndCallbackFailure(t *testing.T) {
	for _, tc := range []struct{ name, selected, keys string }{
		{"dot", "dot", "dns"}, {"doh1", "doh", "dns"}, {"doh2", "doh", "dns"},
		{"doq", "doq", "dns"}, {"doh3", "doh", "dns"},
		{"mqtt", "mqtt", "mqtt_redis"}, {"redis", "redis", "mqtt_redis"},
	} {
		packets, clientKeys, serverKeys := quicDSBBlocks(t, "test/testdata/d08_"+tc.name+".pcapng", "test/testdata/d08_"+tc.keys+".keys")
		for _, canceled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cancel=%t", tc.name, canceled), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					r, w := io.Pipe()
					defer w.Close()
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					want := errors.New("consumer stopped")
					done := make(chan error, 1)
					calls := 0
					go func() {
						done <- DecryptPcapngStreamWithOptions(ctx, r, func(*types.DecryptedPacket) error {
							calls++
							if canceled {
								cancel()
								return nil
							}
							return want
						}, types.DecryptOptions{ApplicationProtocol: tc.selected})
					}()
					go func() { _, _ = w.Write(packets); _, _ = w.Write(clientKeys); _, _ = w.Write(serverKeys) }()
					synctest.Wait()
					select {
					case err := <-done:
						if canceled {
							want = context.Canceled
						}
						if !errors.Is(err, want) || calls != 1 {
							t.Fatalf("calls=%d err=%v", calls, err)
						}
					default:
						t.Fatal("open capture did not stop")
					}
				})
			})
		}
	}
}

func TestD09UpgradeCaptureAPIs(t *testing.T) {
	for _, name := range []string{"smtp", "imap", "pop3", "ldap", "postgres", "mysql", "connect", "https_connect"} {
		for _, output := range []string{"messages", "raw", "events"} {
			for _, streaming := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/stream=%t", name, output, streaming), func(t *testing.T) {
					options := types.DecryptOptions{TLSUpgrade: strings.ReplaceAll(name, "_", "-"), RawChunks: output == "raw", HTTPEvents: output == "events"}
					path := "test/testdata/d09_" + name + ".pcapng"
					depth := 1
					if name == "https_connect" {
						depth = 2
					}
					var packets []*types.DecryptedPacket
					if streaming {
						capture, client, server := quicDSBBlocks(t, path, "test/testdata/d09_upgrade.keys")
						var innerClient, innerServer []byte
						if depth == 2 {
							_, innerClient, innerServer = quicDSBBlocks(t, path, "test/testdata/d09_inner.keys")
						}
						synctest.Test(t, func(t *testing.T) {
							stream := newLiveStreamWithOptions(t, options)
							stream.write(t, capture)
							stream.write(t, server)
							stream.write(t, client)
							synctest.Wait()
							stream.assertOpen(t)
							if depth == 2 {
								outer := false
								for _, p := range stream.packets {
									if p.Metadata["tls_depth"] == 2 {
										t.Fatal("inner output without inner secrets")
									}
									outer = outer || p.Protocol == "tls" && p.Metadata["tls_depth"] == 1 && len(p.Data) > 0
								}
								if !outer {
									t.Fatal("outer plaintext withheld while inner keys were missing")
								}
								stream.write(t, innerClient)
								stream.write(t, innerServer)
							}
							synctest.Wait()
							stream.assertOpen(t)
							if !slices.ContainsFunc(stream.packets, func(p *types.DecryptedPacket) bool { return p.Metadata["tls_depth"] == depth && len(p.Data) > 0 }) {
								t.Fatal("upgraded output delayed until EOF")
							}
							stream.write(t, client)
							stream.write(t, server)
							if err := stream.writer.Close(); err != nil {
								t.Fatal(err)
							}
							synctest.Wait()
							if err := <-stream.done; err != nil {
								t.Fatal(err)
							}
							packets = stream.packets
						})
					} else {
						packets, _ = decryptD09Capture(t, path, options, true)
					}
					connections := map[string]bool{}
					plaintext := map[string][]byte{}
					inner := map[string][]byte{}
					var innerID string
					ends := 0
					for _, p := range packets {
						connections[p.ConnectionID()] = true
						if p.Protocol == "starttls" {
							if p.Metadata["tls_depth"] != depth-1 || p.Metadata["upgrade_protocol"] != options.TLSUpgrade {
								t.Fatal(p.Metadata)
							}
							key := p.ConnectionID() + "/" + p.Direction
							plaintext[key] = append(plaintext[key], p.Data...)
						}
						if p.Metadata["tls_depth"] != depth {
							continue
						}
						if p.Metadata["parent_tls_depth"] != depth-1 {
							t.Fatal("missing parent layer", p.Metadata)
						}
						if innerID != "" && innerID != p.ConnectionID() {
							t.Fatal("rejected connection produced TLS output")
						}
						innerID = p.ConnectionID()
						if output == "events" {
							if p.Metadata["kind"] == "end" {
								ends++
							}
							if p.Metadata["kind"] != "body_chunk" {
								continue
							}
						} else if output == "raw" {
							if p.Protocol != "tls" || p.Metadata["offset"] != uint64(len(inner[p.Direction])) {
								t.Fatal(p.Metadata)
							}
						} else if p.Protocol != "http/1.1" {
							t.Fatal(p.Protocol)
						}
						inner[p.Direction] = append(inner[p.Direction], p.Data...)
					}
					if len(connections) != 2 || innerID == "" {
						t.Fatalf("connections=%d upgraded=%q", len(connections), innerID)
					}
					refused := false
					for key, data := range plaintext {
						if strings.HasPrefix(key, innerID+"/") && bytes.Contains(data, []byte("HTTP/1.1 200 OK")) {
							t.Fatal("decrypted application bytes leaked into negotiation output")
						}
						refused = refused || bytes.Contains(data, []byte("\x16\x03\x03\x00\x10not-a-TLS-record/"+name))
					}
					if !refused {
						t.Fatal("rejected negotiation lost plaintext fake-TLS bytes")
					}
					for _, direction := range []string{"request", "response"} {
						body := []byte("d09/" + name + "/" + direction + "\x00\r\n\xff")
						want := body
						if output != "events" {
							header := "HTTP/1.1 200 OK\r\n"
							if direction == "request" {
								header = "POST /d09/" + name + " HTTP/1.1\r\nHost: fixture\r\n"
							}
							want = append([]byte(fmt.Sprintf("%sContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", header, len(body))), body...)
						}
						if !bytes.Equal(inner[direction], want) {
							t.Fatalf("%s bytes: %q, want %q", direction, inner[direction], want)
						}
					}
					if output == "events" && ends != 2 {
						t.Fatalf("HTTP terminal events %d", ends)
					}
				})
			}
		}
	}
}

func decryptD09Capture(t *testing.T, path string, options types.DecryptOptions, innerKeys bool) ([]*types.DecryptedPacket, error) {
	t.Helper()
	keys, err := os.ReadFile("test/testdata/d09_upgrade.keys")
	if err != nil {
		t.Fatal(err)
	}
	if innerKeys {
		inner, err := os.ReadFile("test/testdata/d09_inner.keys")
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, inner...)
	}
	packets, err := decryptTLSCapture(t, path, keys, options)
	if innerKeys && err != nil {
		t.Fatal(err)
	}
	return packets, err
}

func decryptTLSCapture(t *testing.T, path string, keys []byte, options types.DecryptOptions) ([]*types.DecryptedPacket, error) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ch := make(chan *types.DecryptedPacket)
	done := make(chan struct{})
	var packets []*types.DecryptedPacket
	go func() {
		for p := range ch {
			packets = append(packets, p)
		}
		close(done)
	}()
	err = DecryptWithConfig(NewDecryptorConfig().WithPcapReader(f).WithSSLKeyLog(bytes.NewReader(keys)).WithPacketChan(ch).WithOptions(options).WithLogger(log.New(io.Discard, "", 0)))
	close(ch)
	<-done
	return packets, err
}

func TestD09MissingInnerSecretsPreservesOuter(t *testing.T) {
	const path = "test/testdata/d09_https_connect.pcapng"
	options := types.DecryptOptions{TLSUpgrade: "https-connect", KeyWaitTimeout: time.Second}
	full, _ := decryptD09Capture(t, path, options, true)
	var diagnostics []types.Diagnostic
	var mu sync.Mutex
	options.OnDiagnostic = func(d types.Diagnostic) { mu.Lock(); defer mu.Unlock(); diagnostics = append(diagnostics, d) }
	partial, err := decryptD09Capture(t, path, options, false)
	if err == nil {
		t.Fatal("missing inner keys reported success")
	}
	outer := func(packets []*types.DecryptedPacket) map[string][]byte {
		result := map[string][]byte{}
		for _, p := range packets {
			if p.Protocol == "tls" && p.Metadata["tls_depth"] == 1 {
				key := p.ConnectionID() + "/" + p.Direction
				result[key] = append(result[key], p.Data...)
			}
		}
		return result
	}
	want, got := outer(full), outer(partial)
	if len(want) != 4 || len(want) != len(got) {
		t.Fatal("outer directions lost", len(want), len(got))
	}
	for key, data := range want {
		if !bytes.Equal(data, got[key]) {
			t.Fatal("available outer bytes changed without inner secrets")
		}
	}
	for _, p := range partial {
		if p.Metadata["tls_depth"] == 2 {
			t.Fatal("unauthenticated inner plaintext emitted")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.ContainsFunc(diagnostics, func(d types.Diagnostic) bool { return d.Stage == "tunnel" && d.Code == "inner_tls_unavailable" }) {
		t.Fatal("missing fixed inner TLS diagnostic", diagnostics)
	}
}

func TestD09CancelAndCallbackFailure(t *testing.T) {
	for _, name := range []string{"smtp", "imap", "pop3", "ldap", "postgres", "mysql", "connect", "https_connect"} {
		path := "test/testdata/d09_" + name + ".pcapng"
		capture, client, server := quicDSBBlocks(t, path, "test/testdata/d09_upgrade.keys")
		var innerClient, innerServer []byte
		if name == "https_connect" {
			_, innerClient, innerServer = quicDSBBlocks(t, path, "test/testdata/d09_inner.keys")
		}
		for _, canceled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cancel=%t", name, canceled), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					r, w := io.Pipe()
					defer w.Close()
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					want := errors.New("upgraded consumer stopped")
					done := make(chan error, 1)
					calls, stopped := 0, false
					go func() {
						done <- DecryptPcapngStreamWithOptions(ctx, r, func(p *types.DecryptedPacket) error {
							if stopped {
								calls++
							}
							if p.Protocol == "http/1.1" && !stopped {
								stopped = true
								calls++
								if canceled {
									cancel()
								} else {
									return want
								}
							}
							return nil
						}, types.DecryptOptions{TLSUpgrade: strings.ReplaceAll(name, "_", "-")})
					}()
					go func() {
						for _, b := range [][]byte{capture, client, server, innerClient, innerServer} {
							if len(b) > 0 {
								_, _ = w.Write(b)
							}
						}
					}()
					synctest.Wait()
					select {
					case err := <-done:
						if canceled {
							want = context.Canceled
						}
						if !errors.Is(err, want) || calls != 1 {
							t.Fatalf("calls=%d err=%v", calls, err)
						}
					default:
						t.Fatal("upgraded stream did not stop")
					}
				})
			})
		}
	}
}

// tlsFixtureDSB constructs only a DSB, for appending to the little-endian
// independently captured fixtures without rewriting their network packets.
func tlsFixtureDSB(t *testing.T, keys []byte) []byte {
	t.Helper()
	var encoded bytes.Buffer
	w, err := pcapgo.NewNgWriter(&encoded, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	encoded.Reset()
	if err := w.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, keys); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(encoded.Bytes())
}

func d10HTTP(mode string, index int) (request, response, body []byte) {
	request = fmt.Appendf(nil, "GET /d10/%s/%d HTTP/1.1\r\nHost: fixture\r\n\r\n", mode, index)
	body = fmt.Appendf(nil, "d10/%s/%d\n", mode, index)
	response = fmt.Appendf(nil, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	return
}

func TestD10TLSCaptureAPIs(t *testing.T) {
	for _, tc := range []struct {
		mode                string
		connections, rounds int
	}{
		{"ku_aes128", 1, 6}, {"ku_aes256", 1, 6}, {"ku_chacha", 1, 6},
		{"hrr", 1, 1}, {"early", 4, 1}, {"tls12_resume", 2, 1}, {"grease", 1, 1},
		{"ech_accepted", 1, 1}, {"ech_rejected", 0, 0},
		{"hrr_early", 2, 1}, {"ech_hrr_accepted", 1, 1}, {"ech_hrr_rejected", 0, 0},
	} {
		keyPath := "test/testdata/d10_openssl.keys"
		if strings.HasPrefix(tc.mode, "ech_") {
			keyPath = "test/testdata/d10_ech.keys"
		}
		if tc.mode == "hrr_early" {
			keyPath = "test/testdata/d10_hrr_early.keys"
		}
		if strings.HasPrefix(tc.mode, "ech_hrr_") {
			keyPath = "test/testdata/d10_ech_hrr.keys"
		}
		echAccepted := strings.HasPrefix(tc.mode, "ech_") && strings.HasSuffix(tc.mode, "accepted")
		echRejected := strings.HasPrefix(tc.mode, "ech_") && strings.HasSuffix(tc.mode, "rejected")
		keys, err := os.ReadFile(keyPath)
		if err != nil {
			t.Fatal(err)
		}
		path := "test/testdata/d10_" + tc.mode + ".pcapng"
		for _, output := range []string{"messages", "raw", "events"} {
			modes := []string{"file", "late_keys"}
			if tc.mode == "hrr_early" {
				modes = append(modes, "late_handshake")
			}
			for _, mode := range modes {
				streaming := mode != "file"
				t.Run(fmt.Sprintf("%s/%s/%s", tc.mode, output, mode), func(t *testing.T) {
					var mu sync.Mutex
					var diagnostics []types.Diagnostic
					options := types.DecryptOptions{RawChunks: output == "raw", HTTPEvents: output == "events", OnDiagnostic: func(d types.Diagnostic) {
						mu.Lock()
						defer mu.Unlock()
						diagnostics = append(diagnostics, d)
					}}
					var packets []*types.DecryptedPacket
					var result error
					if !streaming {
						packets, result = decryptTLSCapture(t, path, keys, options)
					} else {
						capture, err := os.ReadFile(path)
						if err != nil {
							t.Fatal(err)
						}
						// App secrets alone arrive first, followed by handshake/early
						// secrets, and finally the ECH association. No new network packet.
						var groups [3][]byte
						for _, line := range bytes.Split(keys, []byte{'\n'}) {
							f := bytes.Fields(line)
							if len(f) != 3 || f[0][0] == '#' {
								continue
							}
							group := 1
							label := string(f[0])
							if strings.HasSuffix(label, "TRAFFIC_SECRET_0") || label == "CLIENT_RANDOM" {
								group = 0
							} else if strings.HasPrefix(label, "ECH_") || tc.mode == "hrr_early" && label == "CLIENT_EARLY_TRAFFIC_SECRET" {
								group = 2
							}
							groups[group] = append(groups[group], append(bytes.Clone(line), '\n')...)
						}
						if mode == "late_handshake" {
							groups[1], groups[2] = groups[2], groups[1]
						}
						if echRejected {
							// A definitive rejection requires ECH evidence when selecting
							// the outer random; absent evidence is only "unknown".
							groups[0], groups[2] = groups[2], groups[0]
						}
						synctest.Test(t, func(t *testing.T) {
							stream := newLiveStreamWithOptions(t, options)
							stream.write(t, capture)
							for i, group := range groups {
								if len(group) == 0 {
									continue
								}
								stream.write(t, tlsFixtureDSB(t, group))
								synctest.Wait()
								stream.assertOpen(t)
								if echAccepted && i < 2 && len(stream.packets) != 0 {
									t.Fatal("ECH traffic emitted before random association was authenticated")
								}
							}
							if tc.connections != 0 && len(stream.packets) == 0 {
								t.Fatal("TLS output delayed until EOF")
							}
							if output != "raw" {
								complete := 0
								for _, p := range stream.packets {
									if output == "messages" || p.Metadata["kind"] == "end" {
										complete++
									}
								}
								if complete != 2*tc.connections*tc.rounds {
									t.Fatalf("complete HTTP exchanges delayed until EOF: %d", complete)
								}
							}
							before := len(stream.packets)
							stream.write(t, tlsFixtureDSB(t, keys))
							synctest.Wait()
							if len(stream.packets) != before {
								t.Fatal("duplicate DSB repeated TLS output")
							}
							if err := stream.writer.Close(); err != nil {
								t.Fatal(err)
							}
							synctest.Wait()
							result, packets = <-stream.done, stream.packets
							if output != "raw" && len(packets) != before {
								t.Fatal("HTTP output delayed until EOF")
							}
						})
					}
					if result != nil && !echRejected {
						t.Fatal(result)
					}
					type exchange struct {
						request, response []byte
						ends              int
					}
					got := map[string]*exchange{}
					earlyRaw := map[string][]byte{}
					for _, p := range packets {
						if p.Metadata["encryption_level"] == "0rtt" && p.Metadata["early_data"] != "accepted" {
							if output != "raw" || (tc.mode != "early" && tc.mode != "hrr_early") || p.Metadata["early_data"] != "rejected" || p.Direction != "request" || p.Metadata["offset"] != uint64(len(earlyRaw[p.ConnectionID()])) {
								t.Fatal("unexpected rejected early output", p.Metadata)
							}
							earlyRaw[p.ConnectionID()] = append(earlyRaw[p.ConnectionID()], p.Data...)
							continue
						}
						if output == "raw" && p.Metadata["kind"] == "stream_end" {
							continue
						}
						e := got[p.ConnectionID()]
						if e == nil {
							e = &exchange{}
							got[p.ConnectionID()] = e
						}
						data := &e.response
						if p.Direction == "request" {
							data = &e.request
						}
						if output == "raw" {
							if p.Protocol != "tls" || p.Metadata["offset"] != uint64(len(*data)) {
								t.Fatal("noncontiguous TLS raw bytes", p.Metadata)
							}
						} else if p.Protocol != "http/1.1" {
							t.Fatal(p.Protocol)
						}
						if output == "events" {
							switch p.Metadata["kind"] {
							case "headers":
								if p.Direction == "request" {
									e.request = append(e.request, []byte(fmt.Sprint(p.Metadata["url"])+"\n")...)
								}
							case "body_chunk":
								*data = append(*data, p.Data...)
							case "end":
								e.ends++
							default:
								t.Fatal("unexpected HTTP event", p.Metadata)
							}
						} else {
							*data = append(*data, p.Data...)
						}
					}
					if len(got) != tc.connections {
						t.Fatalf("connections=%d, want %d", len(got), tc.connections)
					}
					for connection := 0; connection < tc.connections; connection++ {
						var wantRequest, wantResponse []byte
						for round := 0; round < tc.rounds; round++ {
							index := round
							if tc.connections > 1 {
								index = connection
							}
							request, response, body := d10HTTP(tc.mode, index)
							if output == "events" {
								request = fmt.Appendf(nil, "/d10/%s/%d\n", tc.mode, index)
								response = body
							}
							wantRequest = append(wantRequest, request...)
							wantResponse = append(wantResponse, response...)
						}
						matched := false
						for id, e := range got {
							if bytes.Equal(e.request, wantRequest) && bytes.Equal(e.response, wantResponse) && (output != "events" || e.ends == tc.rounds*2) {
								matched = true
								delete(got, id)
								break
							}
						}
						if !matched {
							t.Fatalf("missing exact HTTP exchange %d: want request %q response %q; got %+v", connection, wantRequest, wantResponse, got)
						}
					}
					if (tc.mode == "early" || tc.mode == "hrr_early") && output == "raw" {
						index := 3
						if tc.mode == "hrr_early" {
							index = 1
						}
						want, _, _ := d10HTTP(tc.mode, index)
						if len(earlyRaw) != 1 {
							t.Fatal("rejected early bytes missing or duplicated")
						}
						for _, data := range earlyRaw {
							if !bytes.Equal(data, want) {
								t.Fatal("rejected early request bytes changed")
							}
						}
					}
					if strings.HasPrefix(tc.mode, "ech_") {
						mu.Lock()
						defer mu.Unlock()
						if !slices.ContainsFunc(diagnostics, func(d types.Diagnostic) bool {
							return d.Stage == "handshake" && d.Code == strings.Replace(tc.mode, "ech_hrr_", "ech_", 1)
						}) {
							t.Fatal("missing fixed ECH diagnostic", diagnostics)
						}
					}
				})
			}
		}
	}
}

func TestTLSStateMatrixCaptureAPIs(t *testing.T) {
	for _, fixture := range []string{"resumption", "ech_early"} {
		t.Run(fixture, func(t *testing.T) { testTLSStateMatrixCapture(t, fixture) })
	}
}

func testTLSStateMatrixCapture(t *testing.T, fixture string) {
	t.Helper()
	path := "test/testdata/d10_" + fixture + "_matrix.pcapng"
	keys, err := os.ReadFile("test/testdata/d10_" + fixture + "_matrix.keys")
	if err != nil {
		t.Fatal(err)
	}
	capture, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	type scenario struct {
		mode                             string
		port                             uint32
		count                            int
		early, hrr, resumed, rejectedECH bool
	}
	cases := []scenario{
		{"hrr_early_aes128", 44482, 2, true, true, false, false}, {"hrr_early_aes256", 44483, 2, true, true, false, false}, {"hrr_early_chacha", 44484, 2, true, true, false, false},
		{"hrr_psk_aes128", 44485, 2, false, true, true, false}, {"hrr_psk_aes256", 44486, 2, false, true, true, false}, {"hrr_psk_chacha", 44487, 2, false, true, true, false},
		{"hrr_early_switch_chacha", 44488, 2, true, true, false, false}, {"hrr_early_switch_aes256", 44489, 2, true, true, false, false},
	}
	if fixture == "ech_early" {
		cases = []scenario{
			{"ech_hrr_aes128", 44490, 1, false, true, false, false}, {"ech_hrr_aes256", 44491, 1, false, true, false, false}, {"ech_hrr_chacha", 44492, 1, false, true, false, false},
			{"ech_hrr_early_aes128", 44493, 2, true, true, true, false}, {"ech_hrr_early_aes256", 44494, 2, true, true, true, false}, {"ech_hrr_early_chacha", 44495, 2, true, true, true, false},
			{"ech_rejected_early_aes128", 44496, 2, true, false, false, true},
		}
	}
	for _, output := range []string{"messages", "raw", "events"} {
		var reference map[string]string
		inputs := []string{"file", "late_early", "late_handshake"}
		if fixture == "ech_early" {
			inputs = append(inputs, "late_ech")
		}
		for _, input := range inputs {
			t.Run(output+"/"+input, func(t *testing.T) {
				type exchange struct {
					port                     uint32
					request, response, early []byte
					bodyOffset               [2]uint64
					headers, ends, messages  [2]int
					rawEnds                  [2]int
				}
				check := func(t *testing.T, packets []*types.DecryptedPacket, final bool) map[string]string {
					t.Helper()
					got := map[string]*exchange{}
					for _, p := range packets {
						port := p.DstPort
						if p.Direction == "response" {
							port = p.SrcPort
						} else if p.Direction != "request" {
							t.Fatal("invalid direction", p.Direction)
						}
						e := got[p.ConnectionID()]
						if e == nil {
							e = &exchange{port: port}
							got[p.ConnectionID()] = e
						}
						if p.Transport != "tcp" || p.SrcIP != "127.0.0.1" || p.DstIP != "127.0.0.1" {
							t.Fatal("fixture endpoints changed")
						}
						if e.port != port {
							t.Fatal("connection crossed fixture endpoints")
						}
						if p.Metadata["encryption_level"] == "0rtt" {
							if output != "raw" || p.Protocol != "tls" || p.Direction != "request" || p.Metadata["early_data"] != "rejected" || p.Metadata["offset"] != uint64(len(e.early)) || p.Metadata["kind"] != "stream_chunk" || p.Metadata["end"] != false {
								t.Fatal("rejected early data entered accepted output", p.Metadata)
							}
							e.early = append(e.early, p.Data...)
							continue
						}
						data, direction := &e.request, 0
						if p.Direction == "response" {
							data, direction = &e.response, 1
						}
						if output == "raw" {
							if p.Protocol != "tls" || p.Metadata["offset"] != uint64(len(*data)) || p.Metadata["early_data"] != nil || e.rawEnds[direction] != 0 {
								t.Fatal("normal raw bytes lost their independent offset", p.Metadata)
							}
							if p.Metadata["encryption_level"] != nil && p.Metadata["encryption_level"] != "1rtt" {
								t.Fatal("normal raw chunk has an invalid encryption level")
							}
							if p.Metadata["kind"] == "stream_end" {
								if p.Metadata["end"] != true || len(p.Data) != 0 {
									t.Fatal("invalid raw end marker", p.Metadata)
								}
								e.rawEnds[direction]++
								continue
							}
							if p.Metadata["kind"] != "stream_chunk" || p.Metadata["end"] != false {
								t.Fatal("invalid raw chunk", p.Metadata)
							}
						} else if p.Protocol != "http/1.1" {
							t.Fatal("unexpected application protocol", p.Protocol)
						}
						if output == "events" {
							if e.ends[direction] != 0 {
								t.Fatal("HTTP event after direction ended")
							}
							if p.Metadata["kind"] != "headers" && e.headers[direction] != 1 {
								t.Fatal("HTTP event before headers")
							}
							switch p.Metadata["kind"] {
							case "headers":
								e.headers[direction]++
								if e.headers[direction] != 1 || p.Direction == "response" && p.Metadata["status"] != 200 {
									t.Fatal("duplicate headers or incorrect response status")
								}
								if p.Direction == "request" {
									e.request = fmt.Appendf(e.request, "%v\n", p.Metadata["url"])
								}
							case "body_chunk":
								if p.Metadata["offset"] != e.bodyOffset[direction] {
									t.Fatal("HTTP body offset changed", p.Metadata)
								}
								e.bodyOffset[direction] += uint64(len(p.Data))
								*data = append(*data, p.Data...)
							case "end":
								e.ends[direction]++
							default:
								t.Fatal("unexpected HTTP event", p.Metadata)
							}
						} else {
							e.messages[direction]++
							*data = append(*data, p.Data...)
						}
					}
					wantConnections := 0
					for _, tc := range cases {
						wantConnections += tc.count
						if tc.rejectedECH && output != "raw" {
							wantConnections--
						}
					}
					if len(got) != wantConnections {
						t.Fatalf("connections=%d, want %d", len(got), wantConnections)
					}
					normalized := map[string]string{}
					for _, tc := range cases {
						for index := 0; index < tc.count; index++ {
							rejected := tc.rejectedECH && index == 1
							if rejected && output != "raw" {
								continue
							}
							request, response, body := d10HTTP(tc.mode, index)
							var early []byte
							if output == "raw" && tc.early && index == 1 {
								early = request
							}
							if output == "events" {
								request = fmt.Appendf(nil, "/d10/%s/%d\n", tc.mode, index)
								response = body
							}
							if rejected {
								request, response = nil, nil
							}
							matched := false
							for id, e := range got {
								if e.port == tc.port && bytes.Equal(e.request, request) && bytes.Equal(e.response, response) && bytes.Equal(e.early, early) && (output != "events" || e.ends == [2]int{1, 1}) && (output != "messages" || e.messages == [2]int{1, 1}) && (output != "raw" || !final || rejected || e.rawEnds == [2]int{1, 1}) {
									if rejected && e.rawEnds != [2]int{} {
										t.Fatal("incomplete ECH rejection emitted a normal raw end")
									}
									normalized[fmt.Sprintf("%s/%d", tc.mode, index)] = id
									delete(got, id)
									matched = true
									break
								}
							}
							if !matched {
								t.Fatalf("missing exact %s/%d exchange or rejected early bytes", tc.mode, index)
							}
						}
					}
					return normalized
				}
				var mu sync.Mutex
				diagnostics := map[string]map[string]int{}
				options := types.DecryptOptions{RawChunks: output == "raw", HTTPEvents: output == "events", OnDiagnostic: func(d types.Diagnostic) {
					mu.Lock()
					defer mu.Unlock()
					if diagnostics[d.ConnectionID] == nil {
						diagnostics[d.ConnectionID] = map[string]int{}
					}
					diagnostics[d.ConnectionID][d.Code]++
				}}
				var packets []*types.DecryptedPacket
				if input == "file" {
					packets, err = decryptTLSCapture(t, path, keys, options)
					if (err != nil) != (fixture == "ech_early") {
						t.Fatal(err)
					}
				} else {
					var groups [4][]byte
					for _, line := range bytes.Split(keys, []byte{'\n'}) {
						f := bytes.Fields(line)
						if len(f) != 3 || f[0][0] == '#' {
							continue
						}
						group := 1
						if strings.HasSuffix(string(f[0]), "TRAFFIC_SECRET_0") {
							group = 0
						} else if string(f[0]) == "CLIENT_EARLY_TRAFFIC_SECRET" {
							group = 2
						} else if strings.HasPrefix(string(f[0]), "ECH_") {
							group = 3
						}
						groups[group] = append(groups[group], append(bytes.Clone(line), '\n')...)
					}
					if input == "late_handshake" {
						groups[1], groups[2] = groups[2], groups[1]
					}
					ordered := [][]byte{groups[0], groups[1], groups[2], groups[3]}
					if fixture == "ech_early" && input != "late_ech" {
						ordered = [][]byte{groups[3], groups[0], groups[1], groups[2]}
					}
					synctest.Test(t, func(t *testing.T) {
						stream := newLiveStreamWithOptions(t, options)
						stream.write(t, capture)
						synctest.Wait()
						if len(stream.packets) != 0 {
							t.Fatal("output without secrets")
						}
						for i, group := range ordered {
							if len(group) == 0 {
								continue
							}
							stream.write(t, tlsFixtureDSB(t, group))
							synctest.Wait()
							stream.assertOpen(t)
							if input == "late_ech" && i < len(ordered)-1 && len(stream.packets) != 0 {
								t.Fatal("ECH output before authenticated random association")
							}
						}
						check(t, stream.packets, false)
						before := len(stream.packets)
						stream.write(t, tlsFixtureDSB(t, keys))
						synctest.Wait()
						if len(stream.packets) != before {
							t.Fatal("duplicate DSB repeated output")
						}
						if err := stream.writer.Close(); err != nil {
							t.Fatal(err)
						}
						synctest.Wait()
						if err := <-stream.done; (err != nil) != (fixture == "ech_early") {
							t.Fatal(err)
						}
						if output != "raw" && len(stream.packets) != before {
							t.Fatal("complete HTTP output delayed until EOF")
						}
						for _, p := range stream.packets[before:] {
							if output != "raw" || p.Metadata["kind"] != "stream_end" {
								t.Fatal("data delayed until EOF")
							}
						}
						packets = stream.packets
					})
				}
				got := check(t, packets, true)
				mu.Lock()
				for _, tc := range cases {
					for index := 0; index < tc.count; index++ {
						if tc.rejectedECH && index == 1 && output != "raw" {
							continue
						}
						d := diagnostics[got[fmt.Sprintf("%s/%d", tc.mode, index)]]
						hrr, resumed := 0, 0
						if tc.hrr && (tc.count == 1 || index == 1) {
							hrr = 1
						}
						if tc.resumed && index == 1 {
							resumed = 1
						}
						if d["hello_retry_request"] != hrr || d["session_resumed"] != resumed {
							t.Errorf("%s/%d HRR/resumption state: %v", tc.mode, index, d)
						}
						if fixture == "ech_early" {
							want := "ech_accepted"
							if tc.rejectedECH && index == 1 {
								want = "ech_rejected"
							}
							if d[want] == 0 {
								t.Errorf("missing definitive %s for %s/%d", want, tc.mode, index)
							}
						}
					}
				}
				accepted, rejected := 0, 0
				for _, d := range diagnostics {
					if d["ech_accepted"] > 0 {
						accepted++
					}
					if d["ech_rejected"] > 0 {
						rejected++
					}
					if d["ech_accepted"] > 0 && d["ech_rejected"] > 0 {
						t.Error("ECH connection changed acceptance state")
					}
					if d["ech_rejected"] == 0 {
						for _, code := range []string{"missing_secret", "ech_unavailable", "ech_unknown", "no_authenticated_application_data"} {
							if d[code] != 0 {
								t.Errorf("completed connection reported %s", code)
							}
						}
					}
					for _, code := range []string{"authentication_failed", "invalid_handshake", "invalid_secret", "resource_limit", "truncated_record"} {
						if d[code] != 0 {
							t.Errorf("unexpected matrix diagnostic %s", code)
						}
					}
				}
				if fixture == "ech_early" && (accepted != 10 || rejected != 1) {
					t.Errorf("ECH outcomes accepted/rejected=%d/%d", accepted, rejected)
				}
				mu.Unlock()
				if reference == nil {
					reference = got
				} else if !reflect.DeepEqual(reference, got) {
					t.Fatal("connection identity changed across APIs")
				}
			})
		}
	}
}

func TestD10TLSCaptureInvalidSecrets(t *testing.T) {
	for _, name := range []string{"wrong_application", "wrong_application_only", "wrong_handshake", "missing_ech", "wrong_ech", "wrong_ech_random", "ech_outer_unconfirmed", "missing_ech_hrr", "wrong_ech_hrr", "wrong_ech_random_hrr", "ech_outer_unconfirmed_hrr"} {
		t.Run(name, func(t *testing.T) {
			hrr := strings.HasSuffix(name, "_hrr")
			name = strings.TrimSuffix(name, "_hrr")
			mode, keyPath := "ku_aes128", "test/testdata/d10_openssl.keys"
			if strings.Contains(name, "ech") {
				mode, keyPath = "ech_accepted", "test/testdata/d10_ech.keys"
			}
			if name == "ech_outer_unconfirmed" {
				mode = "ech_rejected"
			}
			if hrr {
				mode = strings.Replace(mode, "ech_", "ech_hrr_", 1)
				keyPath = "test/testdata/d10_ech_hrr.keys"
			}
			original, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			var keys []byte
			for _, line := range bytes.Split(original, []byte{'\n'}) {
				f := bytes.Fields(line)
				if len(f) != 3 || f[0][0] == '#' {
					continue
				}
				label := string(f[0])
				if name == "missing_ech" && strings.HasPrefix(label, "ECH_") || name == "wrong_application_only" && strings.Contains(label, "HANDSHAKE") || name == "ech_outer_unconfirmed" && (strings.HasPrefix(label, "ECH_") || strings.Contains(label, "HANDSHAKE")) {
					continue
				}
				if (strings.HasPrefix(name, "wrong_application") || name == "ech_outer_unconfirmed") && strings.HasSuffix(label, "TRAFFIC_SECRET_0") || name == "wrong_handshake" && strings.Contains(label, "HANDSHAKE") || name == "wrong_ech" && label == "ECH_SECRET" {
					f[2] = bytes.Repeat([]byte("00"), len(f[2])/2)
				}
				if name == "wrong_ech_random" && strings.HasPrefix(label, "ECH_") {
					f[1] = bytes.Repeat([]byte("ff"), 32)
				}
				keys = append(keys, append(bytes.Join(f, []byte{' '}), '\n')...)
			}
			var mu sync.Mutex
			var diagnostics []types.Diagnostic
			packets, err := decryptTLSCapture(t, "test/testdata/d10_"+mode+".pcapng", keys, types.DecryptOptions{
				RawChunks: true, KeyWaitTimeout: time.Second,
				OnDiagnostic: func(d types.Diagnostic) { mu.Lock(); defer mu.Unlock(); diagnostics = append(diagnostics, d) },
			})
			if err == nil || len(packets) != 0 {
				t.Fatalf("invalid secrets yielded packets=%d err=%v", len(packets), err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(diagnostics) == 0 {
				t.Fatal("missing failure diagnostic")
			}
			if name == "ech_outer_unconfirmed" && !slices.ContainsFunc(diagnostics, func(d types.Diagnostic) bool { return d.Code == "ech_unknown" }) {
				t.Fatal("unconfirmed outer keys overstated ECH status", diagnostics)
			}
		})
	}
}

func TestD11QUICDatagramCaptureAPIs(t *testing.T) {
	const keyPath = "test/testdata/d11_datagram.keys"
	keys, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"v1", "v2"} {
		path := "test/testdata/d11_datagram_" + version + ".pcapng"
		for _, input := range []string{"file", "late_client", "late_server"} {
			t.Run(version+"/"+input, func(t *testing.T) {
				options := types.DecryptOptions{RawChunks: true}
				var packets []*types.DecryptedPacket
				if input == "file" {
					packets, err = decryptTLSCapture(t, path, keys, options)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					capture, client, server := quicDSBBlocks(t, path, keyPath)
					if input == "late_server" {
						client, server = server, client
					}
					synctest.Test(t, func(t *testing.T) {
						stream := newLiveStreamWithOptions(t, options)
						writeD11DuplicateCapture(t, stream.write, capture)
						stream.write(t, client)
						stream.write(t, server)
						synctest.Wait()
						stream.assertOpen(t)
						if len(stream.packets) != 35 {
							t.Fatalf("datagrams before EOF = %d, want 35", len(stream.packets))
						}
						stream.write(t, client)
						stream.write(t, server)
						if err := stream.writer.Close(); err != nil {
							t.Fatal(err)
						}
						synctest.Wait()
						if err := <-stream.done; err != nil {
							t.Fatal(err)
						}
						packets = stream.packets
					})
				}
				type flow struct {
					mode              string
					request, response []string
				}
				flows := map[string]*flow{}
				for _, p := range packets {
					if p.Protocol != "quic" || p.Transport != "udp" || p.Metadata["kind"] != "datagram" {
						t.Fatalf("unexpected datagram output: %+v", p)
					}
					for _, key := range []string{"stream_id", "offset", "end"} {
						if _, ok := p.Metadata[key]; ok {
							t.Fatalf("datagram carries stream metadata %q", key)
						}
					}
					f := flows[p.ConnectionID()]
					if f == nil {
						f = &flow{mode: "seed"}
						flows[p.ConnectionID()] = f
					}
					if p.Metadata["encryption_level"] == "0rtt" {
						mode, ok := p.Metadata["early_data"].(string)
						if !ok || (mode != "accepted" && mode != "rejected") || p.Direction != "request" || string(p.Data) != "early\x00\xff" || f.mode != "seed" {
							t.Fatalf("invalid early datagram: %+v", p)
						}
						f.mode = mode
					} else if p.Metadata["encryption_level"] != "1rtt" {
						t.Fatal("missing datagram encryption level", p.Metadata)
					}
					switch p.Direction {
					case "request":
						f.request = append(f.request, string(p.Data))
					case "response":
						f.response = append(f.response, string(p.Data))
					default:
						t.Fatal("unknown direction", p.Direction)
					}
				}
				modes := map[string]int{}
				for _, f := range flows {
					want := []string{"", "\x00\xffD11", "repeat", "repeat", "tail"}
					if f.mode != "seed" {
						want = append([]string{"early\x00\xff"}, want...)
					}
					if !slices.Equal(f.response, want) {
						t.Fatalf("%s response = %q, want %q", f.mode, f.response, want)
					}
					if f.mode == "rejected" {
						want = append([]string{"early\x00\xff"}, want...)
					}
					if !slices.Equal(f.request, want) {
						t.Fatalf("%s request = %q, want %q", f.mode, f.request, want)
					}
					modes[f.mode]++
				}
				if len(modes) != 3 || modes["seed"] != 1 || modes["accepted"] != 1 || modes["rejected"] != 1 {
					t.Fatal("wrong connection/mode counts", modes)
				}
			})
		}
		t.Run(version+"/requires_raw", func(t *testing.T) {
			packets, err := decryptTLSCapture(t, path, keys, types.DecryptOptions{})
			if err == nil || len(packets) != 0 {
				t.Fatalf("unknown ALPN without raw: outputs=%d err=%v", len(packets), err)
			}
		})
	}
}

// Replay each real EPB twice to model duplicated capture input; packet bytes and
// timestamps are unchanged. This checks record/packet identity, not payload dedupe.
func writeD11DuplicateCapture(t *testing.T, write func(*testing.T, []byte), capture []byte) {
	t.Helper()
	for len(capture) > 0 {
		if len(capture) < 12 {
			t.Fatal("short capture block")
		}
		n := int(binary.LittleEndian.Uint32(capture[4:8]))
		if n < 12 || n > len(capture) {
			t.Fatal("invalid capture block length")
		}
		write(t, capture[:n])
		if binary.LittleEndian.Uint32(capture[:4]) == 6 {
			write(t, capture[:n])
		}
		capture = capture[n:]
	}
}

func TestD11DTLSCaptureAPIs(t *testing.T) {
	keys, err := os.ReadFile("test/testdata/d11_dtls.keys")
	if err != nil {
		t.Fatal(err)
	}
	for _, suite := range []string{"aes128", "aes256"} {
		path := "test/testdata/d11_dtls_" + suite + ".pcapng"
		for _, raw := range []bool{false, true} {
			for _, streaming := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/raw=%t/stream=%t", suite, raw, streaming), func(t *testing.T) {
					options := types.DecryptOptions{UDPProtocol: "dtls", RawChunks: raw}
					var packets []*types.DecryptedPacket
					if !streaming {
						var err error
						packets, err = decryptTLSCapture(t, path, keys, options)
						if err != nil {
							t.Fatal(err)
						}
					} else {
						capture, err := os.ReadFile(path)
						if err != nil {
							t.Fatal(err)
						}
						synctest.Test(t, func(t *testing.T) {
							stream := newLiveStreamWithOptions(t, options)
							writeD11DuplicateCapture(t, stream.write, capture)
							synctest.Wait()
							if len(stream.packets) != 0 {
								t.Fatal("DTLS emitted before master secret")
							}
							stream.write(t, tlsFixtureDSB(t, keys))
							synctest.Wait()
							stream.assertOpen(t)
							if len(stream.packets) != 8 {
								t.Fatalf("DTLS datagrams before EOF=%d, want 8", len(stream.packets))
							}
							stream.write(t, tlsFixtureDSB(t, keys))
							if err := stream.writer.Close(); err != nil {
								t.Fatal(err)
							}
							synctest.Wait()
							if err := <-stream.done; err != nil {
								t.Fatal(err)
							}
							packets = stream.packets
						})
					}
					connections, counts := map[string]bool{}, map[string]int{}
					for _, p := range packets {
						connections[p.ConnectionID()] = true
						counts[p.Direction]++
						want := "dtls request\x00\xff\r\n"
						if p.Direction == "response" {
							want = "dtls response\x00\xfe\r\n"
						} else if p.Direction != "request" {
							t.Fatal("invalid direction", p.Direction)
						}
						if p.Protocol != "dtls" || p.Transport != "udp" || p.Metadata["kind"] != "datagram" || p.Metadata["epoch"] != uint16(1) || p.Metadata["sequence"] != uint64(counts[p.Direction]) || string(p.Data) != want {
							t.Fatalf("unexpected DTLS record: %+v", p)
						}
						for _, key := range []string{"offset", "end", "stream_id"} {
							if _, ok := p.Metadata[key]; ok {
								t.Fatal("DTLS record carries stream metadata", key)
							}
						}
					}
					if len(connections) != 1 || counts["request"] != 4 || counts["response"] != 4 {
						t.Fatal("DTLS capture counts", len(connections), counts)
					}
				})
			}
		}
		for _, invalid := range []string{"missing", "wrong"} {
			t.Run(suite+"/"+invalid, func(t *testing.T) {
				var bad []byte
				if invalid == "wrong" {
					for _, line := range bytes.Split(keys, []byte{'\n'}) {
						f := bytes.Fields(line)
						if len(f) == 3 && string(f[0]) == "CLIENT_RANDOM" {
							f[2] = bytes.Repeat([]byte{'0'}, 96)
							bad = append(bad, append(bytes.Join(f, []byte{' '}), '\n')...)
						}
					}
				}
				packets, err := decryptTLSCapture(t, path, bad, types.DecryptOptions{UDPProtocol: "dtls"})
				if err == nil || len(packets) != 0 {
					t.Fatalf("invalid DTLS keys: output=%d err=%v", len(packets), err)
				}
			})
		}
	}
}

func TestD11DatagramCallbackFailure(t *testing.T) {
	for _, tc := range []struct {
		name, key string
		options   types.DecryptOptions
	}{
		{"datagram_v1", "datagram", types.DecryptOptions{RawChunks: true}},
		{"datagram_v2", "datagram", types.DecryptOptions{RawChunks: true}},
		{"dtls_aes128", "dtls", types.DecryptOptions{UDPProtocol: "dtls"}},
		{"dtls_aes256", "dtls", types.DecryptOptions{UDPProtocol: "dtls"}},
	} {
		capture, err := os.ReadFile("test/testdata/d11_" + tc.name + ".pcapng")
		if err != nil {
			t.Fatal(err)
		}
		keys, err := os.ReadFile("test/testdata/d11_" + tc.key + ".keys")
		if err != nil {
			t.Fatal(err)
		}
		for _, canceled := range []bool{false, true} {
			if canceled && tc.options.UDPProtocol != "dtls" {
				continue
			}
			t.Run(fmt.Sprintf("%s/cancel=%t", tc.name, canceled), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					r, w := io.Pipe()
					defer w.Close()
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					want := errors.New("datagram consumer stopped")
					calls := 0
					done := make(chan error, 1)
					go func() {
						done <- DecryptPcapngStreamWithOptions(ctx, r, func(*types.DecryptedPacket) error {
							calls++
							if canceled {
								cancel()
								return nil
							}
							return want
						}, tc.options)
					}()
					keyBlock := tlsFixtureDSB(t, keys)
					go func() { _, _ = w.Write(capture); _, _ = w.Write(keyBlock) }()
					synctest.Wait()
					select {
					case err := <-done:
						if canceled {
							want = context.Canceled
						}
						if !errors.Is(err, want) || calls != 1 {
							t.Fatalf("calls=%d err=%v", calls, err)
						}
					default:
						t.Fatal("datagram stream did not stop and drain")
					}
				})
			})
		}
	}
}

func TestHTTP3DynamicEventCaptureAPIs(t *testing.T) {
	type message struct {
		Headers       map[string]any
		Informational []map[string]any
		Body          []byte
		Trailers      http.Header
		Terminal      string
	}
	// Normalize only body chunk boundaries: event order, headers, offsets and
	// terminal states are checked before comparing file and streaming semantics.
	check := func(t *testing.T, packets []*types.DecryptedPacket) map[string]message {
		t.Helper()
		byConnection := make(map[string]map[string]*message)
		for _, p := range packets {
			if p.Protocol != "http/3" || p.Transport != "udp" || (p.Direction != "request" && p.Direction != "response") {
				t.Fatal("unexpected event identity", p.Protocol, p.Direction)
			}
			id, ok := p.Metadata["stream_id"].(uint64)
			if !ok {
				t.Fatal("missing stream ID")
			}
			conn := p.ConnectionID()
			if byConnection[conn] == nil {
				byConnection[conn] = make(map[string]*message)
			}
			key := fmt.Sprintf("%d/%s", id, p.Direction)
			m := byConnection[conn][key]
			if m == nil {
				m = &message{}
				byConnection[conn][key] = m
			}
			if m.Terminal != "" {
				t.Fatal("event after terminal", key, p.Metadata)
			}
			if p.Metadata["offset"] != uint64(len(m.Body)) {
				t.Fatal("noncontiguous event body offset", key, p.Metadata)
			}
			kind := p.Metadata["kind"]
			if kind != "body_chunk" && len(p.Data) != 0 {
				t.Fatal("non-body event contains data", kind)
			}
			switch kind {
			case "headers":
				if m.Headers != nil {
					t.Fatal("headers after final headers", key)
				}
				h, ok := p.Metadata["headers"].(http.Header)
				if !ok {
					t.Fatal("missing headers")
				}
				tls, ok := p.Metadata["tls"].(map[string]string)
				if !ok || len(tls["ja3"]) != 32 || !strings.HasPrefix(tls["ja4"], "q13") || tls["alpn"] != "" && tls["alpn"] != "h3" {
					t.Fatal("invalid captured TLS snapshot")
				}
				metadata := maps.Clone(p.Metadata)
				// Late handshake keys can reveal ALPN after an application event;
				// compare application semantics, without rewriting prior snapshots.
				delete(metadata, "tls")
				if p.Direction == "response" && id&2 == 0 {
					// Ordinary response authority is optional request context, not
					// a response pseudo-header. Server keys may arrive first.
					if a := metadata["authority"]; a != nil && a != "" && a != "localhost" {
						t.Fatal("response authority crossed connections", a)
					}
					metadata = maps.Clone(metadata)
					delete(metadata, "authority")
				}
				if p.Metadata["informational"] == true {
					if p.Direction != "response" || (id != 4 && id != 8) || p.Metadata["status"] != 103 || h.Get("Link") != "</asset>; rel=preload" || len(m.Informational) != 0 {
						t.Fatal("incorrect/duplicate informational section", p.Metadata)
					}
					m.Informational = append(m.Informational, metadata)
				} else {
					m.Headers = metadata
				}
			case "body_chunk":
				if m.Headers == nil || m.Trailers != nil || len(p.Data) == 0 {
					t.Fatal("body outside header/trailer boundary", key)
				}
				m.Body = append(m.Body, p.Data...)
			case "trailers":
				if m.Headers == nil || m.Trailers != nil {
					t.Fatal("trailers outside message", key)
				}
				h, ok := p.Metadata["trailers"].(http.Header)
				if !ok {
					t.Fatal("missing trailer fields")
				}
				m.Trailers = h
			case "end", "reset":
				if m.Headers == nil {
					t.Fatal("terminal event before final headers", key)
				}
				if kind == "reset" && (id != 12 || p.Direction != "response" || p.Metadata["error_code"] != uint64(0x10c)) {
					t.Fatal("incorrect reset", p.Metadata)
				}
				if kind == "end" && p.Metadata["error_code"] != nil {
					t.Fatal("normal end has reset code")
				}
				m.Terminal = kind.(string)
			default:
				t.Fatal("unexpected HTTPEvents kind", p.Metadata)
			}
		}
		if len(byConnection) != 2 {
			t.Fatalf("connections=%d, want 2", len(byConnection))
		}
		result := make(map[string]message)
		labels := make(map[string]bool)
		for _, messages := range byConnection {
			if len(messages) != 9 {
				t.Fatalf("message directions=%d, want 9", len(messages))
			}
			request := messages["0/request"]
			if request == nil || request.Headers == nil {
				t.Fatal("missing warmup request")
			}
			path, _ := request.Headers["path"].(string)
			parts := strings.Split(path, "/")
			if len(parts) != 3 {
				t.Fatal("invalid fixture path", path)
			}
			label := parts[1]
			if (label != "alpha" && label != "beta") || labels[label] {
				t.Fatal("connection labels crossed or duplicated", label)
			}
			labels[label] = true
			for _, id := range []uint64{0, 4, 8, 12, 15} {
				for _, direction := range []string{"request", "response"} {
					if id == 15 && direction == "request" {
						continue
					}
					key := fmt.Sprintf("%d/%s", id, direction)
					m := messages[key]
					if m == nil || m.Headers == nil {
						t.Fatal("missing message", label, key)
					}
					h := m.Headers["headers"].(http.Header)
					suffix := map[uint64]string{0: "warmup", 4: "one", 8: "two", 12: "reset", 15: "asset"}[id]
					wantBody, wantEnd := "", "end"
					if direction == "request" {
						if m.Headers["method"] != "GET" || m.Headers["scheme"] != "https" || m.Headers["authority"] != "localhost" || m.Headers["path"] != "/"+label+"/"+suffix || h.Get("X-Fixture-Token") != strings.Repeat(label, 16) || m.Trailers != nil || len(m.Informational) != 0 {
							t.Fatal("request fields crossed streams/connections", label, key, m.Headers)
						}
					} else {
						if m.Headers["status"] != 200 {
							t.Fatal("missing final status", key, m.Headers)
						}
						switch id {
						case 12:
							wantBody, wantEnd = "discarded partial response", "reset"
							if m.Trailers != nil || len(m.Informational) != 0 {
								t.Fatal("reset produced trailers/informational")
							}
						case 15:
							wantBody = "asset " + label
							promise, ok := m.Headers["promise_headers"].(http.Header)
							if !ok || promise == nil || h.Get("Content-Length") != fmt.Sprint(len(wantBody)) || m.Headers["push_id"] != uint64(0) || m.Headers["parent_stream_id"] != uint64(4) || m.Headers["method"] != "GET" || m.Headers["scheme"] != "https" || m.Headers["authority"] != "localhost" || m.Headers["path"] != "/"+label+"/asset" || m.Trailers != nil || len(m.Informational) != 0 {
								t.Fatal("push association", m.Headers)
							}
						default:
							wantBody = "reply /" + label + "/" + suffix
							wantInfo := 0
							if id != 0 {
								wantInfo = 1
							}
							if h.Get("X-Fixture-Token") != strings.Repeat(label, 16) || h.Get("Content-Length") != fmt.Sprint(len(wantBody)) || h.Get("X-Finished") != "" || len(m.Trailers) != 1 || m.Trailers.Get("X-Finished") != label || len(m.Informational) != wantInfo {
								t.Fatal("response headers/trailers/103", label, key, m.Headers, m.Trailers)
							}
						}
					}
					if string(m.Body) != wantBody || m.Terminal != wantEnd {
						t.Fatalf("%s/%s body=%q terminal=%q, want %q/%q", label, key, m.Body, m.Terminal, wantBody, wantEnd)
					}
					result[label+"/"+key] = *m
				}
			}
		}
		return result
	}
	for _, tc := range []struct{ name, base string }{{"v1", "http3_dynamic_aioquic"}, {"v2", "http3_dynamic_aioquic_v2"}} {
		t.Run(tc.name, func(t *testing.T) {
			base := "test/testdata/" + tc.base
			capture, clientKeys, serverKeys := quicDSBBlocks(t, base+".pcapng", base+".keys")
			keylog, err := os.ReadFile(base + ".keys")
			if err != nil {
				t.Fatal(err)
			}
			options := types.DecryptOptions{HTTPEvents: true}
			var reference map[string]message
			for _, mode := range []string{"file", "late_client_first", "late_server_first"} {
				t.Run(mode, func(t *testing.T) {
					var packets []*types.DecryptedPacket
					if mode == "file" {
						var err error
						packets, err = decryptTLSCapture(t, base+".pcapng", keylog, options)
						if err != nil {
							t.Fatal(err)
						}
					} else {
						synctest.Test(t, func(t *testing.T) {
							stream := newLiveStreamWithOptions(t, options)
							stream.write(t, capture)
							synctest.Wait()
							if len(stream.packets) != 0 {
								t.Fatal("events before secrets")
							}
							first, second := clientKeys, serverKeys
							if mode == "late_server_first" {
								first, second = second, first
							}
							stream.write(t, first)
							synctest.Wait()
							stream.assertOpen(t)
							stream.write(t, second)
							synctest.Wait()
							stream.assertOpen(t)
							// All decoded dynamic sections, push and reset must arrive while input
							// remains open, even though the keys followed every captured packet.
							check(t, stream.packets)
							before := len(stream.packets)
							stream.write(t, first)
							stream.write(t, second)
							synctest.Wait()
							if len(stream.packets) != before {
								t.Fatal("duplicate DSB repeated an event")
							}
							if err := stream.writer.Close(); err != nil {
								t.Fatal(err)
							}
							synctest.Wait()
							if err := <-stream.done; err != nil {
								t.Fatal(err)
							}
							if len(stream.packets) != before {
								t.Fatal("complete events delayed until EOF")
							}
							packets = stream.packets
						})
					}
					got := check(t, packets)
					if reference == nil {
						reference = got
					} else if !reflect.DeepEqual(reference, got) {
						for key, value := range got {
							if !reflect.DeepEqual(reference[key], value) {
								t.Errorf("dynamic HTTPEvents semantics for %s: file=%+v late=%+v", key, reference[key], value)
							}
						}
					}
				})
			}
		})
	}
}
