package ecapture_decryptor

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
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
	if !errors.Is(err, want) || errors.Is(err, context.DeadlineExceeded) || calls != 1 {
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
