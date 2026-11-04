package ecapture_decryptor

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gojue/ecapture_decryptor/protocol"
	"github.com/gojue/ecapture_decryptor/types"
)

// These Linux VM fixtures cover loopback and a public HTTP/3 server, captured
// with tcpdump or eCapture while one client made two requests per connection.
func TestDecryptHTTP3QUICCapture(t *testing.T) {
	for _, tc := range []struct {
		name, capture, keylog string
		loopback              bool
		stream                bool
	}{
		{"loopback_external_keylog", "test/testdata/http3_loopback_tcpdump_no_dsb.pcapng", "test/testdata/http3_loopback_tcpdump.keys", true, false},
		{"loopback_stream_external_keylog", "test/testdata/http3_loopback_tcpdump_no_dsb.pcapng", "test/testdata/http3_loopback_tcpdump.keys", true, true},
		{"loopback_embedded_dsb", "test/testdata/http3_loopback_ecapture_dsb.pcapng", "", true, false},
		{"loopback_stream_dsb", "test/testdata/http3_loopback_ecapture_dsb.pcapng", "", true, true},
		{"public_external_keylog", "test/testdata/http3_cloudflare_tcpdump_no_dsb.pcapng", "test/testdata/http3_cloudflare_tcpdump.keys", false, false},
		{"public_stream_external_keylog", "test/testdata/http3_cloudflare_tcpdump_no_dsb.pcapng", "test/testdata/http3_cloudflare_tcpdump.keys", false, true},
		{"public_embedded_dsb", "test/testdata/http3_cloudflare_ecapture_dsb.pcapng", "", false, false},
		{"public_stream_dsb", "test/testdata/http3_cloudflare_ecapture_dsb.pcapng", "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file, err := os.Open(tc.capture)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			var capture io.Reader = file
			if tc.stream {
				data, err := io.ReadAll(file)
				if err != nil {
					t.Fatal(err)
				}
				capture = bytes.NewBuffer(data)
			}
			var external io.Reader
			if tc.keylog != "" {
				keylog, err := os.ReadFile(tc.keylog)
				if err != nil {
					t.Fatal(err)
				}
				external = bytes.NewReader(keylog)
			}
			packets := make(chan *types.DecryptedPacket, 32)
			if err := DecryptPcapFile(external, capture, packets); err != nil {
				t.Fatal(err)
			}
			close(packets)
			var requests, responses []string
			streamIDs := make(map[uint64]map[string]bool)
			for packet := range packets {
				if packet.Protocol != "http/3" {
					continue
				}
				logDecryptedPreview(t, packet)
				if packet.Transport != types.TransportProtocolUDP {
					t.Fatalf("HTTP/3 packet transport = %q, want UDP", packet.Transport)
				}
				if packet.Direction == "request" {
					if tc.loopback {
						if packet.SrcIP != "127.0.0.1" || packet.DstIP != "127.0.0.1" || packet.DstPort != 44433 {
							t.Fatalf("loopback request endpoint = %s:%d -> %s:%d", packet.SrcIP, packet.SrcPort, packet.DstIP, packet.DstPort)
						}
					} else {
						dst := net.ParseIP(packet.DstIP)
						if dst == nil || !dst.IsGlobalUnicast() || dst.IsPrivate() || packet.DstPort != 443 {
							t.Fatalf("public request endpoint = %s:%d -> %s:%d", packet.SrcIP, packet.SrcPort, packet.DstIP, packet.DstPort)
						}
						if packet.Metadata["authority"] != "www.cloudflare.com" {
							t.Fatalf("public request authority = %v", packet.Metadata["authority"])
						}
					}
				}
				id, ok := packet.Metadata["stream_id"].(uint64)
				if !ok {
					t.Fatalf("HTTP/3 packet lacks stream ID: %v", packet.Metadata)
				}
				if streamIDs[id] == nil {
					streamIDs[id] = make(map[string]bool)
				}
				streamIDs[id][packet.Direction] = true
				switch packet.Direction {
				case "request":
					requests = append(requests, string(packet.Data))
				case "response":
					responses = append(responses, string(packet.Data))
				}
			}
			if len(requests) != 2 || len(responses) != 2 {
				t.Fatalf("decrypted %d requests and %d responses; want 2 each", len(requests), len(responses))
			}
			if len(streamIDs) != 2 {
				t.Fatalf("decrypted %d QUIC request streams, want 2", len(streamIDs))
			}
			for id, directions := range streamIDs {
				if !directions["request"] || !directions["response"] {
					t.Fatalf("incomplete HTTP/3 exchange on stream %d: %v", id, directions)
				}
			}
			allRequests := strings.Join(requests, "\n")
			if tc.loopback {
				if !strings.Contains(allRequests, "GET /one HTTP/3.0") ||
					!strings.Contains(allRequests, "POST /upload HTTP/3.0") ||
					!strings.Contains(allRequests, strings.Repeat("payload-", 300)) {
					t.Fatalf("loopback HTTP/3 requests are incomplete: %q", requests)
				}
			} else if !strings.Contains(allRequests, "GET /robots.txt HTTP/3.0") ||
				!strings.Contains(allRequests, "GET /favicon.ico HTTP/3.0") {
				t.Fatalf("public HTTP/3 requests are incomplete: %q", requests)
			}
			for _, response := range responses {
				if !strings.HasPrefix(response, "HTTP/3.0 200\r\n") {
					t.Fatalf("unexpected HTTP/3 response: %q", response)
				}
			}
			allResponses := strings.Join(responses, "\n")
			if tc.loopback {
				if !strings.Contains(allResponses, "GET /one ") ||
					!strings.Contains(allResponses, "POST /upload "+strings.Repeat("payload-", 300)) {
					t.Fatalf("loopback HTTP/3 responses are incomplete: %q", responses)
				}
			} else {
				for _, response := range responses {
					parts := strings.SplitN(response, "\r\n\r\n", 2)
					if len(parts) != 2 || len(parts[1]) == 0 {
						t.Fatalf("public HTTP/3 response body is empty")
					}
				}
			}
		})
	}
}

// These real loopback captures include 7+ quic-go key updates per direction.
// Generation-zero application secrets must decrypt every stream through EOF, even
// when the DSB arrives after all encrypted packets and input remains open.
func TestQUICKeyUpdateCaptureAPIs(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			base := fmt.Sprintf("test/testdata/http3_keyupdate_v%d", version)
			packets, clientKeys, serverKeys := quicDSBBlocks(t, base+".pcapng", base+".keys")
			keylog, err := os.ReadFile(base + ".keys")
			if err != nil {
				t.Fatal(err)
			}
			withDSB := bytes.Join([][]byte{packets, clientKeys, serverKeys}, nil)
			for _, raw := range []bool{false, true} {
				var reference map[string][]byte
				var referenceMetadata map[string]map[string]interface{}
				for _, mode := range []string{"file_external", "file_dsb", "stream_late_dsb"} {
					t.Run(fmt.Sprintf("raw=%t/%s", raw, mode), func(t *testing.T) {
						var output []*types.DecryptedPacket
						if mode == "stream_late_dsb" {
							synctest.Test(t, func(t *testing.T) {
								stream := newQUICLiveStream(t, raw)
								stream.write(t, packets)
								synctest.Wait()
								if len(stream.packets) != 0 {
									t.Fatal("emitted before application secrets")
								}
								stream.write(t, clientKeys)
								stream.write(t, serverKeys)
								synctest.Wait()
								stream.assertOpen(t)
								if len(stream.packets) < 24 {
									t.Fatal("key updates were not decrypted before EOF")
								}
								count := len(stream.packets)
								if err := stream.writer.Close(); err != nil {
									t.Fatal(err)
								}
								synctest.Wait()
								if err := <-stream.done; err != nil {
									t.Fatal(err)
								}
								if len(stream.packets) != count {
									t.Fatal("output delayed until EOF")
								}
								output = stream.packets
							})
						} else {
							input := withDSB
							var secrets io.Reader
							if mode == "file_external" {
								input = packets
								secrets = bytes.NewReader(keylog)
							}
							ch := make(chan *types.DecryptedPacket)
							done := make(chan struct{})
							go func() {
								defer close(done)
								for p := range ch {
									output = append(output, p)
								}
							}()
							err := DecryptWithConfig(NewDecryptorConfig().WithPcapReader(bytes.NewReader(input)).WithSSLKeyLog(secrets).WithPacketChan(ch).WithOptions(types.DecryptOptions{RawChunks: raw}).WithLogger(log.New(io.Discard, "", 0)))
							close(ch)
							<-done
							if err != nil {
								t.Fatal(err)
							}
						}
						data := make(map[string][]byte)
						metadata := make(map[string]map[string]interface{})
						ended := make(map[string]bool)
						connections := make(map[string]bool)
						var messages []*types.DecryptedPacket
						parsed := make(chan *types.DecryptedPacket, 24)
						parser := protocol.NewHTTP3StreamParser(types.ConnectionKey{}, parsed)
						for _, p := range output {
							connections[p.ConnectionID()] = true
							id, ok := p.Metadata["stream_id"].(uint64)
							if !ok || p.Transport != "udp" {
								t.Fatal("missing QUIC stream identity")
							}
							key := fmt.Sprintf("%d/%s", id, p.Direction)
							if ended[key] {
								t.Fatal("duplicate message or bytes after FIN")
							}
							if raw {
								if p.Protocol != "quic" || p.Metadata["offset"] != uint64(len(data[key])) {
									t.Fatal("raw offset or protocol mismatch")
								}
								data[key] = append(data[key], p.Data...)
								ended[key] = p.Metadata["end"] == true
								if id%4 == 0 {
									if err := parser.FeedQUICStream(id, p.Direction == "request", p.Data, ended[key], time.Time{}); err != nil {
										t.Fatal(err)
									}
								}
							} else {
								if p.Protocol != "http/3" {
									t.Fatal("unexpected message protocol")
								}
								parts := bytes.SplitN(p.Data, []byte("\r\n\r\n"), 2)
								if len(parts) != 2 {
									t.Fatal("invalid message framing")
								}
								data[key] = parts[1]
								metadata[key] = p.Metadata
								ended[key] = true
								messages = append(messages, p)
							}
						}
						if len(connections) != 1 {
							t.Fatalf("connection count=%d", len(connections))
						}
						if raw {
							close(parsed)
							for p := range parsed {
								messages = append(messages, p)
							}
						}
						if len(messages) != 24 {
							t.Fatalf("messages=%d, want 24", len(messages))
						}
						seen := make(map[string]bool)
						for _, p := range messages {
							id := p.Metadata["stream_id"].(uint64)
							key := fmt.Sprintf("%d/%s", id, p.Direction)
							path := fmt.Sprintf("/update/%d", id/4)
							body := strings.Repeat("payload-", 300)
							if id%4 != 0 || id/4 >= 12 || seen[key] || !ended[key] {
								t.Fatalf("invalid or repeated stream %s", key)
							}
							seen[key] = true
							switch p.Direction {
							case "request":
								if p.Metadata["method"] != "POST" || p.Metadata["path"] != path || p.Metadata["authority"] != "127.0.0.1:44433" {
									t.Fatalf("request metadata=%v", p.Metadata)
								}
							case "response":
								if p.Metadata["status"] != 200 {
									t.Fatalf("response metadata=%v", p.Metadata)
								}
								body = "POST " + path + " " + body
							default:
								t.Fatal("unknown direction")
							}
							parts := bytes.SplitN(p.Data, []byte("\r\n\r\n"), 2)
							if len(parts) != 2 || !bytes.Equal(parts[1], []byte(body)) {
								t.Fatalf("body differs for %s", key)
							}
						}
						if reference == nil {
							reference = data
							referenceMetadata = metadata
						} else if !reflect.DeepEqual(reference, data) || !reflect.DeepEqual(referenceMetadata, metadata) {
							t.Fatal("file and stream output bytes differ")
						}
					})
				}
			}
		})
	}
}
