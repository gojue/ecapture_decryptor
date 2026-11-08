package ecapture_decryptor

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
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
				tls, ok := packet.Metadata["tls"].(map[string]string)
				if !ok || len(tls["ja3"]) != 32 || !strings.HasPrefix(tls["ja4"], "q13") {
					t.Fatalf("missing QUIC client fingerprint: %v", tls)
				}
				if tc.loopback && (tls["ja3"] != "aeb4a42cd7925b343b143434a712dd00" || tls["ja4"] != "q13d0313h3_55b375c5d22e_f902b76752af") {
					t.Fatal("QUIC fingerprints disagree with independent tshark fixture results")
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

func TestQUICStateMatrixCaptureAPIs(t *testing.T) {
	for _, fixture := range []string{"keyupdate_matrix", "retry_early", "retry_early_matrix"} {
		t.Run(fixture, func(t *testing.T) {
			base := "test/testdata/http3_" + fixture + "_aioquic"
			capture, clientKeys, serverKeys := quicDSBBlocks(t, base+".pcapng", base+".keys")
			keys, err := os.ReadFile(base + ".keys")
			if err != nil {
				t.Fatal(err)
			}
			withDSB := bytes.Join([][]byte{capture, clientKeys, serverKeys}, nil)
			var reference map[string]string
			for _, raw := range []bool{false, true} {
				var referenceRaw map[string][]byte
				modes := []string{"external", "seek_dsb", "nonseek_dsb", "late_client_first", "late_server_first"}
				if fixture == "retry_early_matrix" {
					modes = append(modes, "late_early", "late_handshake")
				}
				for _, mode := range modes {
					t.Run(fmt.Sprintf("raw=%v/%s", raw, mode), func(t *testing.T) {
						var output []*types.DecryptedPacket
						if strings.HasPrefix(mode, "late_") {
							synctest.Test(t, func(t *testing.T) {
								stream := newQUICLiveStream(t, raw)
								stream.write(t, capture)
								synctest.Wait()
								if len(stream.packets) != 0 {
									t.Fatal("output before secrets")
								}
								groups := [][]byte{clientKeys, serverKeys}
								if mode == "late_server_first" {
									groups[0], groups[1] = groups[1], groups[0]
								}
								if mode == "late_early" || mode == "late_handshake" {
									var first, last bytes.Buffer
									for _, line := range strings.Split(string(keys), "\n") {
										fields := strings.Fields(line)
										if len(fields) != 3 {
											continue
										}
										late := mode == "late_early" && fields[0] == "CLIENT_EARLY_TRAFFIC_SECRET" ||
											mode == "late_handshake" && strings.Contains(fields[0], "HANDSHAKE_TRAFFIC_SECRET")
										if late {
											last.WriteString(line + "\n")
										} else {
											first.WriteString(line + "\n")
										}
									}
									if first.Len() == 0 || last.Len() == 0 {
										t.Fatal("missing independent late-secret group")
									}
									groups = [][]byte{tlsFixtureDSB(t, first.Bytes()), tlsFixtureDSB(t, last.Bytes())}
								}
								for _, group := range groups {
									stream.write(t, group)
									synctest.Wait()
									stream.assertOpen(t)
								}
								checkQUICStateMatrixOutput(t, fixture, stream.packets, raw)
								count := len(stream.packets)
								stream.write(t, tlsFixtureDSB(t, keys))
								synctest.Wait()
								if len(stream.packets) != count {
									t.Fatal("duplicate DSB repeated output")
								}
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
							var reader io.Reader = bytes.NewReader(withDSB)
							var external io.Reader
							if mode == "external" {
								reader, external = bytes.NewReader(capture), bytes.NewReader(keys)
							} else if mode == "nonseek_dsb" {
								reader = bytes.NewBuffer(withDSB)
							}
							ch, done := make(chan *types.DecryptedPacket), make(chan struct{})
							go func() {
								defer close(done)
								for p := range ch {
									output = append(output, p)
								}
							}()
							err := DecryptWithConfig(NewDecryptorConfig().WithPcapReader(reader).WithSSLKeyLog(external).
								WithPacketChan(ch).WithOptions(types.DecryptOptions{RawChunks: raw}).WithLogger(log.New(io.Discard, "", 0)))
							close(ch)
							<-done
							if err != nil {
								t.Fatal(err)
							}
						}
						messages, wire := checkQUICStateMatrixOutput(t, fixture, output, raw)
						if reference == nil {
							reference = messages
						} else if !reflect.DeepEqual(reference, messages) {
							t.Fatal("message bytes, stream IDs or connection ownership differ across APIs")
						}
						if raw {
							if referenceRaw == nil {
								referenceRaw = wire
							} else if !reflect.DeepEqual(referenceRaw, wire) {
								t.Fatal("raw stream bytes or early offset space differ across APIs")
							}
						}
					})
				}
			}
		})
	}
}

func checkQUICStateMatrixOutput(t *testing.T, fixture string, output []*types.DecryptedPacket, raw bool) (map[string]string, map[string][]byte) {
	t.Helper()
	messages := make(map[string][]*types.DecryptedPacket)
	parsers := make(map[string]*protocol.HTTP3StreamParser)
	channels := make(map[string]chan *types.DecryptedPacket)
	wire, ended := make(map[string][]byte), make(map[string]bool)
	early := make(map[string]string)
	for _, p := range output {
		conn := p.ConnectionID()
		if p.Transport != types.TransportProtocolUDP || p.Direction != "request" && p.Direction != "response" || p.SrcIP != "127.0.0.1" || p.DstIP != "127.0.0.1" {
			t.Fatal("connection endpoint/direction", p)
		}
		if !raw {
			messages[conn] = append(messages[conn], p)
			continue
		}
		id, ok := p.Metadata["stream_id"].(uint64)
		if !ok || p.Protocol != "quic" || p.Metadata["kind"] != "stream_chunk" && p.Metadata["kind"] != "stream_end" {
			t.Fatal("unexpected raw output", p.Metadata)
		}
		level, _ := p.Metadata["encryption_level"].(string)
		status, _ := p.Metadata["early_data"].(string)
		space := ""
		if level == "0rtt" {
			if !strings.HasPrefix(fixture, "retry_early") || p.Direction != "request" || status != "accepted" && status != "rejected" || early[conn] != "" && early[conn] != status {
				t.Fatal("early state/connection mismatch", p.Metadata)
			}
			early[conn] = status
			if status == "rejected" {
				space = "/early"
			}
		}
		key := fmt.Sprintf("%s%s/%d/%s", conn, space, id, p.Direction)
		if ended[key] || p.Metadata["offset"] != uint64(len(wire[key])) {
			t.Fatal("duplicate or non-contiguous stream", key, p.Metadata)
		}
		wire[key] = append(wire[key], p.Data...)
		ended[key] = p.Metadata["end"] == true
		owner := conn + space
		if parsers[owner] == nil {
			channels[owner] = make(chan *types.DecryptedPacket, 16)
			parsers[owner] = protocol.NewHTTP3StreamParser(types.ConnectionKey{}, channels[owner])
		}
		if err := parsers[owner].FeedQUICStream(id, p.Direction == "request", p.Data, ended[key], p.Timestamp); err != nil {
			t.Fatal(err)
		}
	}
	for owner, parser := range parsers {
		if err := parser.Close(); err != nil {
			t.Fatal(err)
		}
		close(channels[owner])
		for p := range channels[owner] {
			messages[owner] = append(messages[owner], p)
		}
	}
	expected := make(map[string]uint64)
	for _, version := range []int{1, 2} {
		if fixture == "keyupdate_matrix" {
			for _, suite := range []string{"aes256", "chacha"} {
				for generation := 0; generation < 3; generation++ {
					expected[fmt.Sprintf("/ku/v%d/%s/g%d", version, suite, generation)] = uint64(generation * 4)
				}
			}
		} else {
			suites := []string{""}
			if fixture == "retry_early_matrix" {
				suites = []string{"aes256/", "chacha/"}
			}
			for _, suite := range suites {
				for _, mode := range []string{"seed", "accepted", "rejected"} {
					expected[fmt.Sprintf("/retry/v%d/%s%s", version, suite, mode)] = 0
				}
			}
		}
	}
	result, owners, rejectedPaths := make(map[string]string), make(map[string]string), make(map[string]string)
	connections := make(map[string]bool)
	for owner, packets := range messages {
		isRejected := strings.HasSuffix(owner, "/early")
		conn := strings.TrimSuffix(owner, "/early")
		paths := make(map[uint64]string)
		for _, p := range packets {
			if p.Direction == "request" {
				paths[p.Metadata["stream_id"].(uint64)] = p.Metadata["path"].(string)
			}
		}
		if isRejected && (len(packets) != 1 || early[conn] != "rejected") {
			t.Fatal("rejected early request missing or duplicated", owner)
		}
		for _, p := range packets {
			id := p.Metadata["stream_id"].(uint64)
			path := paths[id]
			wantID, exists := expected[path]
			body := bytes.SplitN(p.Data, []byte("\r\n\r\n"), 2)
			if !exists || id != wantID || p.Protocol != "http/3" || len(body) != 2 {
				t.Fatal("unexpected message or stream identity", p.Metadata)
			}
			if p.Direction == "request" {
				if p.Metadata["method"] != "GET" || p.Metadata["path"] != path || p.Metadata["authority"] != "localhost" || len(body[1]) != 0 {
					t.Fatal("request changed", p.Metadata)
				}
			} else if p.Direction != "response" || p.Metadata["status"] != 200 || string(body[1]) != "reply "+path || isRejected {
				t.Fatal("response changed", p.Metadata)
			}
			if isRejected {
				if !strings.HasSuffix(path, "/rejected") {
					t.Fatal("rejected early bytes belong to another connection", path)
				}
				rejectedPaths[conn] = path
				continue
			}
			connections[conn] = true
			cell := path
			if fixture == "keyupdate_matrix" {
				cell = path[:strings.LastIndex(path, "/")]
			}
			if owners[cell] != "" && owners[cell] != conn {
				t.Fatal("connection identity changed during state transition", path)
			}
			owners[cell] = conn
			key := path + "/" + p.Direction
			if _, duplicate := result[key]; duplicate {
				t.Fatal("duplicate complete message", key)
			}
			result[key] = fmt.Sprintf("%s/%d/%s", conn, id, body[1])
			if raw && strings.HasPrefix(fixture, "retry_early") {
				want := path[strings.LastIndex(path, "/")+1:]
				if want == "seed" {
					want = ""
				}
				if early[conn] != want {
					t.Fatal("Retry acceptance metadata mismatch", path, early[conn])
				}
			}
		}
	}
	for conn, path := range rejectedPaths {
		if owners[path] != conn {
			t.Fatal("rejected early and normal replay belong to different connections", path)
		}
	}
	wantConnections := 4
	if strings.HasPrefix(fixture, "retry_early") {
		wantConnections = 6
		if fixture == "retry_early_matrix" {
			wantConnections = 12
		}
	}
	if len(connections) != wantConnections || len(owners) != wantConnections || len(result) != len(expected)*2 {
		t.Fatalf("connections/cells/messages=%d/%d/%d, want %d/%d/%d", len(connections), len(owners), len(result), wantConnections, wantConnections, len(expected)*2)
	}
	return result, wire
}

func TestQUICLifecycleCaptureAPIs(t *testing.T) {
	const base = "test/testdata/http3_lifecycle_aioquic"
	packets, clientKeys, serverKeys := quicDSBBlocks(t, base+".pcapng", base+".keys")
	keylog, err := os.ReadFile(base + ".keys")
	if err != nil {
		t.Fatal(err)
	}
	withDSB := bytes.Join([][]byte{packets, clientKeys, serverKeys}, nil)
	var reference map[string]string
	for _, raw := range []bool{false, true} {
		for _, mode := range []string{"file_external", "file_dsb", "stream_late_dsb"} {
			t.Run(fmt.Sprintf("raw=%v/%s", raw, mode), func(t *testing.T) {
				var output []*types.DecryptedPacket
				if mode == "stream_late_dsb" {
					synctest.Test(t, func(t *testing.T) {
						stream := newQUICLiveStream(t, raw)
						stream.write(t, packets)
						synctest.Wait()
						if len(stream.packets) != 0 {
							t.Fatal("application output without secrets")
						}
						stream.write(t, clientKeys)
						stream.write(t, serverKeys)
						synctest.Wait()
						stream.assertOpen(t)
						if len(stream.packets) < 48 {
							t.Fatal("lifecycle output delayed until EOF")
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
							t.Fatal("output changed at EOF")
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
				parsers := make(map[string]*protocol.HTTP3StreamParser)
				// Parser output uses its configured ConnectionKey, so retain the
				// original raw identity separately for stable-connection assertions.
				parsed := make(map[string]chan *types.DecryptedPacket)
				messages := make(map[string][]*types.DecryptedPacket)
				offsets := make(map[string]uint64)
				ended := make(map[string]bool)
				early := map[string]map[string]bool{"accepted": {}, "rejected": {}}
				for _, p := range output {
					conn := p.ConnectionID()
					if !raw {
						messages[conn] = append(messages[conn], p)
						continue
					}
					id := p.Metadata["stream_id"].(uint64)
					level, _ := p.Metadata["encryption_level"].(string)
					status, _ := p.Metadata["early_data"].(string)
					space := ""
					if level == "0rtt" && status != "accepted" {
						space = "early"
					}
					key := fmt.Sprintf("%s/%d/%s/%s", conn, id, p.Direction, space)
					if ended[key] || p.Metadata["offset"] != offsets[key] {
						t.Fatal("duplicate or non-contiguous raw output", key)
					}
					offsets[key] += uint64(len(p.Data))
					ended[key] = p.Metadata["end"] == true
					if level == "0rtt" {
						if early[status] == nil {
							t.Fatal("unexpected early status", status)
						}
						early[status][conn] = true
						if status == "rejected" {
							continue
						}
					}
					if id%4 != 0 {
						continue
					}
					if parsers[conn] == nil {
						parsed[conn] = make(chan *types.DecryptedPacket, 8)
						parsers[conn] = protocol.NewHTTP3StreamParser(types.ConnectionKey{}, parsed[conn])
					}
					if err := parsers[conn].FeedQUICStream(id, p.Direction == "request", p.Data, ended[key], time.Time{}); err != nil {
						t.Fatal(err)
					}
				}
				if raw {
					if len(early["accepted"]) != 6 || len(early["rejected"]) != 6 {
						t.Fatalf("early connections=%v", early)
					}
					for conn, parser := range parsers {
						parser.Flush()
						close(parsed[conn])
						for p := range parsed[conn] {
							messages[conn] = append(messages[conn], p)
						}
					}
				}
				if len(messages) != 18 {
					t.Fatalf("stable connections=%d want18", len(messages))
				}
				data := make(map[string]string)
				owners := make(map[string]string)
				for conn, ps := range messages {
					paths := make(map[uint64]string)
					for _, p := range ps {
						if p.Direction == "request" {
							paths[p.Metadata["stream_id"].(uint64)] = p.Metadata["path"].(string)
						}
					}
					for _, p := range ps {
						path := paths[p.Metadata["stream_id"].(uint64)]
						key := path + "/" + p.Direction
						if _, seen := data[key]; seen {
							t.Fatal("duplicate business message", key)
						}
						data[key] = string(p.Data)
						owners[path] = conn
						if p.Direction == "response" {
							body := bytes.SplitN(p.Data, []byte("\r\n\r\n"), 2)
							if p.Metadata["status"] != 200 || len(body) != 2 || string(body[1]) != "reply "+path {
								t.Fatal("response mismatch", key)
							}
						} else if p.Metadata["method"] != "GET" || p.Metadata["authority"] != "localhost" {
							t.Fatal("request metadata mismatch")
						}
					}
				}
				if len(data) != 48 {
					t.Fatalf("messages=%d want48", len(data))
				}
				for _, v := range []int{1, 2} {
					for _, suite := range []string{"aes128", "aes256", "chacha"} {
						prefix := fmt.Sprintf("/v%d/%s/", v, suite)
						for _, stage := range []string{"seed", "migrate", "accepted", "rejected"} {
							if owners[prefix+stage] == "" {
								t.Fatal("missing matrix cell", prefix+stage)
							}
						}
						if owners[prefix+"seed"] != owners[prefix+"migrate"] || owners[prefix+"accepted"] == owners[prefix+"rejected"] {
							t.Fatal("migration or reused tuple identity mismatch")
						}
					}
				}
				if reference == nil {
					reference = data
				} else if !reflect.DeepEqual(reference, data) {
					t.Fatal("raw/messages or file/stream results differ")
				}
			})
		}
	}
}

func TestHTTP3DynamicCaptureAPIs(t *testing.T) {
	for _, name := range []string{"http3_dynamic_aioquic", "http3_dynamic_aioquic_v2"} {
		t.Run(name, func(t *testing.T) { checkHTTP3DynamicCaptureAPIs(t, "test/testdata/"+name) })
	}
}

func checkHTTP3DynamicCaptureAPIs(t *testing.T, base string) {
	t.Helper()
	capture, clientKeys, serverKeys := quicDSBBlocks(t, base+".pcapng", base+".keys")
	keylog, err := os.ReadFile(base + ".keys")
	if err != nil {
		t.Fatal(err)
	}
	dsb := bytes.Join([][]byte{capture, clientKeys, serverKeys}, nil)
	type semantic struct {
		Metadata map[string]interface{}
		Body     string
	}
	var reference map[string]semantic
	for _, raw := range []bool{false, true} {
		for _, mode := range []string{"external", "seek_dsb", "nonseek_dsb", "late_dsb"} {
			t.Run(fmt.Sprintf("raw=%v/%s", raw, mode), func(t *testing.T) {
				var output []*types.DecryptedPacket
				if mode == "late_dsb" {
					synctest.Test(t, func(t *testing.T) {
						stream := newQUICLiveStream(t, raw)
						stream.write(t, capture)
						synctest.Wait()
						if len(stream.packets) != 0 {
							t.Fatal("output without secrets")
						}
						stream.write(t, clientKeys)
						synctest.Wait()
						stream.assertOpen(t)
						stream.write(t, serverKeys)
						synctest.Wait()
						stream.assertOpen(t)
						count := len(stream.packets)
						if count < 20 {
							t.Fatalf("dynamic output delayed until EOF: %d", count)
						}
						stream.write(t, clientKeys)
						stream.write(t, serverKeys)
						synctest.Wait()
						if len(stream.packets) != count {
							t.Fatal("duplicate DSB repeated output")
						}
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
					var input io.Reader = bytes.NewReader(dsb)
					var secrets io.Reader
					if mode == "external" {
						input = bytes.NewReader(capture)
						secrets = bytes.NewReader(keylog)
					} else if mode == "nonseek_dsb" {
						input = bytes.NewBuffer(dsb)
					}
					ch := make(chan *types.DecryptedPacket)
					done := make(chan struct{})
					go func() {
						defer close(done)
						for p := range ch {
							output = append(output, p)
						}
					}()
					err := DecryptWithConfig(NewDecryptorConfig().WithPcapReader(input).WithSSLKeyLog(secrets).WithPacketChan(ch).
						WithOptions(types.DecryptOptions{RawChunks: raw}).WithLogger(log.New(io.Discard, "", 0)))
					close(ch)
					<-done
					if err != nil {
						t.Fatal(err)
					}
				}
				messages := make(map[string][]*types.DecryptedPacket)
				for _, p := range output {
					tls, ok := p.Metadata["tls"].(map[string]string)
					if !ok || len(tls["ja3"]) != 32 || !strings.HasPrefix(tls["ja4"], "q13") {
						t.Fatal("captured output lost TLS fingerprint")
					}
				}
				if raw {
					parsers := make(map[string]*protocol.HTTP3StreamParser)
					channels := make(map[string]chan *types.DecryptedPacket)
					offsets := make(map[string]uint64)
					ended := make(map[string]bool)
					resets := 0
					for _, p := range output {
						conn := p.ConnectionID()
						id := p.Metadata["stream_id"].(uint64)
						key := fmt.Sprintf("%s/%d/%s", conn, id, p.Direction)
						if parsers[conn] == nil {
							channels[conn] = make(chan *types.DecryptedPacket, 32)
							parsers[conn] = protocol.NewHTTP3StreamParser(types.ConnectionKey{}, channels[conn])
						}
						if ended[key] {
							t.Fatal("bytes after stream completion", key)
						}
						if p.Metadata["kind"] == "stream_reset" {
							resets++
							ended[key] = true
							if p.Metadata["error_code"] != uint64(0x10c) || id != 12 || p.Direction != "response" {
								t.Fatal(p.Metadata)
							}
							if err := parsers[conn].ResetQUICStream(id, false); err != nil {
								t.Fatal(err)
							}
							continue
						}
						if p.Metadata["offset"] != offsets[key] {
							t.Fatal("noncontiguous raw output", key)
						}
						offsets[key] += uint64(len(p.Data))
						ended[key] = p.Metadata["end"] == true
						if err := parsers[conn].FeedQUICStream(id, p.Direction == "request", p.Data, ended[key], p.Timestamp); err != nil {
							t.Fatal(err)
						}
					}
					if resets != 2 {
						t.Fatalf("resets=%d", resets)
					}
					for conn, p := range parsers {
						if err := p.Close(); err != nil {
							t.Fatal(err)
						}
						close(channels[conn])
						for m := range channels[conn] {
							messages[conn] = append(messages[conn], m)
						}
					}
				} else {
					for _, p := range output {
						messages[p.ConnectionID()] = append(messages[p.ConnectionID()], p)
					}
				}
				if len(messages) != 2 {
					t.Fatalf("connections=%d", len(messages))
				}
				got := make(map[string]semantic)
				labels := make(map[string]bool)
				for conn, packets := range messages {
					if len(packets) != 10 {
						t.Fatalf("connection messages=%d, want 10", len(packets))
					}
					label := ""
					for _, p := range packets {
						if p.Direction == "request" {
							label = strings.Split(p.Metadata["path"].(string), "/")[1]
							break
						}
					}
					if label != "alpha" && label != "beta" || labels[label] {
						t.Fatal("connection isolation", label)
					}
					labels[label] = true
					for _, p := range packets {
						id := p.Metadata["stream_id"].(uint64)
						kind, _ := p.Metadata["kind"].(string)
						key := fmt.Sprintf("%s/%d/%s/%s", conn, id, p.Direction, kind)
						if _, exists := got[key]; exists {
							t.Fatal("duplicate event", key)
						}
						parts := bytes.SplitN(p.Data, []byte("\r\n\r\n"), 2)
						if len(parts) != 2 {
							t.Fatal("message framing")
						}
						body := string(parts[1])
						headers := p.Metadata["headers"].(http.Header)
						if p.Direction == "request" {
							suffix := map[uint64]string{0: "warmup", 4: "one", 8: "two", 12: "reset"}[id]
							if suffix == "" || p.Metadata["path"] != "/"+label+"/"+suffix || p.Metadata["method"] != "GET" || p.Metadata["authority"] != "localhost" || headers.Get("x-fixture-token") != strings.Repeat(label, 16) || body != "" {
								t.Fatal("request", p.Metadata, body)
							}
						} else if kind == "informational" {
							if (id != 4 && id != 8) || p.Metadata["status"] != 103 || headers.Get("link") != "</asset>; rel=preload" || body != "" {
								t.Fatal("informational", p.Metadata)
							}
						} else if kind == "push_response" {
							if p.Metadata["push_id"] != uint64(0) || p.Metadata["parent_stream_id"] != uint64(4) || id != 15 || p.Metadata["path"] != "/"+label+"/asset" || body != "asset "+label || p.Metadata["status"] != 200 {
								t.Fatal("push", p.Metadata, body)
							}
						} else {
							suffix := map[uint64]string{0: "warmup", 4: "one", 8: "two"}[id]
							if suffix == "" || kind != "" || p.Metadata["status"] != 200 || body != "reply /"+label+"/"+suffix || headers.Get("x-fixture-token") != strings.Repeat(label, 16) || headers.Get("x-finished") != "" || p.Metadata["trailers"].(http.Header).Get("x-finished") != label {
								t.Fatal("final", p.Metadata, body)
							}
						}
						metadata := maps.Clone(p.Metadata)
						// Plaintext-only reconstruction has no TLS parser. Handshake
						// observations are validated separately on the captured output.
						delete(metadata, "tls")
						got[key] = semantic{metadata, body}
					}
				}
				if reference == nil {
					reference = got
				} else if !reflect.DeepEqual(reference, got) {
					t.Fatal("field semantics/body/stream/direction differ across APIs or raw reconstruction")
				}
			})
		}
	}
}

// The independent peer sends a partial POST and a 0-RTT RESET, then completes
// a separate request. Rejected early RESETs are retransmitted at 1-RTT without
// the POST prefix; these two reset spaces must remain independent.
func TestQUICEarlyResetCaptureAPIs(t *testing.T) {
	const base = "test/testdata/http3_early_reset_aioquic"
	capture, clientKeys, serverKeys := quicDSBBlocks(t, base+".pcapng", base+".keys")
	keys, err := os.ReadFile(base + ".keys")
	if err != nil {
		t.Fatal(err)
	}
	var early, handshake, application []byte
	for _, line := range bytes.Split(keys, []byte("\n")) {
		fields := bytes.Fields(line)
		if len(fields) != 3 || fields[0][0] == '#' {
			continue
		}
		switch string(fields[0]) {
		case "CLIENT_EARLY_TRAFFIC_SECRET":
			early = append(early, append(bytes.Clone(line), '\n')...)
		case "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET":
			handshake = append(handshake, append(bytes.Clone(line), '\n')...)
		default:
			application = append(application, append(bytes.Clone(line), '\n')...)
		}
	}
	for _, mode := range []string{"messages", "raw", "events"} {
		options := types.DecryptOptions{RawChunks: mode == "raw", HTTPEvents: mode == "events"}
		for _, input := range []string{"external", "late_client_first", "late_server_first", "late_early", "late_handshake"} {
			t.Run(mode+"/"+input, func(t *testing.T) {
				if input == "external" {
					packets, err := decryptTLSCapture(t, base+".pcapng", keys, options)
					if err != nil {
						t.Fatal(err)
					}
					checkQUICEarlyResetCapture(t, packets, options)
					return
				}
				synctest.Test(t, func(t *testing.T) {
					stream := newLiveStreamWithOptions(t, options)
					stream.write(t, capture)
					synctest.Wait()
					if len(stream.packets) != 0 {
						t.Fatal("output before secrets")
					}
					groups := [][]byte{clientKeys, serverKeys}
					switch input {
					case "late_server_first":
						groups = [][]byte{serverKeys, clientKeys}
					case "late_early":
						groups = [][]byte{tlsFixtureDSB(t, append(bytes.Clone(application), handshake...)), tlsFixtureDSB(t, early)}
					case "late_handshake":
						groups = [][]byte{tlsFixtureDSB(t, append(bytes.Clone(application), early...)), tlsFixtureDSB(t, handshake)}
					}
					for _, group := range groups {
						stream.write(t, group)
						synctest.Wait()
						stream.assertOpen(t)
					}
					checkQUICEarlyResetCapture(t, stream.packets, options)
					count := len(stream.packets)
					stream.write(t, tlsFixtureDSB(t, keys))
					synctest.Wait()
					if len(stream.packets) != count {
						t.Fatal("duplicate DSB repeated output")
					}
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
				})
			})
		}
	}
}

func checkQUICEarlyResetCapture(t *testing.T, packets []*types.DecryptedPacket, options types.DecryptOptions) {
	t.Helper()
	// Fixed wire prefix from the independent endpoint, including binary body.
	const prefix = "\x01\x1b\x00\x00\xd4\xd7\x50\x86\xa0\xe4\x1d\x13\x9d\x09\x51\x89\x60\xa3\xb2\x8f\x4c\x58\x54\x15\x3f\x54\x02\x36\x34\x00\x09partial\x00\xff"
	byConnection := make(map[string][]*types.DecryptedPacket)
	for _, p := range packets {
		if p.Transport != types.TransportProtocolUDP {
			t.Fatal("non-UDP output")
		}
		byConnection[p.ConnectionID()] = append(byConnection[p.ConnectionID()], p)
	}
	if len(byConnection) != 6 {
		t.Fatalf("connections=%d, want 6", len(byConnection))
	}
	paths := make(map[string]bool)
	for conn, output := range byConnection {
		var earlyStatus string
		if options.RawChunks {
			ch := make(chan *types.DecryptedPacket, 16)
			parser := protocol.NewHTTP3StreamParser(types.ConnectionKey{}, ch)
			data := make(map[string][]byte)
			ended := make(map[string]bool)
			var earlyPrefix []byte
			earlyResets, applicationResets := 0, 0
			for _, p := range output {
				id := p.Metadata["stream_id"].(uint64)
				level, _ := p.Metadata["encryption_level"].(string)
				status, _ := p.Metadata["early_data"].(string)
				space := ""
				if level == "0rtt" {
					if status != "accepted" && status != "rejected" || earlyStatus != "" && earlyStatus != status {
						t.Fatal("early status", p.Metadata)
					}
					earlyStatus = status
					if status == "rejected" {
						space = "early"
					}
				}
				key := fmt.Sprintf("%d/%s/%s", id, p.Direction, space)
				if p.Protocol != "quic" || ended[key] {
					t.Fatal("invalid or repeated stream output", conn, p.Metadata)
				}
				reset := p.Metadata["kind"] == "stream_reset"
				if reset {
					if id != 0 || p.Direction != "request" || p.Metadata["offset"] != uint64(40) || p.Metadata["error_code"] != uint64(0x10c) || len(p.Data) != 0 || p.Metadata["end"] != true {
						t.Fatal("reset", p.Metadata)
					}
					if level == "0rtt" {
						earlyResets++
						if string(earlyPrefix) != prefix {
							t.Fatalf("early prefix lost before reset: %x", earlyPrefix)
						}
					} else if level == "1rtt" && earlyStatus == "rejected" && earlyResets == 1 {
						applicationResets++
					} else {
						t.Fatal("application reset preceded early resolution", p.Metadata)
					}
				} else {
					if p.Metadata["kind"] != "stream_chunk" || p.Metadata["offset"] != uint64(len(data[key])) {
						t.Fatal("raw offsets", p.Metadata)
					}
					data[key] = append(data[key], p.Data...)
					if level == "0rtt" && id == 0 {
						earlyPrefix = append(earlyPrefix, p.Data...)
					}
				}
				ended[key] = p.Metadata["end"] == true
				if space == "early" {
					continue // Rejected bytes cannot become accepted HTTP messages.
				}
				var err error
				if reset {
					err = parser.ResetQUICStream(id, p.Direction == "request")
				} else {
					err = parser.FeedQUICStream(id, p.Direction == "request", p.Data, ended[key], p.Timestamp)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			wantEarly, wantApplication := 0, 0
			if earlyStatus != "" {
				wantEarly = 1
			}
			if earlyStatus == "rejected" {
				wantApplication = 1
			}
			if earlyResets != wantEarly || applicationResets != wantApplication {
				t.Fatalf("early/application resets=%d/%d, want %d/%d", earlyResets, applicationResets, wantEarly, wantApplication)
			}
			if err := parser.Close(); err != nil {
				t.Fatal(err)
			}
			close(ch)
			output = nil
			for p := range ch {
				output = append(output, p)
			}
		}
		type message struct {
			meta map[string]interface{}
			body string
			end  string
		}
		messages := make(map[string]*message)
		path := ""
		for _, p := range output {
			id := p.Metadata["stream_id"].(uint64)
			key := fmt.Sprintf("%d/%s", id, p.Direction)
			if p.Protocol != "http/3" {
				t.Fatal("protocol", p.Protocol)
			}
			if !options.HTTPEvents {
				parts := bytes.SplitN(p.Data, []byte("\r\n\r\n"), 2)
				if len(parts) != 2 || messages[key] != nil {
					t.Fatal("invalid or duplicate complete message")
				}
				messages[key] = &message{meta: p.Metadata, body: string(parts[1]), end: "end"}
			} else {
				kind := p.Metadata["kind"]
				m := messages[key]
				if kind == "headers" {
					if m != nil || p.Metadata["offset"] != uint64(0) || len(p.Data) != 0 {
						t.Fatal("duplicate headers", p.Metadata)
					}
					messages[key] = &message{meta: p.Metadata}
				} else {
					if m == nil || m.end != "" || p.Metadata["offset"] != uint64(len(m.body)) {
						t.Fatal("event order/offset", p.Metadata)
					}
					switch kind {
					case "body_chunk":
						m.body += string(p.Data)
					case "end", "reset":
						m.end = kind.(string)
						if len(p.Data) != 0 || kind == "reset" && p.Metadata["error_code"] != uint64(0x10c) {
							t.Fatal("terminal event", p.Metadata)
						}
					default:
						t.Fatal("unexpected event", p.Metadata)
					}
				}
			}
			if p.Direction == "request" && p.Metadata["method"] == "GET" {
				path = p.Metadata["path"].(string)
			}
		}
		parts := strings.Split(path, "/")
		if len(parts) != 4 || (parts[1] != "v1" && parts[1] != "v2") || (parts[2] != "seed" && parts[2] != "accepted" && parts[2] != "rejected") || parts[3] != "ok" || paths[path] {
			t.Fatal("connection isolation/path", path)
		}
		paths[path] = true
		id := uint64(4)
		if parts[2] == "seed" {
			id = 0
		}
		request, response := messages[fmt.Sprintf("%d/request", id)], messages[fmt.Sprintf("%d/response", id)]
		if request == nil || response == nil || request.meta["method"] != "GET" || request.meta["authority"] != "localhost" || request.body != "" || request.end != "end" || response.meta["status"] != 200 || response.body != "reply "+path || response.end != "end" {
			t.Fatalf("normal request/response lost: %s %+v", path, messages)
		}
		if options.RawChunks && ((parts[2] == "seed" && earlyStatus != "") || (parts[2] != "seed" && earlyStatus != parts[2])) {
			t.Fatal("early status belongs to wrong connection", path, earlyStatus)
		}
		want := 2
		if options.HTTPEvents && parts[2] == "accepted" {
			want++
			m := messages["0/request"]
			if m == nil || m.meta["method"] != "POST" || m.meta["path"] != "/early/reset" || m.meta["headers"].(http.Header).Get("Content-Length") != "64" || m.body != "partial\x00\xff" || m.end != "reset" {
				t.Fatal("accepted early request must end with reset", m)
			}
		}
		if len(messages) != want {
			t.Fatalf("%s emitted %d messages, want %d; incomplete/rejected POST must not complete", path, len(messages), want)
		}
	}
}
