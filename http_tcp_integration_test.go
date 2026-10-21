package ecapture_decryptor

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/gojue/ecapture_decryptor/types"
)

// All fixtures are real Linux VM captures of TLS traffic on 127.0.0.1.
func TestDecryptTCPHTTPCaptures(t *testing.T) {
	for _, tc := range []struct {
		name, capture, keylog, protocol string
		serverPort                      uint32
		requests                        int
		stream                          bool
	}{
		{"http10_external_keylog", "test/testdata/http10_tcpdump_no_dsb.pcapng", "test/testdata/http10_tcpdump.keys", "http/1.0", 44434, 1, false},
		{"http10_embedded_dsb", "test/testdata/http10_ecapture_dsb.pcapng", "", "http/1.0", 44434, 1, false},
		{"http10_stream_external_keylog", "test/testdata/http10_tcpdump_no_dsb.pcapng", "test/testdata/http10_tcpdump.keys", "http/1.0", 44434, 1, true},
		{"http10_stream_embedded_dsb", "test/testdata/http10_ecapture_dsb.pcapng", "", "http/1.0", 44434, 1, true},
		{"http10_embedded_dsb_plus_external", "test/testdata/http10_ecapture_dsb.pcapng", "test/testdata/http11_keepalive_chunked_tcpdump.keys", "http/1.0", 44434, 1, false},
		{"http11_external_keylog", "test/testdata/http11_keepalive_chunked_tcpdump_no_dsb.pcapng", "test/testdata/http11_keepalive_chunked_tcpdump.keys", "http/1.1", 44435, 2, false},
		{"http11_embedded_dsb", "test/testdata/http11_keepalive_chunked_ecapture_dsb.pcapng", "", "http/1.1", 44435, 2, false},
		{"http11_stream_external_keylog", "test/testdata/http11_keepalive_chunked_tcpdump_no_dsb.pcapng", "test/testdata/http11_keepalive_chunked_tcpdump.keys", "http/1.1", 44435, 2, true},
		{"http11_stream_embedded_dsb", "test/testdata/http11_keepalive_chunked_ecapture_dsb.pcapng", "", "http/1.1", 44435, 2, true},
		{"http2_external_keylog", "test/testdata/http2_multiplex_tcpdump_no_dsb.pcapng", "test/testdata/http2_multiplex_tcpdump.keys", "http/2", 44436, 2, false},
		{"http2_embedded_dsb", "test/testdata/http2_multiplex_ecapture_dsb.pcapng", "", "http/2", 44436, 2, false},
		{"http2_stream_external_keylog", "test/testdata/http2_multiplex_tcpdump_no_dsb.pcapng", "test/testdata/http2_multiplex_tcpdump.keys", "http/2", 44436, 2, true},
		{"http2_stream_embedded_dsb", "test/testdata/http2_multiplex_ecapture_dsb.pcapng", "", "http/2", 44436, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capture, err := os.Open(tc.capture)
			if err != nil {
				t.Fatal(err)
			}
			defer capture.Close()
			var input io.Reader = capture
			if tc.stream {
				data, err := io.ReadAll(capture)
				if err != nil {
					t.Fatal(err)
				}
				input = bytes.NewBuffer(data)
			}
			var external io.Reader
			if tc.keylog != "" {
				keylog, err := os.ReadFile(tc.keylog)
				if err != nil {
					t.Fatal(err)
				}
				external = bytes.NewReader(keylog)
			}
			output := make(chan *types.DecryptedPacket, 32)
			if err := DecryptPcapFile(external, input, output); err != nil {
				t.Fatal(err)
			}
			close(output)
			var requests, responses []*types.DecryptedPacket
			clientPorts := make(map[uint32]bool)
			for packet := range output {
				if packet.Protocol != tc.protocol {
					continue
				}
				logDecryptedPreview(t, packet)
				if packet.Transport != types.TransportProtocolTCP {
					t.Fatalf("transport=%q, want TCP", packet.Transport)
				}
				if packet.Direction == "request" {
					if packet.DstIP != "127.0.0.1" || packet.DstPort != tc.serverPort {
						t.Fatalf("bad request endpoint: %+v", packet)
					}
					clientPorts[packet.SrcPort] = true
					requests = append(requests, packet)
				} else if packet.Direction == "response" {
					if packet.SrcIP != "127.0.0.1" || packet.SrcPort != tc.serverPort {
						t.Fatalf("bad response endpoint: %+v", packet)
					}
					responses = append(responses, packet)
				}
			}
			if len(requests) != tc.requests || len(responses) != tc.requests {
				t.Fatalf("decrypted %d requests and %d responses, want %d each", len(requests), len(responses), tc.requests)
			}
			if len(clientPorts) != 1 {
				t.Fatalf("used %d TCP connections, want one", len(clientPorts))
			}
			switch tc.protocol {
			case "http/1.0":
				response := string(responses[0].Data)
				if !strings.Contains(string(requests[0].Data), "GET /legacy HTTP/1.0") ||
					!strings.HasPrefix(response, "HTTP/1.0 200 OK\r\n") ||
					!strings.HasSuffix(response, "legacy-response") ||
					strings.Contains(response, "Content-Length:") || strings.Contains(response, "Transfer-Encoding:") {
					t.Fatal("HTTP/1.0 close-delimited exchange incomplete")
				}
			case "http/1.1":
				var keepRequest, keepResponse, chunkRequest, chunkResponse bool
				for _, packet := range requests {
					data := string(packet.Data)
					if strings.Contains(data, "GET /keep-one HTTP/1.1") {
						keepRequest = true
					}
					if strings.Contains(data, "POST /chunked HTTP/1.1") && strings.Contains(strings.ToLower(data), "transfer-encoding: chunked") && strings.Contains(data, "hello") && strings.Contains(data, "-chunked-world") {
						chunkRequest = true
					}
				}
				for _, packet := range responses {
					data := string(packet.Data)
					if strings.Contains(data, "HTTP/1.1 200 OK") && strings.Contains(data, "keep-one-response") {
						keepResponse = true
					}
					if strings.Contains(data, "HTTP/1.1 201") && strings.Contains(strings.ToLower(data), "transfer-encoding: chunked") && strings.Contains(data, "chunked-") && strings.Contains(data, "response") {
						chunkResponse = true
					}
				}
				if !keepRequest || !keepResponse || !chunkRequest || !chunkResponse {
					t.Fatalf("HTTP/1.1 keep-alive/chunked exchange incomplete: keep request=%t response=%t chunked request=%t response=%t", keepRequest, keepResponse, chunkRequest, chunkResponse)
				}
			case "http/2":
				streams := make(map[uint32]map[string]*types.DecryptedPacket)
				for _, packet := range append(requests, responses...) {
					id, ok := packet.Metadata["stream_id"].(uint32)
					if !ok {
						t.Fatalf("missing HTTP/2 stream ID: %v", packet.Metadata)
					}
					if streams[id] == nil {
						streams[id] = make(map[string]*types.DecryptedPacket)
					}
					streams[id][packet.Direction] = packet
				}
				if len(streams) != 2 {
					t.Fatalf("HTTP/2 stream count=%d, want two", len(streams))
				}
				paths := make(map[string]bool)
				for id, pair := range streams {
					if pair["request"] == nil || pair["response"] == nil {
						t.Fatalf("incomplete HTTP/2 stream %d", id)
					}
					path, ok := pair["request"].Metadata["path"].(string)
					if !ok || !strings.Contains(string(pair["response"].Data), "multiplexed-response-"+strings.TrimPrefix(path, "/")) {
						t.Fatalf("HTTP/2 stream %d response does not match request %q", id, path)
					}
					paths[path] = true
				}
				if !paths["/alpha"] || !paths["/beta"] {
					t.Fatalf("HTTP/2 paths=%v", paths)
				}
			}
		})
	}
}
