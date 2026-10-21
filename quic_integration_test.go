package ecapture_decryptor

import (
	"bytes"
	"io"
	"net"
	"os"
	"strings"
	"testing"

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
