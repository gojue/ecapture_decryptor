package ecapture_decryptor

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gojue/ecapture_decryptor/types"
)

// Exercise the streaming API with unmodified eCapture pcapng files whose DSBs
// contain the keys needed for the complete HTTP exchanges.
func TestDecryptPcapngStreamCapturedTraffic(t *testing.T) {
	for _, tc := range []struct {
		name, capture, protocol, transport string
		requestMarkers, responseMarkers    []string
	}{
		{
			"http10", "test/testdata/http10_ecapture_dsb.pcapng", "http/1.0", types.TransportProtocolTCP,
			[]string{"GET /legacy HTTP/1.0"}, []string{"HTTP/1.0 200 OK", "legacy-response"},
		},
		{
			"http11_keepalive_chunked", "test/testdata/http11_keepalive_chunked_ecapture_dsb.pcapng", "http/1.1", types.TransportProtocolTCP,
			[]string{"GET /keep-one HTTP/1.1", "POST /chunked HTTP/1.1", "Transfer-Encoding: chunked"},
			[]string{"keep-one-response", "HTTP/1.1 201 Created", "Transfer-Encoding: chunked", "chunked-"},
		},
		{
			"http2_multiplex", "test/testdata/http2_multiplex_ecapture_dsb.pcapng", "http/2", types.TransportProtocolTCP,
			[]string{"GET /alpha HTTP/2.0", "GET /beta HTTP/2.0"},
			[]string{"multiplexed-response-alpha", "multiplexed-response-beta"},
		},
		{
			"http3_loopback", "test/testdata/http3_loopback_ecapture_dsb.pcapng", "http/3", types.TransportProtocolUDP,
			[]string{"GET /one HTTP/3.0", "POST /upload HTTP/3.0"},
			[]string{"GET /one ", "POST /upload "},
		},
		{
			"http3_public", "test/testdata/http3_cloudflare_ecapture_dsb.pcapng", "http/3", types.TransportProtocolUDP,
			[]string{"GET /robots.txt HTTP/3.0", "GET /favicon.ico HTTP/3.0"},
			[]string{"HTTP/3.0 200"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input, err := os.Open(tc.capture)
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			var packets []*types.DecryptedPacket
			if err := DecryptPcapngStream(ctx, input, func(packet *types.DecryptedPacket) error {
				packets = append(packets, packet)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			requestCount, responseCount := 0, 0
			var requests, responses strings.Builder
			for _, packet := range packets {
				logDecryptedPreview(t, packet)
				if packet.Protocol != tc.protocol || packet.Transport != tc.transport {
					t.Fatalf("unexpected protocol/transport: %s/%s", packet.Protocol, packet.Transport)
				}
				switch packet.Direction {
				case "request":
					requestCount++
					requests.Write(packet.Data)
				case "response":
					responseCount++
					responses.Write(packet.Data)
				default:
					t.Fatalf("unexpected direction %q", packet.Direction)
				}
			}
			wantMessages := 1
			if tc.protocol != "http/1.0" {
				wantMessages = 2
			}
			if requestCount != wantMessages || responseCount != wantMessages {
				t.Fatalf("decrypted %d requests and %d responses, want %d each", requestCount, responseCount, wantMessages)
			}
			for _, marker := range tc.requestMarkers {
				if !strings.Contains(requests.String(), marker) {
					t.Errorf("missing request marker %q", marker)
				}
			}
			for _, marker := range tc.responseMarkers {
				if !strings.Contains(responses.String(), marker) {
					t.Errorf("missing response marker %q", marker)
				}
			}
		})
	}
}

func TestDecryptPcapngStreamCapturedTrafficCallbackError(t *testing.T) {
	input, err := os.Open("test/testdata/http10_ecapture_dsb.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	wantErr := errors.New("stop after first decrypted message")
	callbacks := 0
	err = DecryptPcapngStream(ctx, input, func(*types.DecryptedPacket) error {
		callbacks++
		return wantErr
	})
	if !errors.Is(err, wantErr) || callbacks != 1 {
		t.Fatalf("callback error=%v, callbacks=%d; want original error and one callback", err, callbacks)
	}
}
