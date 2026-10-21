package transport

import (
	"io"
	"log"
	"strings"
	"testing"

	"github.com/gojue/ecapture_decryptor/crypto"
	"github.com/gojue/ecapture_decryptor/protocol"
	"github.com/gojue/ecapture_decryptor/types"
)

func TestSplitHTTP2PrefaceSelectsHTTP2Parser(t *testing.T) {
	output := make(chan *types.DecryptedPacket, 1)
	decryptor := NewTLSDecryptor(types.ConnectionKey{}, crypto.NewKeyLogStore(), io.Discard, io.Discard, log.New(io.Discard, "", 0), output)
	decryptor.queueRequest([]byte("PRI *"))
	if decryptor.parser != nil {
		t.Fatal("selected a parser before the HTTP/2 preface was complete")
	}
	decryptor.queueRequest([]byte(" HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	if _, ok := decryptor.parser.(*protocol.HTTP2StreamParser); !ok {
		t.Fatalf("selected %T for split HTTP/2 preface", decryptor.parser)
	}
}

func TestTLSDecryptorKeepsResponseBeforeProtocolDetection(t *testing.T) {
	output := make(chan *types.DecryptedPacket, 2)
	decryptor := NewTLSDecryptor(types.ConnectionKey{}, crypto.NewKeyLogStore(), io.Discard, io.Discard, log.New(io.Discard, "", 0), output)
	decryptor.queueResponse([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	decryptor.queueRequest([]byte("GET /early HTTP/1.1\r\nHost: example.test\r\n\r\n"))

	if got := len(output); got != 2 {
		t.Fatalf("got %d parsed packets, want request and response", got)
	}
	request, response := <-output, <-output
	if request.Direction != "request" || response.Direction != "response" {
		t.Fatalf("got directions %q and %q, want request and response", request.Direction, response.Direction)
	}
	if !strings.Contains(string(response.Data), "\r\n\r\nok") {
		t.Fatalf("response body was lost: %q", response.Data)
	}
}
