package transport

import (
	"io"
	"log"
	"testing"

	"github.com/cfc4n/ecapture_decryptor/crypto"
	"github.com/cfc4n/ecapture_decryptor/protocol"
	"github.com/cfc4n/ecapture_decryptor/types"
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
