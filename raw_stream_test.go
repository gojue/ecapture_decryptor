package ecapture_decryptor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"testing"
	"time"

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
