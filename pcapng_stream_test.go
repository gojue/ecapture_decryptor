package ecapture_decryptor

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/cfc4n/ecapture_decryptor/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type shortReader struct{ io.Reader }

func (r shortReader) Read(p []byte) (int, error) {
	if len(p) > 3 {
		p = p[:3]
	}
	return r.Reader.Read(p)
}

func TestPcapngBlockReaderObservesLateDSBAfterLastPacket(t *testing.T) {
	var encoded bytes.Buffer
	writer, err := pcapgo.NewNgWriter(&encoded, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 60)
	if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1, 0), CaptureLength: len(packet), Length: len(packet)}, packet); err != nil {
		t.Fatal(err)
	}
	secret := []byte("CLIENT_RANDOM " + string(bytes.Repeat([]byte("a"), 64)) + " " + string(bytes.Repeat([]byte("b"), 96)) + "\n")
	if err := writer.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, secret); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	var got [][]byte
	reader := &pcapngBlockReader{source: shortReader{bytes.NewReader(encoded.Bytes())}, onTLSSecrets: func(payload []byte) error {
		got = append(got, bytes.Clone(payload))
		return nil
	}}
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, encoded.Bytes()) || len(got) != 1 || !bytes.Equal(got[0], secret) {
		t.Fatalf("block pass-through or late DSB callback failed: bytes=%d, DSBs=%d", len(decoded), len(got))
	}
}

func TestTCPDirectionReordersAndDeduplicates(t *testing.T) {
	var d tcpDirection
	d.Start(101)
	if ready, err := d.Push(106, []byte("world")); err != nil || len(ready) != 0 {
		t.Fatalf("future segment ready=%v err=%v", ready, err)
	}
	ready, err := d.Push(101, []byte("hello"))
	if err != nil || len(ready) != 2 || string(append(ready[0], ready[1]...)) != "helloworld" {
		t.Fatalf("reassembly ready=%q err=%v", ready, err)
	}
	if ready, err := d.Push(101, []byte("helloworld")); err != nil || len(ready) != 0 {
		t.Fatalf("retransmission ready=%v err=%v", ready, err)
	}
}

func TestTCPDirectionRejectsUnboundedGap(t *testing.T) {
	var d tcpDirection
	d.Start(1)
	if _, err := d.Push(100, make([]byte, maxOutOfOrderBytes+1)); err == nil {
		t.Fatal("out-of-order byte limit was not enforced")
	}
}

func TestPcapngBlockReaderRejectsTruncatedAndMalformedBlocks(t *testing.T) {
	var encoded bytes.Buffer
	writer, err := pcapgo.NewNgWriter(&encoded, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	data := encoded.Bytes()
	if len(data) < 2 {
		t.Fatal("short fixture")
	}
	for _, test := range []struct {
		name string
		data []byte
	}{
		{"truncated", data[:len(data)-1]},
		{"bad trailer", append(bytes.Clone(data[:len(data)-4]), 0, 0, 0, 0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := io.ReadAll(&pcapngBlockReader{source: bytes.NewReader(test.data)})
			if err == nil {
				t.Fatal("malformed pcapng accepted")
			}
		})
	}
}

func TestDecryptPcapngStreamCancellation(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- DecryptPcapngStream(ctx, reader, func(*types.DecryptedPacket) error { return nil }) }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancellation was not returned")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not unblock pcapng read")
	}
}

func TestDecryptPcapngStreamDSBPlacement(t *testing.T) {
	keylog, err := os.ReadFile("test/testdata/all_clients_sslkey.log")
	if err != nil {
		t.Fatal(err)
	}
	pcapFile, err := os.Open("test/testdata/all_clients.pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer pcapFile.Close()
	pcapReader, err := pcapgo.NewReader(pcapFile)
	if err != nil {
		t.Fatal(err)
	}
	type captured struct {
		packet []byte
		info   gopacket.CaptureInfo
	}
	var packets []captured
	for {
		packet, ci, readErr := pcapReader.ReadPacketData()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			t.Fatal(readErr)
		}
		packets = append(packets, captured{bytes.Clone(packet), ci})
	}
	if len(packets) < 10 {
		t.Fatal("fixture lacks handshake and application packets")
	}
	var baseline int
	for _, test := range []struct {
		name      string
		dsbAfter  int
		duplicate bool
	}{
		{"before_packets", 0, false},
		{"after_handshake", 10, false},
		{"after_last_packet", len(packets), false},
		{"duplicate_after_last", len(packets), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var encoded bytes.Buffer
			writer, err := pcapgo.NewNgWriter(&encoded, pcapReader.LinkType())
			if err != nil {
				t.Fatal(err)
			}
			for index, item := range packets {
				if index == test.dsbAfter {
					if err := writer.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, keylog); err != nil {
						t.Fatal(err)
					}
				}
				if err := writer.WritePacket(item.info, item.packet); err != nil {
					t.Fatal(err)
				}
			}
			if test.dsbAfter == len(packets) {
				if err := writer.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, keylog); err != nil {
					t.Fatal(err)
				}
			}
			if test.duplicate {
				if err := writer.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, keylog); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Flush(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			count := 0
			err = DecryptPcapngStream(ctx, io.NopCloser(shortReader{bytes.NewReader(encoded.Bytes())}), func(packet *types.DecryptedPacket) error {
				if packet.Direction == "request" || packet.Direction == "response" {
					count++
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if count == 0 {
				t.Fatal("DSB placement produced no decrypted HTTP messages")
			}
			if baseline == 0 {
				baseline = count
			} else if count != baseline {
				t.Fatalf("message count %d differs from baseline %d", count, baseline)
			}
		})
	}
}
