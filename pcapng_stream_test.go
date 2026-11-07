package ecapture_decryptor

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"testing"
	"time"

	"github.com/gojue/ecapture_decryptor/types"
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
	const minimumPerDirection = 25 // The fixture has 25 TLS connections with HTTP exchanges.
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
			// The capture includes a multi-megabyte upload. Race instrumentation
			// and coverage can make offline replay much slower on shared CI runners.
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			var requests, responses int
			// Block fragmentation is covered by TestPcapngBlockReaderObservesLateDSBAfterLastPacket.
			// This fixture contains multi-megabyte HTTP bodies; forcing three-byte reads
			// makes the race and coverage build spend its deadline in the test reader.
			err = DecryptPcapngStream(ctx, io.NopCloser(bytes.NewReader(encoded.Bytes())), func(packet *types.DecryptedPacket) error {
				if len(packet.Data) == 0 {
					return nil
				}
				switch packet.Direction {
				case "request":
					requests++
				case "response":
					responses++
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if requests < minimumPerDirection || responses < minimumPerDirection {
				t.Fatalf("DSB placement decrypted %d requests and %d responses; expected at least %d of each", requests, responses, minimumPerDirection)
			}
		})
	}
}

func TestDecryptPcapFileKeyLogSources(t *testing.T) {
	const minimumPerDirection = 25 // The fixture has 25 TLS connections with HTTP exchanges.
	keylog, err := os.ReadFile("test/testdata/all_clients_sslkey.log")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name        string
		includeDSB  bool
		externalLog bool
	}{
		{name: "external_keylog", externalLog: true},
		{name: "embedded_dsb", includeDSB: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			capture, err := os.Open("test/testdata/all_clients.pcap")
			if err != nil {
				t.Fatal(err)
			}
			defer capture.Close()
			pcap, err := pcapgo.NewReader(capture)
			if err != nil {
				t.Fatal(err)
			}
			path := t.TempDir() + "/capture.pcapng"
			output, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			writer, err := pcapgo.NewNgWriter(output, pcap.LinkType())
			if err != nil {
				t.Fatal(err)
			}
			for {
				packet, info, readErr := pcap.ReadPacketData()
				if readErr == io.EOF {
					break
				}
				if readErr != nil {
					t.Fatal(readErr)
				}
				if err := writer.WritePacket(info, packet); err != nil {
					t.Fatal(err)
				}
			}
			if test.includeDSB {
				if err := writer.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, keylog); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Flush(); err != nil {
				t.Fatal(err)
			}
			if err := output.Close(); err != nil {
				t.Fatal(err)
			}

			input, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			var external io.Reader
			if test.externalLog {
				external = bytes.NewReader(keylog)
			}
			packets := make(chan *types.DecryptedPacket, 256)
			type messageCounts struct{ requests, responses int }
			countDone := make(chan messageCounts, 1)
			go func() {
				var counts messageCounts
				for packet := range packets {
					if len(packet.Data) == 0 {
						continue
					}
					switch packet.Direction {
					case "request":
						counts.requests++
					case "response":
						counts.responses++
					}
				}
				countDone <- counts
			}()
			err = DecryptPcapFile(external, input, packets)
			close(packets)
			if err != nil {
				t.Fatal(err)
			}
			counts := <-countDone
			if counts.requests < minimumPerDirection || counts.responses < minimumPerDirection {
				t.Fatalf("decrypted %d requests and %d responses; expected at least %d of each", counts.requests, counts.responses, minimumPerDirection)
			}
		})
	}
}

func processTrailer(pid uint32, name string, endpoint byte, legacy bool) []byte {
	data := make([]byte, 9+len(name))
	binary.BigEndian.PutUint32(data, 0xCC0C4CFC)
	binary.BigEndian.PutUint32(data[4:], pid)
	data[8] = byte(len(name))
	copy(data[9:], name)
	if !legacy {
		data = append(data, 1, endpoint)
	}
	return append(data, 0, 0, 0, 0)
}

func TestProcessTrailerBoundaries(t *testing.T) {
	// Historical Ethernet encoders pad short IP packets before the trailer.
	for _, vlan := range []bool{false, true} {
		header := 14
		if vlan {
			header += 4
		}
		raw := make([]byte, 60)
		raw[12] = 8
		if vlan {
			raw[12], raw[13], raw[16] = 0x81, 0, 8
		}
		raw[header], raw[header+9] = 0x45, 17
		binary.BigEndian.PutUint16(raw[header+2:], 28)
		binary.BigEndian.PutUint16(raw[header+24:], 8)
		packet := gopacket.NewPacket(append(raw, processTrailer(42, "padded", 2, true)...), layers.LayerTypeEthernet, gopacket.Default)
		info := packetProcess(packet)
		if info == nil {
			t.Fatal("lost padded legacy trailer")
		}
		if pid, name := info.Identity("response"); pid != 42 || name != "padded" {
			t.Fatal("lost legacy process identity")
		}
	}
	for _, ipv6 := range []bool{false, true} {
		raw := make([]byte, 74)
		if ipv6 {
			raw[12], raw[13], raw[14], raw[20] = 0x86, 0xdd, 0x60, 17
			binary.BigEndian.PutUint16(raw[18:], 20)
		} else {
			raw[12], raw[13], raw[14], raw[23] = 8, 0, 0x45, 17
			binary.BigEndian.PutUint16(raw[16:], 60)
		}
		for _, legacy := range []bool{false, true} {
			trailer := processTrailer(4242, "client\x00", 1, legacy)
			packet := gopacket.NewPacket(append(bytes.Clone(raw), trailer...), layers.LayerTypeEthernet, gopacket.Default)
			info := packetProcess(packet)
			if info == nil {
				t.Fatal("missing valid trailer")
			}
			if pid, name := info.Identity("request"); pid != 4242 || name != "client" {
				t.Fatal("lost trailer metadata")
			}
			for n := 0; n < 9+len("client\x00"); n++ {
				if packetProcess(gopacket.NewPacket(append(bytes.Clone(raw), trailer[:n]...), layers.LayerTypeEthernet, gopacket.Default)) != nil {
					t.Fatalf("accepted truncated trailer %d", n)
				}
			}
			for _, bad := range [][]byte{bytes.Repeat([]byte{0}, 20), processTrailer(0, "client", 1, false), processTrailer(42, "client", 3, false), processTrailer(42, "01234567890123456", 1, false)} {
				if packetProcess(gopacket.NewPacket(append(bytes.Clone(raw), bad...), layers.LayerTypeEthernet, gopacket.Default)) != nil {
					t.Fatal("accepted invalid process trailer")
				}
			}
		}
	}
}

// The encrypted fixture stays unchanged; only test capture annotations are
// synthetic. This checks real TLS/QUIC parsing, DSBs, callbacks and stable IDs.
func TestCaptureProcessFileAndStream(t *testing.T) {
	for _, fixture := range []struct {
		name string
		port layers.TCPPort
	}{
		{"http11_keepalive_chunked", 44435}, {"http2_multiplex", 44436}, {"http3_loopback", 44433},
	} {
		for _, legacy := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/legacy=%v", fixture.name, legacy), func(t *testing.T) {
				file, err := os.Open("test/testdata/" + fixture.name + "_tcpdump_no_dsb.pcapng")
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				reader, err := pcapgo.NewNgReader(file, pcapgo.DefaultNgReaderOptions)
				if err != nil {
					t.Fatal(err)
				}
				var encoded bytes.Buffer
				writer, err := pcapgo.NewNgWriter(&encoded, layers.LinkTypeEthernet)
				if err != nil {
					t.Fatal(err)
				}
				for {
					raw, ci, err := reader.ReadPacketData()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					packet := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
					pid, name := uint32(101), "client"
					annotate := true
					if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
						annotate = !tcp.SYN // first packet deliberately has no owner
						if tcp.SrcPort == fixture.port && !legacy {
							pid, name = 202, "server"
						}
					} else if udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
						if uint16(udp.SrcPort) == uint16(fixture.port) && !legacy {
							pid, name = 202, "server"
						}
					}
					if annotate {
						raw = append(raw, processTrailer(pid, name, 1, legacy)...)
						ci.CaptureLength = len(raw)
						ci.Length = len(raw)
					}
					if err := writer.WritePacket(ci, raw); err != nil {
						t.Fatal(err)
					}
				}
				keys, err := os.ReadFile("test/testdata/" + fixture.name + "_tcpdump.keys")
				if err != nil {
					t.Fatal(err)
				}
				// Late secrets also allow process observations to arrive before output.
				if err := writer.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, keys); err != nil {
					t.Fatal(err)
				}
				if err := writer.Flush(); err != nil {
					t.Fatal(err)
				}
				for _, stream := range []bool{false, true} {
					var packets []*types.DecryptedPacket
					if stream {
						err = DecryptPcapngStream(context.Background(), io.NopCloser(bytes.NewReader(encoded.Bytes())), func(p *types.DecryptedPacket) error { packets = append(packets, p); return nil })
					} else {
						output := make(chan *types.DecryptedPacket)
						done := make(chan struct{})
						go func() {
							defer close(done)
							for p := range output {
								packets = append(packets, p)
							}
						}()
						err = DecryptWithConfig(NewDecryptorConfig().WithPcapReader(bytes.NewReader(encoded.Bytes())).WithPacketChan(output).WithLogger(log.New(io.Discard, "", 0)))
						close(output)
						<-done
					}
					if err != nil {
						t.Fatal(err)
					}
					ids := map[string]bool{}
					directions := map[string]int{}
					for _, p := range packets {
						want, name := int64(101), "client"
						if p.Direction == "response" && !legacy {
							want, name = 202, "server"
						}
						if p.PID != want || p.PName != name {
							t.Fatalf("stream=%v direction=%s pid=%d name=%q want=%d/%s", stream, p.Direction, p.PID, p.PName, want, name)
						}
						ids[p.ConnectionID()] = true
						directions[p.Direction]++
					}
					if len(ids) != 1 || directions["request"] == 0 || directions["response"] == 0 {
						t.Fatalf("attribution split/dropped connection: ids=%d directions=%v", len(ids), directions)
					}
				}
			})
		}
	}
}
