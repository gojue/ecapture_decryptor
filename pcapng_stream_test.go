package ecapture_decryptor

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gojue/ecapture_decryptor/crypto"
	"github.com/gojue/ecapture_decryptor/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/crypto/hkdf"
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
		if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrStreamCanceled) {
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
					var args *types.ProcessArgs
					if annotate && !legacy {
						args = captureTestArgs(name)
					}
					writeCaptureArgsPacket(t, writer, &encoded, ci, raw, args)
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
						if legacy {
							if p.ProcessArgs != nil {
								t.Fatal("invented legacy argv")
							}
						} else if wantArgs := captureTestArgs(name); p.ProcessArgs == nil || !bytes.Equal(p.ProcessArgs.Data, wantArgs.Data) || p.ProcessArgs.Truncated != wantArgs.Truncated {
							t.Fatal("argv crossed endpoints or lost bytes/truncation")
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

func captureTestArgs(name string) *types.ProcessArgs {
	if name == "server" {
		return &types.ProcessArgs{Data: bytes.Repeat([]byte("s"), 256), Truncated: true}
	}
	return &types.ProcessArgs{Data: []byte("client\x00two words\x00\x00参数\x00\xff\x00")}
}

func writeCaptureArgsPacket(t *testing.T, writer *pcapgo.NgWriter, out *bytes.Buffer, ci gopacket.CaptureInfo, data []byte, args *types.ProcessArgs) {
	t.Helper()
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	start := out.Len()
	if err := writer.WritePacket(ci, data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if args == nil {
		return
	}
	flag := 0
	if args.Truncated {
		flag = 1
	}
	comment := fmt.Sprintf("eCapture argv v1 %d ", flag) + base64.StdEncoding.EncodeToString(args.Data)
	out.Truncate(out.Len() - 4)
	options := binary.LittleEndian.AppendUint16(nil, 1)
	options = binary.LittleEndian.AppendUint16(options, uint16(len(comment)))
	options = append(options, comment...)
	options = append(options, make([]byte, (-len(comment))&3)...)
	options = append(options, 0, 0, 0, 0)
	_, _ = out.Write(options)
	length := uint32(out.Len() - start + 4)
	binary.LittleEndian.PutUint32(out.Bytes()[start+4:], length)
	_, _ = out.Write(binary.LittleEndian.AppendUint32(nil, length))
}

func TestProcessArgsOptionsValidation(t *testing.T) {
	full := "eCapture argv v1 0 " + base64.StdEncoding.EncodeToString([]byte("tool\x00\x00"))
	truncated := "eCapture argv v1 1 " + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 256))
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		makeBlock := func(comments ...string) []byte {
			block := make([]byte, 32) // 28-byte header and a 1-byte padded packet
			order.PutUint32(block, 6)
			order.PutUint32(block[20:], 1)
			for _, c := range comments {
				block = order.(binary.AppendByteOrder).AppendUint16(block, 1)
				block = order.(binary.AppendByteOrder).AppendUint16(block, uint16(len(c)))
				block = append(block, c...)
				block = append(block, make([]byte, (-len(c))&3)...)
			}
			block = append(block, make([]byte, 8)...)
			order.PutUint32(block[4:], uint32(len(block)))
			order.PutUint32(block[len(block)-4:], uint32(len(block)))
			return block
		}
		for _, test := range []struct {
			name      string
			comments  []string
			want      bool
			truncated bool
		}{
			{"complete", []string{"unrelated comment", full}, true, false},
			{"truncated", []string{truncated}, true, true},
			{"absent", nil, false, false},
			{"duplicate", []string{full, full}, false, false},
			{"bad flag", []string{"eCapture argv v1 2 dG9vbAA="}, false, false},
			{"unterminated", []string{"eCapture argv v1 0 dG9vbA=="}, false, false},
			{"short truncated", []string{"eCapture argv v1 1 dG9vbA=="}, false, false},
			{"oversized", []string{"eCapture argv v1 1 " + base64.StdEncoding.EncodeToString(make([]byte, 257))}, false, false},
			{"bad base64", []string{"eCapture argv v1 0 ????"}, false, false},
		} {
			t.Run(fmt.Sprint(order)+"/"+test.name, func(t *testing.T) {
				got := pcapngProcessArgs(makeBlock(test.comments...), order)
				if (got != nil) != test.want || got != nil && got.Truncated != test.truncated {
					t.Fatal("unexpected argv acceptance")
				}
			})
		}
		block := makeBlock(full)
		order.PutUint32(block[20:], ^uint32(0))
		if pcapngProcessArgs(block, order) != nil {
			t.Fatal("accepted overflowing packet length")
		}
		block = makeBlock(full)
		order.PutUint16(block[34:], 65535)
		if pcapngProcessArgs(block, order) != nil {
			t.Fatal("accepted overflowing option length")
		}
		for n := 0; n < 32; n++ {
			if pcapngProcessArgs(block[:n], order) != nil {
				t.Fatal("accepted short EPB")
			}
		}
	}
}

// keyLogStreamHellos and keyLogStreamRecord create deterministic, synthetic TLS
// traffic for lifecycle tests; they are not replacements for captured fixtures.
func keyLogStreamHellos(random []byte) ([]byte, []byte) {
	client := append([]byte{3, 3}, random...)
	client = append(client, 0, 0, 2, 0x13, 1, 1, 0, 0, 7, 0, 43, 0, 3, 2, 3, 4)
	server := append([]byte{3, 3}, bytes.Repeat([]byte{0x55}, 32)...)
	server = append(server, 0, 0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4)
	return append([]byte{22, 3, 3, 0, byte(4 + len(client)), 1, 0, 0, byte(len(client))}, client...),
		append([]byte{22, 3, 3, 0, byte(4 + len(server)), 2, 0, 0, byte(len(server))}, server...)
}

func keyLogStreamRecord(t *testing.T, secret []byte, sequence uint64) []byte {
	t.Helper()
	expand := func(label string, n int) []byte {
		label = "tls13 " + label
		info := append([]byte{0, byte(n), byte(len(label))}, label...)
		info = append(info, 0)
		out := make([]byte, n)
		if _, err := io.ReadFull(hkdf.Expand(sha256.New, secret, info), out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	block, err := aes.NewCipher(expand("key", 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := expand("iv", 12)
	binary.BigEndian.PutUint64(nonce[4:], binary.BigEndian.Uint64(nonce[4:])^sequence)
	plain := []byte("lifecycle payload\x17")
	header := []byte{23, 3, 3, 0, byte(len(plain) + aead.Overhead())}
	return append(header, aead.Seal(nil, nonce, plain, header)...)
}

func keyLogStreamPacket(t *testing.T, writer *pcapgo.NgWriter, port uint16, reverse, syn, fin bool, seq uint32, payload []byte) {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2)}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(port), DstPort: 443, Seq: seq, SYN: syn, FIN: fin, ACK: !syn || reverse, Window: 65535}
	if reverse {
		ip.SrcIP, ip.DstIP = ip.DstIP, ip.SrcIP
		tcp.SrcPort, tcp.DstPort = tcp.DstPort, tcp.SrcPort
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	packet := buf.Bytes()
	if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1, 0), CaptureLength: len(packet), Length: len(packet)}, packet); err != nil {
		t.Fatal(err)
	}
}

func TestPcapngStreamKeyLogSequentialConnectionsBeyondCapacity(t *testing.T) {
	for _, rotating := range []bool{false, true} {
		t.Run(fmt.Sprintf("rotating_pending=%v", rotating), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				reader, pipe := io.Pipe()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				defer reader.Close()
				defer pipe.Close()
				done := make(chan error, 1)
				chunks, ends := 0, 0
				var diagnosticMu sync.Mutex
				timeouts := 0
				go func() {
					done <- DecryptPcapngStreamWithOptions(ctx, reader, func(p *types.DecryptedPacket) error {
						switch p.Metadata["kind"] {
						case "stream_chunk":
							if string(p.Data) != "lifecycle payload" {
								return errors.New("incorrect decrypted payload")
							}
							chunks++
						case "stream_end":
							ends++
						}
						return nil
					}, types.DecryptOptions{RawChunks: true, KeyWaitTimeout: 4 * time.Second,
						OnDiagnostic: func(d types.Diagnostic) {
							if strings.Contains(d.Code, "timeout") {
								diagnosticMu.Lock()
								timeouts++
								diagnosticMu.Unlock()
							}
						},
					})
				}()
				writer, err := pcapgo.NewNgWriter(pipe, layers.LinkTypeRaw)
				if err != nil {
					t.Fatal(err)
				}
				secret := bytes.Repeat([]byte{0x31}, 32)
				record := keyLogStreamRecord(t, secret, 0)
				keys := func(random []byte) string {
					return fmt.Sprintf("CLIENT_TRAFFIC_SECRET_0 %x %x\nSERVER_TRAFFIC_SECRET_0 %x %x\n", random, secret, random, secret)
				}
				start := func(port uint16, random []byte, end bool) {
					client, server := keyLogStreamHellos(random)
					keyLogStreamPacket(t, writer, port, false, true, false, 100, nil)
					keyLogStreamPacket(t, writer, port, true, true, false, 100, nil)
					keyLogStreamPacket(t, writer, port, false, false, end, 101, append(client, record...))
					keyLogStreamPacket(t, writer, port, true, false, end, 101, append(server, record...))
				}
				// Keep one fully established connection alive through all reclamation batches.
				activeRandom := bytes.Repeat([]byte{0xff}, 32)
				if err := writer.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, []byte(keys(activeRandom))); err != nil {
					t.Fatal(err)
				}
				start(39999, activeRandom, false)
				if err := writer.Flush(); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				const batches, batchSize = 65, 256 // 16,640 unique connections, plus the active one.
				for batch := 0; batch < batches; batch++ {
					if rotating {
						// Each incomplete ClientHello lives four seconds, but a new
						// worker is admitted every second. Discovery never becomes
						// globally quiescent while the healthy batches are running.
						port := uint16(35000 + batch)
						keyLogStreamPacket(t, writer, port, false, true, false, 100, nil)
						keyLogStreamPacket(t, writer, port, false, false, false, 101, []byte{22, 3, 3, 0, 60, 1})
					}
					var dsb strings.Builder
					for i := 0; i < batchSize; i++ {
						random := make([]byte, 32)
						binary.BigEndian.PutUint64(random[24:], uint64(batch*batchSize+i+1))
						dsb.WriteString(keys(random))
					}
					if batch%2 == 0 {
						if err := writer.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, []byte(dsb.String())); err != nil {
							t.Fatal(err)
						}
					}
					for i := 0; i < batchSize; i++ {
						random := make([]byte, 32)
						binary.BigEndian.PutUint64(random[24:], uint64(batch*batchSize+i+1))
						start(uint16(40000+i), random, true)
					}
					if err := writer.Flush(); err != nil {
						t.Fatal(err)
					}
					synctest.Wait()
					if batch%2 != 0 {
						// Both FINs precede the DSB; no subsequent packet or EOF can wake retries.
						if err := writer.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, []byte(dsb.String())); err != nil {
							t.Fatal(err)
						}
						if err := writer.Flush(); err != nil {
							t.Fatal(err)
						}
						synctest.Wait()
					}
					if chunks != 2+(batch+1)*batchSize*2 || ends != (batch+1)*batchSize*2 {
						pipe.Close()
						t.Fatalf("batch %d: chunks=%d ends=%d err=%v", batch, chunks, ends, <-done)
					}
					if rotating {
						time.Sleep(time.Second)
						synctest.Wait()
					}
				}
				client, server := keyLogStreamHellos(activeRandom)
				next := keyLogStreamRecord(t, secret, 1)
				keyLogStreamPacket(t, writer, 39999, false, false, true, uint32(101+len(client)+len(record)), next)
				keyLogStreamPacket(t, writer, 39999, true, false, true, uint32(101+len(server)+len(record)), next)
				if err := writer.Flush(); err != nil {
					t.Fatal(err)
				}
				if rotating {
					time.Sleep(4 * time.Second)
					synctest.Wait()
				}
				if err := pipe.Close(); err != nil {
					t.Fatal(err)
				}
				err = <-done
				if rotating {
					if !errors.Is(err, ErrConnectionFailures) || errors.Is(err, ErrPipelineFailure) || errors.Is(err, crypto.ErrKeyLogResourceLimit) {
						t.Fatalf("expected only bounded connection summary: %v", err)
					}
					if timeouts != batches {
						t.Fatalf("incomplete workers did not expire: timeouts=%d want=%d", timeouts, batches)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				if chunks != 4+batches*batchSize*2 || ends != 2+batches*batchSize*2 {
					t.Fatal("active connection lost keys or final drain")
				}
			})
		})
	}
}

func TestPcapngStreamConnectionFailuresDoNotStopHealthyConnections(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(fmt.Sprintf("malformed=%v", malformed), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				reader, pipe := io.Pipe()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				defer reader.Close()
				defer pipe.Close()
				var mu sync.Mutex
				var diagnostics []types.Diagnostic
				chunks := 0
				done := make(chan error, 1)
				go func() {
					done <- DecryptPcapngStreamWithOptions(ctx, reader, func(p *types.DecryptedPacket) error {
						if len(p.Data) > 0 {
							chunks++
						}
						return nil
					}, types.DecryptOptions{RawChunks: true, KeyWaitTimeout: time.Second, MaxConnections: 2, OnDiagnostic: func(d types.Diagnostic) { mu.Lock(); defer mu.Unlock(); diagnostics = append(diagnostics, d) }})
				}()
				writer, err := pcapgo.NewNgWriter(pipe, layers.LinkTypeRaw)
				if err != nil {
					t.Fatal(err)
				}
				random, secret := bytes.Repeat([]byte{0x41}, 32), bytes.Repeat([]byte{0x31}, 32)
				client, server := keyLogStreamHellos(random)
				keyLogStreamPacket(t, writer, 40000, false, true, false, 100, nil)
				keyLogStreamPacket(t, writer, 40000, true, true, false, 100, nil)
				if malformed {
					client = []byte{22, 3, 3, 0, 4, 2, 0, 0, 0}
				}
				keyLogStreamPacket(t, writer, 40000, false, false, false, 101, client)
				keyLogStreamPacket(t, writer, 40000, true, false, false, 101, server)
				if err := writer.Flush(); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				time.Sleep(time.Second)
				synctest.Wait()
				select {
				case err := <-done:
					t.Fatalf("connection failure ended stream: %v", err)
				default:
				}
				// More healthy connections than MaxConnections prove failed/completed
				// workers release admission slots, and historical failures do not stop input.
				for i := 0; i < 4; i++ {
					random[0]++
					client, server = keyLogStreamHellos(random)
					keylog := fmt.Sprintf("CLIENT_TRAFFIC_SECRET_0 %x %x\nSERVER_TRAFFIC_SECRET_0 %x %x\n", random, secret, random, secret)
					if err := writer.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, []byte(keylog)); err != nil {
						t.Fatal(err)
					}
					record := keyLogStreamRecord(t, secret, 0)
					keyLogStreamPacket(t, writer, 40001, false, true, false, 100, nil)
					keyLogStreamPacket(t, writer, 40001, true, true, false, 100, nil)
					keyLogStreamPacket(t, writer, 40001, false, false, true, 101, append(client, record...))
					keyLogStreamPacket(t, writer, 40001, true, false, true, 101, append(server, record...))
					if err := writer.Flush(); err != nil {
						t.Fatal(err)
					}
					synctest.Wait()
					if chunks != (i+1)*2 {
						t.Fatalf("healthy connection %d did not decrypt: chunks=%d", i, chunks)
					}
				}
				if err := pipe.Close(); err != nil {
					t.Fatal(err)
				}
				err = <-done
				if !errors.Is(err, ErrConnectionFailures) || errors.Is(err, ErrPipelineFailure) || errors.Is(err, ErrStreamCanceled) {
					t.Fatalf("EOF classification: %v", err)
				}
				mu.Lock()
				defer mu.Unlock()
				if len(diagnostics) == 0 || len(diagnostics) > 8 {
					t.Fatalf("unbounded or missing diagnostics: %d", len(diagnostics))
				}
			})
		})
	}
}

func TestStreamPipelineErrorClassification(t *testing.T) {
	for _, live := range []bool{false, true} {
		var encoded bytes.Buffer
		writer, err := pcapgo.NewNgWriter(&encoded, layers.LinkTypeEthernet)
		if err != nil {
			t.Fatal(err)
		}
		var keylog strings.Builder
		for i := 0; i < 16385; i++ {
			fmt.Fprintf(&keylog, "CLIENT_RANDOM %064x %s\n", i, strings.Repeat("ab", 48))
		}
		if err := writer.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, []byte(keylog.String())); err != nil {
			t.Fatal(err)
		}
		if err := writer.Flush(); err != nil {
			t.Fatal(err)
		}
		if live {
			err = DecryptLiveTraffic(nil, bytes.NewReader(encoded.Bytes()), nil)
		} else {
			err = DecryptPcapngStream(context.Background(), io.NopCloser(bytes.NewReader(encoded.Bytes())), func(*types.DecryptedPacket) error { return nil })
		}
		var detail *crypto.KeyLogResourceLimitError
		if !errors.Is(err, ErrPipelineFailure) || !errors.Is(err, crypto.ErrKeyLogResourceLimit) || !errors.As(err, &detail) || detail.Resource != "entries" || errors.Is(err, ErrConnectionFailures) || errors.Is(err, ErrStreamCanceled) {
			t.Fatalf("pipeline capacity classification live=%v: %v", live, err)
		}
	}
	var encoded bytes.Buffer
	writer, err := pcapgo.NewNgWriter(&encoded, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := DecryptPcapngStream(context.Background(), io.NopCloser(bytes.NewReader(encoded.Bytes())), func(*types.DecryptedPacket) error { return nil }); err != nil {
		t.Fatalf("normal EOF: %v", err)
	}
	err = DecryptPcapngStream(context.Background(), io.NopCloser(bytes.NewReader(encoded.Bytes()[:8])), func(*types.DecryptedPacket) error { return nil })
	if !errors.Is(err, ErrPipelineFailure) || errors.Is(err, ErrConnectionFailures) {
		t.Fatalf("malformed input classification: %v", err)
	}
}

func TestLegacyLiveInputFailureIsNotEOF(t *testing.T) {
	var encoded bytes.Buffer
	writer := pcapgo.NewWriter(&encoded)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	header := bytes.Clone(encoded.Bytes())
	if err := writer.WritePacket(gopacket.CaptureInfo{CaptureLength: 60, Length: 60}, make([]byte, 60)); err != nil {
		t.Fatal(err)
	}
	truncated := encoded.Bytes()[:encoded.Len()-1]
	for _, seekable := range []bool{false, true} {
		for _, data := range [][]byte{header, truncated} {
			var input io.Reader = bytes.NewReader(data)
			if !seekable {
				input = struct{ io.Reader }{input}
			}
			err := DecryptLiveTraffic(nil, input, nil)
			if len(data) == len(header) {
				if err != nil {
					t.Fatalf("legacy header EOF seek=%v: %v", seekable, err)
				}
			} else if !errors.Is(err, ErrPipelineFailure) || !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("truncated legacy input seek=%v: %v", seekable, err)
			}
		}
	}
}
