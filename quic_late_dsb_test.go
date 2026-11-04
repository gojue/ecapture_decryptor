// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package ecapture_decryptor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"testing/synctest"

	"github.com/gojue/ecapture_decryptor/types"
	"github.com/google/gopacket/pcapgo"
)

func TestQUICStreamLateDSBBeforeEOF(t *testing.T) {
	packets, clientKeys, serverKeys := quicLateDSBBlocks(t)
	synctest.Test(t, func(t *testing.T) {
		// Two independent engines stay open concurrently, one for each output
		// mode. All I/O within the bubble uses io.Pipe, never files or sockets.
		streams := []*quicLiveStream{newQUICLiveStream(t, false), newQUICLiveStream(t, true)}
		for _, stream := range streams {
			stream.write(t, packets)
		}
		// Unlike a completed Pipe.Write, Wait also proves the QUIC workers have
		// drained their UDP input and are blocked with deferred encrypted data.
		synctest.Wait()
		for _, stream := range streams {
			stream.assertOpen(t)
			if len(stream.packets) != 0 {
				t.Fatal("QUIC application output appeared without secrets")
			}
			stream.write(t, clientKeys)
		}
		synctest.Wait()
		for _, stream := range streams {
			stream.assertOpen(t)
			assertQUICLiveOutput(t, stream.packets, stream.raw, false)
			stream.write(t, serverKeys)
		}
		synctest.Wait()
		counts := make([]int, len(streams))
		for i, stream := range streams {
			stream.assertOpen(t)
			assertQUICLiveOutput(t, stream.packets, stream.raw, true)
			counts[i] = len(stream.packets)
			// There are no packet blocks after the initial write, including here.
			stream.write(t, clientKeys)
			stream.write(t, serverKeys)
		}
		synctest.Wait()
		for i, stream := range streams {
			stream.assertOpen(t)
			if len(stream.packets) != counts[i] {
				t.Fatalf("raw=%v: duplicate DSB repeated application output", stream.raw)
			}
			if err := stream.writer.Close(); err != nil {
				t.Fatal(err)
			}
		}
		synctest.Wait()
		for i, stream := range streams {
			select {
			case err := <-stream.done:
				if err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatal("QUIC stream did not finish after EOF")
			}
			if len(stream.packets) != counts[i] {
				t.Fatalf("raw=%v: output was delayed until EOF or repeated", stream.raw)
			}
		}
	})
}

func TestQUICStreamMissingKeysCancellation(t *testing.T) {
	packets, _, _ := quicLateDSBBlocks(t)
	synctest.Test(t, func(t *testing.T) {
		streams := []*quicLiveStream{newQUICLiveStream(t, false), newQUICLiveStream(t, true)}
		for _, stream := range streams {
			stream.write(t, packets)
		}
		synctest.Wait()
		for _, stream := range streams {
			stream.assertOpen(t)
			stream.cancel()
		}
		synctest.Wait()
		for _, stream := range streams {
			select {
			case err := <-stream.done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("missing-key cancellation: %v", err)
				}
			default:
				t.Fatal("missing-key QUIC stream did not stop after cancellation")
			}
			if len(stream.packets) != 0 {
				t.Fatal("missing-key cancellation emitted application output")
			}
		}
	})
}

type quicLiveStream struct {
	writer  *io.PipeWriter
	cancel  context.CancelFunc
	done    chan error
	raw     bool
	packets []*types.DecryptedPacket // Read only after synctest.Wait synchronizes callbacks.
}

func newQUICLiveStream(t *testing.T, raw bool) *quicLiveStream {
	t.Helper()
	reader, writer := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	stream := &quicLiveStream{writer: writer, cancel: cancel, done: make(chan error, 1), raw: raw}
	t.Cleanup(func() {
		cancel()
		_ = writer.Close()
	})
	go func() {
		stream.done <- DecryptPcapngStreamWithOptions(ctx, reader, func(packet *types.DecryptedPacket) error {
			stream.packets = append(stream.packets, packet)
			return nil
		}, types.DecryptOptions{RawChunks: raw})
	}()
	return stream
}

func (stream *quicLiveStream) write(t *testing.T, data []byte) {
	t.Helper()
	if _, err := stream.writer.Write(data); err != nil {
		t.Fatal(err)
	}
}

func (stream *quicLiveStream) assertOpen(t *testing.T) {
	t.Helper()
	select {
	case err := <-stream.done:
		t.Fatalf("raw=%v: stream exited before input EOF: %v", stream.raw, err)
	default:
	}
}

func assertQUICLiveOutput(t *testing.T, packets []*types.DecryptedPacket, raw, responses bool) {
	t.Helper()
	data := make(map[string][]byte)
	ended := make(map[string]bool)
	for _, packet := range packets {
		id, ok := packet.Metadata["stream_id"].(uint64)
		if !ok || packet.Transport != types.TransportProtocolUDP {
			t.Fatal("QUIC output is missing stream identity or UDP transport")
		}
		key := fmt.Sprintf("%d/%s", id, packet.Direction)
		if ended[key] {
			t.Fatal("QUIC stream emitted output after its completed message or FIN")
		}
		if raw {
			if packet.Protocol != "quic" || packet.Metadata["offset"] != uint64(len(data[key])) {
				t.Fatal("raw QUIC output has incorrect protocol or non-contiguous offsets")
			}
			data[key] = append(data[key], packet.Data...)
			ended[key] = packet.Metadata["end"] == true
		} else {
			parts := bytes.SplitN(packet.Data, []byte("\r\n\r\n"), 2)
			if packet.Protocol != "http/3" || len(parts) != 2 {
				t.Fatal("HTTP/3 output has incorrect protocol or message framing")
			}
			data[key], ended[key] = parts[1], true
		}
	}
	for _, item := range []struct {
		key, body string
		response  bool
	}{
		{"0/request", "", false},
		{"4/request", string(bytes.Repeat([]byte("payload-"), 300)), false},
		{"0/response", "GET /one ", true},
		{"4/response", "POST /upload " + string(bytes.Repeat([]byte("payload-"), 300)), true},
	} {
		if item.response && !responses {
			if _, ok := data[item.key]; ok {
				t.Fatal("server output appeared before its application secret")
			}
			continue
		}
		if !ended[item.key] {
			t.Fatalf("raw=%v: stream %s did not finish before EOF", raw, item.key)
		}
		if raw {
			if len(data[item.key]) == 0 || !bytes.Contains(data[item.key], []byte(item.body)) {
				t.Fatalf("raw stream %s lost expected application bytes", item.key)
			}
		} else if !bytes.Equal(data[item.key], []byte(item.body)) {
			t.Fatalf("HTTP/3 stream %s body differs", item.key)
		}
	}
	if !raw && len(data) != map[bool]int{false: 2, true: 4}[responses] {
		t.Fatalf("unexpected HTTP/3 message count: %d", len(data))
	}
}

// Read only the tracked loopback fixture, outside any synctest bubble. Rewrap
// its real packets and split its matching secrets into two later DSB updates.
func quicLateDSBBlocks(t *testing.T) (packets, clientKeys, serverKeys []byte) {
	t.Helper()
	file, err := os.Open("test/testdata/http3_loopback_tcpdump_no_dsb.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader, err := pcapgo.NewNgReader(file, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	writer, err := pcapgo.NewNgWriter(&encoded, reader.LinkType())
	if err != nil {
		t.Fatal(err)
	}
	for {
		packet, info, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.WritePacket(info, packet); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	packets = bytes.Clone(encoded.Bytes())
	keylog, err := os.ReadFile("test/testdata/http3_loopback_tcpdump.keys")
	if err != nil {
		t.Fatal(err)
	}
	var groups [2][]byte
	for _, line := range bytes.Split(keylog, []byte("\n")) {
		fields := bytes.Fields(line)
		if len(fields) != 3 || bytes.HasPrefix(fields[0], []byte("#")) {
			continue
		}
		group := 0
		if bytes.Equal(fields[0], []byte("SERVER_TRAFFIC_SECRET_0")) {
			group = 1
		}
		groups[group] = append(groups[group], append(bytes.Clone(line), '\n')...)
	}
	blocks := [2]*[]byte{&clientKeys, &serverKeys}
	for i, group := range groups {
		if len(group) == 0 {
			t.Fatal("fixture lacks distinct client and server key updates")
		}
		encoded.Reset()
		if err := writer.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, group); err != nil {
			t.Fatal(err)
		}
		if err := writer.Flush(); err != nil {
			t.Fatal(err)
		}
		*blocks[i] = bytes.Clone(encoded.Bytes())
	}
	return packets, clientKeys, serverKeys
}
