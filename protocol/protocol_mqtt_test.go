// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gojue/ecapture_decryptor/types"
)

func mqttWire(first byte, payload []byte) []byte {
	out := []byte{first}
	n := len(payload)
	for {
		b := byte(n % 128)
		n /= 128
		if n != 0 {
			b |= 128
		}
		out = append(out, b)
		if n == 0 {
			break
		}
	}
	return append(out, payload...)
}
func mqttField(value []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(value))), value...)
}
func mqttConnect() []byte {
	return mqttWire(0x10, []byte{0, 4, 'M', 'Q', 'T', 'T', 4, 2, 0, 30, 0, 4, 't', 'e', 's', 't'})
}
func mqttReady(t *testing.T) (*MQTTStreamParser, chan *types.DecryptedPacket) {
	t.Helper()
	ch := make(chan *types.DecryptedPacket, 64)
	p := NewMQTTStreamParser(types.ConnectionKey{SrcIP: net.IPv4(127, 0, 0, 1), DstIP: net.IPv4(127, 0, 0, 1), SrcPort: 44000, DstPort: 443, Proto: "tcp"}, ch)
	p.FeedRequest(mqttConnect())
	p.FeedResponse([]byte{0x20, 2, 0, 0})
	if p.Err() != nil {
		t.Fatal(p.Err())
	}
	<-ch
	<-ch
	return p, ch
}
func TestMQTTFragmentedConnectAndServerFirst(t *testing.T) {
	ch := make(chan *types.DecryptedPacket, 4)
	p := NewMQTTStreamParser(types.ConnectionKey{}, ch)
	at := time.Unix(100, 0)
	p.SetPacketTime(at)
	p.FeedResponse([]byte{0x20, 2, 0, 0})
	if len(ch) != 0 {
		t.Fatal("server data emitted before the version was established")
	}
	for _, b := range mqttConnect() {
		p.FeedRequest([]byte{b})
	}
	if p.Err() != nil || len(ch) != 2 {
		t.Fatalf("CONNECT: %v, outputs %d", p.Err(), len(ch))
	}
	request := <-ch
	response := <-ch
	if request.Metadata["client_id"] != "test" || request.Metadata["keep_alive"] != uint16(30) || request.Protocol != "mqtt" || request.Timestamp != at || !bytes.Equal(request.Data, mqttConnect()) {
		t.Fatal(request)
	}
	if response.Metadata["packet_name"] != "CONNACK" || response.Direction != "response" || response.Metadata["return_code"] != byte(0) {
		t.Fatal(response)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestMQTTPublishQoSDuplicateAndServerPush(t *testing.T) {
	p, ch := mqttReady(t)
	for _, client := range []bool{true, false} {
		feed := p.FeedResponse
		if client {
			feed = p.FeedRequest
		}
		for qos := byte(0); qos <= 2; qos++ {
			payload := mqttField([]byte("sensors/temperature"))
			if qos != 0 {
				payload = binary.BigEndian.AppendUint16(payload, 7)
			}
			payload = append(payload, 0, 255, qos)
			first := byte(0x31) | qos<<1
			wire := mqttWire(first, payload)
			for _, b := range wire {
				feed([]byte{b})
			}
			out := <-ch
			if !bytes.Equal(out.Data, wire) || out.Metadata["qos"] != qos || out.Metadata["topic"] != "sensors/temperature" || out.Metadata["retain"] != true || out.Metadata["dup"] != false || out.Metadata["payload_length"] != 3 {
				t.Fatal(out.Metadata)
			}
			offset := out.Metadata["payload_offset"].(int)
			if !bytes.Equal(out.Data[offset:], []byte{0, 255, qos}) {
				t.Fatal("payload location did not match wire bytes")
			}
			if qos != 0 {
				if out.Metadata["packet_id"] != uint16(7) {
					t.Fatal(out.Metadata)
				}
				duplicate := mqttWire(first|8, payload)
				feed(duplicate)
				got := <-ch
				if got.Metadata["dup"] != true || !bytes.Equal(got.Data, duplicate) {
					t.Fatal("DUP packet was discarded or rewritten")
				}
			}
		}
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestMQTTSubscribeAcknowledgementsAndCoalescing(t *testing.T) {
	p, ch := mqttReady(t)
	payload := []byte{0, 9}
	payload = append(payload, mqttField([]byte("a/+"))...)
	payload = append(payload, 1)
	payload = append(payload, mqttField([]byte("b/#"))...)
	payload = append(payload, 2)
	client := mqttWire(0x82, payload)
	for _, first := range []byte{0x40, 0x50, 0x62, 0x70} {
		client = append(client, first, 2, 0, 7)
	}
	unsub := append([]byte{0, 10}, mqttField([]byte("a/+"))...)
	client = append(client, mqttWire(0xa2, unsub)...)
	client = append(client, 0xc0, 0)
	p.FeedRequest(client)
	server := []byte{0x90, 4, 0, 9, 1, 128, 0xb0, 2, 0, 10, 0xd0, 0}
	p.FeedResponse(server)
	if p.Err() != nil || len(ch) != 10 {
		t.Fatalf("packets=%d err=%v", len(ch), p.Err())
	}
	sub := <-ch
	if sub.Metadata["kind"] != "subscribe" || sub.Metadata["packet_id"] != uint16(9) || len(sub.Metadata["topics"].([]string)) != 2 || !slices.Equal(sub.Metadata["requested_qos"].([]int), []int{1, 2}) {
		t.Fatal(sub.Metadata)
	}
	for i := 0; i < 4; i++ {
		if ack := <-ch; ack.Metadata["packet_id"] != uint16(7) {
			t.Fatal(ack.Metadata)
		}
	}
	if unsub := <-ch; unsub.Metadata["kind"] != "unsubscribe" {
		t.Fatal(unsub.Metadata)
	}
	<-ch // PINGREQ
	if ack := <-ch; !slices.Equal(ack.Metadata["return_codes"].([]int), []int{1, 128}) {
		t.Fatal(ack.Metadata)
	}
	<-ch // UNSUBACK
	<-ch // PINGRESP
	p.FeedRequest([]byte{0xe0, 0})
	if packet := <-ch; packet.Metadata["packet_name"] != "DISCONNECT" {
		t.Fatal(packet.Metadata)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestMQTTConnectFlagsAndOpaquePassword(t *testing.T) {
	p := NewMQTTStreamParser(types.ConnectionKey{}, nil)
	payload := []byte{0, 4, 'M', 'Q', 'T', 'T', 4, 0xce, 0, 1} // user/password, QoS1 will, clean session
	for _, field := range [][]byte{[]byte("client"), []byte("will/topic"), {0, 255}, []byte("user"), {255, 0, 1}} {
		payload = append(payload, mqttField(field)...)
	}
	p.FeedRequest(mqttWire(0x10, payload))
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	for _, level := range []byte{3, 5} {
		p := NewMQTTStreamParser(types.ConnectionKey{}, nil)
		wire := mqttConnect()
		wire[8] = level
		p.FeedRequest(wire)
		if !errors.Is(p.Err(), errMQTTVersion) {
			t.Fatalf("accepted MQTT level %d", level)
		}
	}
}
func TestMQTTMalformedAndTruncated(t *testing.T) {
	cases := map[string][]byte{
		"reserved type":        {0xf0, 0},
		"bad fixed flags":      {0x81, 2, 0, 1},
		"qos three":            {0x36, 0},
		"qos zero dup":         {0x38, 0},
		"five length bytes":    {0x30, 0x80, 0x80, 0x80, 0x80, 0},
		"nonminimal length":    {0x30, 0x80, 0},
		"empty publish topic":  {0x30, 2, 0, 0},
		"topic wildcard":       {0x30, 3, 0, 1, '#'},
		"topic UTF8":           {0x30, 3, 0, 1, 255},
		"topic zero":           {0x30, 3, 0, 1, 0},
		"zero packet id":       {0x40, 2, 0, 0},
		"ack trailing byte":    {0x40, 3, 0, 1, 0},
		"ping payload":         {0xc0, 1, 0},
		"wrong direction":      {0xd0, 0},
		"empty subscribe":      {0x82, 2, 0, 1},
		"invalid filter":       {0x82, 7, 0, 1, 0, 2, '#', '/', 0},
		"invalid subscription": {0x82, 6, 0, 1, 0, 1, 'a', 3},
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			p, ch := mqttReady(t)
			p.FeedRequest(wire)
			if p.Err() == nil || len(ch) != 0 {
				t.Fatalf("accepted malformed packet: %v", p.Err())
			}
			for _, d := range p.directions {
				if d.buf.Len() != 0 {
					t.Fatal("error retained packet bytes")
				}
			}
		})
	}
	for _, data := range [][]byte{{0x30}, {0x30, 0x80}, {0x30, 5, 0, 1, 'a'}} {
		p, ch := mqttReady(t)
		p.FeedRequest(data)
		if err := p.Close(); !errors.Is(err, io.ErrUnexpectedEOF) || len(ch) != 0 {
			t.Fatalf("truncation: %v", err)
		}
		if err := p.Close(); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatal(err)
		}
	}
	for _, wire := range [][]byte{{0x20, 2, 2, 0}, {0x20, 2, 1, 1}, {0x20, 2, 0, 6}, {0x20, 2, 1, 0}} {
		p := NewMQTTStreamParser(types.ConnectionKey{}, nil)
		p.FeedRequest(mqttConnect())
		p.FeedResponse(wire)
		if p.Err() == nil {
			t.Fatal("invalid CONNACK accepted")
		}
	}
}
func TestMQTTLimitsAndLongConnection(t *testing.T) {
	p, ch := mqttReady(t)
	// A four-byte length declares >16 MiB without providing a large allocation.
	p.FeedRequest([]byte{0x30, 0xff, 0xff, 0xff, 0x7f})
	if !errors.Is(p.Err(), ErrHTTPEventLimit) || len(ch) != 0 {
		t.Fatal(p.Err())
	}
	p, _ = mqttReady(t)
	topics := []byte{0, 1}
	for i := 0; i <= maxMQTTTopics; i++ {
		topics = append(topics, 0, 1, 'a', 0)
	}
	p.FeedRequest(mqttWire(0x82, topics))
	if !errors.Is(p.Err(), ErrHTTPEventLimit) {
		t.Fatal("topic count was unbounded")
	}
	p, ch = mqttReady(t)
	data := append(mqttField([]byte("long")), bytes.Repeat([]byte{'x'}, 64<<10)...)
	wire := mqttWire(0x30, data)
	for i := 0; i < 257; i++ {
		p.FeedRequest(wire)
		out := <-ch
		if !bytes.Equal(out.Data, wire) || out.Metadata["message_index"] != uint64(i+1) {
			t.Fatal("long connection changed packet boundaries")
		}
		if p.directions[0].buf.Len() != 0 {
			t.Fatal("completed packet retained")
		}
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestMQTTBackpressureAndConnectionIsolation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ch := make(chan *types.DecryptedPacket)
		p := NewMQTTStreamParser(types.ConnectionKey{SrcPort: 1}, ch)
		other := NewMQTTStreamParser(types.ConnectionKey{SrcPort: 2}, nil)
		done := make(chan struct{})
		go func() {
			p.FeedRequest(append(mqttConnect(), 0xc0, 0))
			close(done)
		}()
		other.FeedRequest(mqttConnect()[:3])
		for i := 0; i < 2; i++ {
			synctest.Wait()
			select {
			case <-done:
				t.Fatal("producer bypassed slow consumer")
			default:
			}
			out := <-ch
			if out.Metadata["message_index"] != uint64(i) || out.SrcPort != 1 {
				t.Fatal(out.Metadata)
			}
		}
		<-done
		if !errors.Is(other.Close(), io.ErrUnexpectedEOF) || p.Close() != nil {
			t.Fatal("connections shared framing state")
		}
	})
}
func FuzzMQTTPacketFragments(f *testing.F) {
	f.Add([]byte{0x30, 4, 0, 1, 'a', 0})
	f.Add([]byte{0x30, 0x80, 0x80, 0x80, 0x80, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			return
		}
		p := NewMQTTStreamParser(types.ConnectionKey{}, nil)
		p.FeedRequest(mqttConnect())
		for len(data) > 0 {
			n := min(len(data), 3)
			p.FeedRequest(data[:n])
			data = data[n:]
		}
		_ = p.Close()
		if p.directions[0].buf.Len()+p.directions[1].buf.Len() != 0 {
			t.Fatal("terminal parser retained bytes")
		}
	})
}

func TestMQTTMaximumPacketFollowedByAnotherPacket(t *testing.T) {
	p, ch := mqttReady(t)
	payload := make([]byte, maxMQTTPacketBytes-5)
	copy(payload, []byte{0, 1, 'a'})
	wire := mqttWire(0x30, payload)
	if len(wire) != maxMQTTPacketBytes {
		t.Fatal("bad boundary fixture")
	}
	// The last input chunk ends the large packet and starts a separate packet.
	p.FeedRequest(append(wire, 0xc0, 0))
	if p.Err() != nil || len(ch) != 2 {
		t.Fatalf("coalesced maximum packet: %v, packets %d", p.Err(), len(ch))
	}
	if out := <-ch; !bytes.Equal(out.Data, wire) {
		t.Fatal("maximum packet changed")
	}
	if out := <-ch; out.Metadata["packet_name"] != "PINGREQ" {
		t.Fatal(out.Metadata)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMQTTRefusedConnectionRejectsFurtherServerPackets(t *testing.T) {
	ch := make(chan *types.DecryptedPacket, 4)
	p := NewMQTTStreamParser(types.ConnectionKey{}, ch)
	p.FeedRequest(mqttConnect())
	p.FeedResponse([]byte{0x20, 2, 0, 5})
	if p.Err() != nil || len(ch) != 2 {
		t.Fatal("valid refusal rejected")
	}
	<-ch
	refusal := <-ch
	if refusal.Metadata["return_code"] != byte(5) {
		t.Fatal(refusal.Metadata)
	}
	// Client data sent before receiving the refusal can be observed later.
	p.FeedRequest([]byte{0xc0, 0})
	if p.Err() != nil {
		t.Fatal("rejected in-flight client data")
	}
	<-ch
	p.FeedResponse(mqttWire(0x30, append(mqttField([]byte("a")), 'x')))
	if !errors.Is(p.Err(), errMQTT) || len(ch) != 0 {
		t.Fatal("server published after refusing connection")
	}
}
