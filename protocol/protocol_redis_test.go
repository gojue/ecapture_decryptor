// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/gojue/ecapture_decryptor/types"
)

func redisCommand(args ...string) []byte {
	var out bytes.Buffer
	fmt.Fprintf(&out, "*%d\r\n", len(args))
	for _, arg := range args {
		fmt.Fprintf(&out, "$%d\r\n%s\r\n", len(arg), arg)
	}
	return out.Bytes()
}
func redisPubsub(typ, name, channel string, count int) []byte {
	return []byte(fmt.Sprintf("%s3\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n:%d\r\n", typ, len(name), name, len(channel), channel, count))
}
func TestRedisPipelinedFragmentedReplies(t *testing.T) {
	ch := make(chan *types.DecryptedPacket, 16)
	p := NewRedisStreamParser(types.ConnectionKey{SrcPort: 40001}, ch)
	request := append(redisCommand("SET", "a", "one\x00two"), redisCommand("GET", "a")...)
	// Every header line, bulk string and CRLF crosses feed boundaries.
	for _, b := range request {
		p.FeedRequest([]byte{b})
	}
	reply := []byte("+OK\r\n$7\r\none\x00two\r\n")
	for _, b := range reply {
		p.FeedResponse([]byte{b})
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if len(ch) != 4 {
		t.Fatalf("packets %d", len(ch))
	}
	for _, want := range []struct {
		kind, command string
		id            uint64
		data          []byte
	}{
		{"request", "SET", 1, redisCommand("SET", "a", "one\x00two")},
		{"request", "GET", 2, redisCommand("GET", "a")},
		{"response", "SET", 1, []byte("+OK\r\n")},
		{"response", "GET", 2, []byte("$7\r\none\x00two\r\n")},
	} {
		got := <-ch
		if got.Protocol != "redis" || got.Metadata["kind"] != want.kind || got.Metadata["command"] != want.command || got.Metadata["request_id"] != want.id || !bytes.Equal(got.Data, want.data) {
			t.Fatalf("packet: %+v", got)
		}
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestRedisResponseBeforeFragmentedRequests(t *testing.T) {
	ch := make(chan *types.DecryptedPacket, 16)
	p := NewRedisStreamParser(types.ConnectionKey{}, ch)
	set, get := redisCommand("SET", "key", "x\x00y"), redisCommand("GET", "key")
	p.FeedRequest(set[:1])
	p.FeedResponse([]byte("+OK\r\n$3\r\nx\x00y\r\n"))
	if len(ch) != 0 {
		t.Fatal("response emitted before its fragmented request")
	}
	p.FeedRequest(append(set[1:], get[:2]...))
	if len(ch) != 2 || len(p.deferred) != 1 {
		t.Fatal("FIFO response drained without its request")
	}
	attribute, push := "|1\r\n+ttl\r\n:1\r\n", ">2\r\n+invalidate\r\n*0\r\n"
	p.FeedResponse([]byte(attribute + push))
	if len(ch) != 4 {
		t.Fatal("unrelated attribute/push waited for a request")
	}
	for _, b := range get[2:] {
		p.FeedRequest([]byte{b})
	}
	for _, want := range []struct {
		kind string
		id   any
		data string
	}{
		{"request", uint64(1), string(set)}, {"response", uint64(1), "+OK\r\n"},
		{"attribute", nil, attribute}, {"push", nil, push},
		{"request", uint64(2), string(get)}, {"response", uint64(2), "$3\r\nx\x00y\r\n"},
	} {
		got := <-ch
		if got.Metadata["kind"] != want.kind || got.Metadata["request_id"] != want.id || string(got.Data) != want.data || got.Metadata["unsolicited"] != nil {
			t.Fatalf("incorrect deferred value: %+v", got)
		}
	}
	if err := p.Close(); err != nil || p.deferredBytes != 0 || len(p.deferred) != 0 {
		t.Fatalf("deferred replies retained: %v", err)
	}
}
func TestRedisSubscriptionAcknowledgementsBeforeRequests(t *testing.T) {
	for _, typ := range []string{"*", ">"} {
		t.Run(typ, func(t *testing.T) {
			ch := make(chan *types.DecryptedPacket, 16)
			p := NewRedisStreamParser(types.ConnectionKey{}, ch)
			acks := append(redisPubsub(typ, "subscribe", "a", 1), redisPubsub(typ, "subscribe", "b", 2)...)
			p.FeedResponse(acks)
			if len(ch) != 0 {
				t.Fatal("subscription acknowledgement emitted before request")
			}
			request := redisCommand("SUBSCRIBE", "a", "b")
			for _, b := range request {
				p.FeedRequest([]byte{b})
			}
			p.FeedResponse(redisPubsub(typ, "unsubscribe", "a", 1))
			p.FeedResponse(redisPubsub(typ, "unsubscribe", "b", 0))
			p.FeedRequest(redisCommand("PING"))
			p.FeedResponse([]byte("+PONG\r\n"))
			if len(p.deferred) != 2 {
				t.Fatal("unrelated PING consumed unsubscribe acknowledgement")
			}
			p.FeedRequest(redisCommand("UNSUBSCRIBE"))
			for _, want := range []struct {
				kind string
				id   uint64
			}{
				{"request", 1}, {"push", 1}, {"push", 1}, {"request", 2},
				{"response", 2}, {"request", 3}, {"push", 3}, {"push", 3},
			} {
				got := <-ch
				if got.Metadata["kind"] != want.kind || got.Metadata["request_id"] != want.id {
					t.Fatal(got.Metadata)
				}
			}
			if err := p.Close(); err != nil || len(p.subscriptions) != 0 || p.deferredBytes != 0 {
				t.Fatalf("deferred subscription state retained: %v", err)
			}
		})
	}
}
func TestRedisRESP3TypesAttributesAndPush(t *testing.T) {
	ch := make(chan *types.DecryptedPacket, 64)
	p := NewRedisStreamParser(types.ConnectionKey{}, ch)
	p.FeedRequest(redisCommand("HELLO", "3"))
	p.FeedResponse([]byte("%2\r\n+server\r\n+redis\r\n+proto\r\n:3\r\n"))
	<-ch
	<-ch
	cases := []string{
		"_\r\n", "#t\r\n", "#f\r\n", ",1.5e-4\r\n", ",inf\r\n", ",-inf\r\n", ",nan\r\n",
		"(3492890328409238509324850943850943825024385\r\n", "!3\r\nERR\r\n", "=9\r\ntxt:hello\r\n",
		"~3\r\n:1\r\n:2\r\n:3\r\n", "%1\r\n+key\r\n*2\r\n:42\r\n$-1\r\n", "*-1\r\n", "*0\r\n",
		"*2\r\n|1\r\n+ttl\r\n:9\r\n$1\r\na\r\n*2\r\n+yes\r\n-no\r\n",
	}
	for i, want := range cases {
		p.FeedRequest(redisCommand("GET", fmt.Sprint(i)))
		attr := []byte("|1\r\n+ttl\r\n:12\r\n")
		push := []byte(">2\r\n+invalidate\r\n*1\r\n$1\r\na\r\n")
		data := append(append(attr, push...), []byte(want)...)
		for len(data) > 0 {
			n := min(3, len(data))
			p.FeedResponse(data[:n])
			data = data[n:]
		}
		request, attribute, pushed, response := <-ch, <-ch, <-ch, <-ch
		if attribute.Metadata["kind"] != "attribute" || attribute.Metadata["request_id"] != nil || !bytes.Equal(attribute.Data, attr) {
			t.Fatal(attribute.Metadata)
		}
		if pushed.Metadata["kind"] != "push" || pushed.Metadata["request_id"] != nil || !bytes.Equal(pushed.Data, push) {
			t.Fatal(pushed.Metadata)
		}
		if response.Metadata["kind"] != "response" || response.Metadata["request_id"] != request.Metadata["request_id"] || string(response.Data) != want {
			t.Fatalf("reply %d: %v %q", i, response.Metadata, response.Data)
		}
		if p.Err() != nil {
			t.Fatal(p.Err())
		}
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestRedisPubsubCorrelation(t *testing.T) {
	for _, resp3 := range []bool{false, true} {
		t.Run(fmt.Sprint(resp3), func(t *testing.T) {
			ch := make(chan *types.DecryptedPacket, 32)
			p := NewRedisStreamParser(types.ConnectionKey{}, ch)
			typ := "*"
			if resp3 {
				typ = ">"
			}
			p.FeedRequest(redisCommand("SUBSCRIBE", "alpha", "beta"))
			p.FeedRequest(redisCommand("PING"))
			p.FeedResponse(redisPubsub(typ, "subscribe", "alpha", 1))
			p.FeedResponse(redisPubsub(typ, "subscribe", "beta", 2))
			delivery := []byte(typ + "3\r\n$7\r\nmessage\r\n$5\r\nalpha\r\n$5\r\nhello\r\n")
			p.FeedResponse(delivery)
			if resp3 {
				p.FeedResponse([]byte("+PONG\r\n"))
			} else {
				// RESP2 subscribed PING is an array reply and consumes its own request.
				p.FeedResponse([]byte("*2\r\n$4\r\npong\r\n$0\r\n\r\n"))
			}
			first, second := <-ch, <-ch
			if first.Metadata["request_id"] != uint64(1) || second.Metadata["request_id"] != uint64(2) {
				t.Fatal("IDs")
			}
			for i := 0; i < 2; i++ {
				ack := <-ch
				if ack.Metadata["kind"] != "push" || ack.Metadata["request_id"] != uint64(1) {
					t.Fatal(ack.Metadata)
				}
			}
			pushed, pong := <-ch, <-ch
			if pushed.Metadata["kind"] != "push" || pushed.Metadata["request_id"] != nil || !bytes.Equal(pushed.Data, delivery) {
				t.Fatal(pushed.Metadata)
			}
			if pong.Metadata["kind"] != "response" || pong.Metadata["request_id"] != uint64(2) {
				t.Fatal(pong.Metadata)
			}
			p.FeedRequest(redisCommand("UNSUBSCRIBE"))
			p.FeedResponse(redisPubsub(typ, "unsubscribe", "alpha", 1))
			p.FeedResponse(redisPubsub(typ, "unsubscribe", "beta", 0))
			p.FeedRequest(redisCommand("GET", "normal"))
			// A normal array that happens to resemble a pub/sub message is a reply.
			normal := []byte("*3\r\n$7\r\nmessage\r\n$5\r\nalpha\r\n$5\r\nhello\r\n")
			p.FeedResponse(normal)
			<-ch
			for i := 0; i < 2; i++ {
				ack := <-ch
				if ack.Metadata["request_id"] != uint64(3) {
					t.Fatal(ack.Metadata)
				}
			}
			<-ch
			got := <-ch
			if got.Metadata["kind"] != "response" || got.Metadata["request_id"] != uint64(4) {
				t.Fatal(got.Metadata)
			}
			if len(p.subscriptions) != 0 || len(p.pending) != 0 {
				t.Fatal("retained subscription or request")
			}
			if err := p.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestRedisPatternShardAndUnsolicitedPush(t *testing.T) {
	for _, prefix := range []string{"p", "s"} {
		ch := make(chan *types.DecryptedPacket, 16)
		p := NewRedisStreamParser(types.ConnectionKey{}, ch)
		p.FeedRequest(redisCommand(strings.ToUpper(prefix)+"SUBSCRIBE", "a"))
		p.FeedResponse(redisPubsub(">", prefix+"subscribe", "a", 1))
		p.FeedRequest(redisCommand(strings.ToUpper(prefix) + "UNSUBSCRIBE"))
		p.FeedResponse(redisPubsub(">", prefix+"unsubscribe", "a", 0))
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		if len(ch) != 4 {
			t.Fatal("missing ack")
		}
	}
	ch := make(chan *types.DecryptedPacket, 1)
	p := NewRedisStreamParser(types.ConnectionKey{}, ch)
	p.FeedResponse([]byte("-DENIED protected mode\r\n"))
	if len(ch) != 0 {
		t.Fatal("unmatched response emitted before EOF")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if packet := <-ch; packet.Metadata["unsolicited"] != true || string(packet.Data) != "-DENIED protected mode\r\n" {
		t.Fatal("EOF lost unsolicited response")
	}
}
func TestRedisRejectsMalformedAndUnsupported(t *testing.T) {
	for name, data := range map[string]string{
		"inline": "PING\r\n", "bad bulk": "$-2\r\n", "bad length": "$+1\r\na\r\n", "overflow": "$18446744073709551616\r\n",
		"bad integer": ":9223372036854775808\r\n", "bad bool": "#yes\r\n", "bad null": "_extra\r\n", "bad double": ",.5\r\n",
		"hex float": ",0x1p0\r\n", "bad big integer": "(1e4\r\n", "bad verbatim": "=4\r\ntxt!\r\n", "bad bulk terminator": "$1\r\na!\n",
		"bad array": "*-2\r\n", "negative map": "%-1\r\n", "empty push": ">0\r\n", "nested push": "*1\r\n>1\r\n+x\r\n",
		"streamed bulk": "$?\r\n", "streamed aggregate": "*?\r\n", "bare LF": "+hello\nworld\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			ch := make(chan *types.DecryptedPacket, 8)
			p := NewRedisStreamParser(types.ConnectionKey{}, ch)
			p.FeedResponse([]byte(data))
			if p.Err() == nil || len(ch) != 0 {
				t.Fatalf("accepted %q: %v", data, p.Err())
			}
		})
	}
	for _, command := range [][]string{{"MONITOR"}, {"SYNC"}, {"PSYNC", "?", "-1"}, {"CLIENT", "REPLY", "OFF"}} {
		p := NewRedisStreamParser(types.ConnectionKey{}, nil)
		p.FeedRequest(redisCommand(command...))
		if p.Err() == nil {
			t.Fatal("unsupported mode accepted")
		}
	}
	for _, data := range []string{"*1\r\n:3\r\n", "*0\r\n", "+GET\r\n", "*1\r\n$-1\r\n"} {
		p := NewRedisStreamParser(types.ConnectionKey{}, nil)
		p.FeedRequest([]byte(data))
		if p.Err() == nil {
			t.Fatal("invalid command accepted")
		}
	}
}
func TestRedisBoundsAndTruncation(t *testing.T) {
	for name, data := range map[string]string{
		"bulk":      fmt.Sprintf("$%d\r\n", maxRedisValueBytes+1),
		"elements":  fmt.Sprintf("*%d\r\n", maxRedisElements+1),
		"map pairs": fmt.Sprintf("%%%d\r\n", maxRedisElements),
		"depth":     strings.Repeat("*1\r\n", maxRedisDepth+1),
		"line":      "+" + strings.Repeat("x", maxRedisLineBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			p := NewRedisStreamParser(types.ConnectionKey{}, nil)
			p.FeedResponse([]byte(data))
			if !errors.Is(p.Err(), ErrHTTPEventLimit) {
				t.Fatalf("bound %s: %v", name, p.Err())
			}
			if len(p.directions[1].data) != 0 {
				t.Fatal("retained failed buffer")
			}
		})
	}
	for _, data := range []string{"$5\r\nabc", "*2\r\n:1\r\n", "+unfinished", "$0\r\n\r"} {
		p := NewRedisStreamParser(types.ConnectionKey{}, nil)
		p.FeedResponse([]byte(data))
		if err := p.Close(); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("truncated %q: %v", data, err)
		}
		if err := p.Close(); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatal("repeat close changed error")
		}
	}
	p := NewRedisStreamParser(types.ConnectionKey{}, nil)
	for i := 0; i < maxRedisPending+1; i++ {
		p.FeedRequest(redisCommand("PING"))
	}
	if !errors.Is(p.Err(), ErrHTTPEventLimit) || len(p.pending) != 0 {
		t.Fatal("pending requests unbounded")
	}
	for _, bytesBound := range []bool{false, true} {
		p := NewRedisStreamParser(types.ConnectionKey{}, nil)
		value := []byte("+OK\r\n")
		if bytesBound {
			value = []byte("$1048576\r\n" + strings.Repeat("x", 1<<20) + "\r\n")
		}
		for i := 0; i < maxRedisPending+1 && p.Err() == nil; i++ {
			p.FeedResponse(value)
		}
		if !errors.Is(p.Err(), ErrHTTPEventLimit) || len(p.deferred) != 0 || p.deferredBytes != 0 {
			t.Fatal("server-first responses unbounded or retained after failure")
		}
	}
}
func TestRedisLongConnectionAndBackpressure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ch := make(chan *types.DecryptedPacket)
		p := NewRedisStreamParser(types.ConnectionKey{}, ch)
		done := make(chan struct{})
		go func() {
			for i := 0; i < 2000; i++ {
				p.FeedRequest(redisCommand("GET", "key"))
				p.FeedResponse([]byte("$5\r\nvalue\r\n"))
			}
			close(done)
		}()
		for i := 0; i < 4000; i++ {
			synctest.Wait()
			select {
			case <-done:
				t.Fatal("send bypassed backpressure")
			default:
			}
			got := <-ch
			if got.Metadata["request_id"] != uint64(i/2+1) {
				t.Fatal(got.Metadata)
			}
		}
		<-done
		if len(p.pending) != 0 || len(p.directions[0].data)+len(p.directions[1].data) != 0 {
			t.Fatal("retained completed messages")
		}
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
	})
}
func TestRedisConnectionIsolation(t *testing.T) {
	ch := make(chan *types.DecryptedPacket, 8)
	a := NewRedisStreamParser(types.ConnectionKey{SrcPort: 1}, ch)
	b := NewRedisStreamParser(types.ConnectionKey{SrcPort: 2}, ch)
	a.FeedRequest(redisCommand("GET", "a"))
	b.FeedRequest(redisCommand("SET", "b", "2"))
	b.FeedResponse([]byte("+OK\r\n"))
	a.FeedResponse([]byte("$1\r\n1\r\n"))
	<-ch
	<-ch
	rb, ra := <-ch, <-ch
	if rb.Metadata["command"] != "SET" || ra.Metadata["command"] != "GET" || ra.ConnectionID() == rb.ConnectionID() || ra.Metadata["request_id"] != uint64(1) || rb.Metadata["request_id"] != uint64(1) {
		t.Fatal("connection correlation mixed")
	}
}
func FuzzRedisFragments(f *testing.F) {
	f.Add([]byte("*2\r\n$3\r\nGET\r\n$1\r\na\r\n"), true)
	f.Add([]byte("%1\r\n+key\r\n*1\r\n_\r\n"), false)
	f.Add([]byte("$18446744073709551616\r\n"), false)
	f.Fuzz(func(t *testing.T, data []byte, client bool) {
		if len(data) > 65536 {
			return
		}
		p := NewRedisStreamParser(types.ConnectionKey{}, nil)
		for len(data) > 0 {
			n := min(7, len(data))
			if client {
				p.FeedRequest(data[:n])
			} else {
				p.FeedResponse(data[:n])
			}
			data = data[n:]
		}
		_ = p.Close()
		if len(p.pending) != 0 || len(p.deferred) != 0 || p.deferredBytes != 0 || len(p.subscriptions) != 0 || len(p.directions[0].data)+len(p.directions[1].data) != 0 {
			t.Fatal("closed parser retained state")
		}
	})
}

func TestRedisLargeBulkAndIndependentSubscriptionGroups(t *testing.T) {
	ch := make(chan *types.DecryptedPacket, 16)
	p := NewRedisStreamParser(types.ConnectionKey{}, ch)
	payload := bytes.Repeat([]byte{0, 13, 10, 255}, (1<<20)/4)
	raw := append([]byte(fmt.Sprintf("$%d\r\n", len(payload))), payload...)
	raw = append(raw, '\r', '\n')
	for i := 0; i < 17; i++ {
		p.FeedRequest(redisCommand("GET", "large"))
		<-ch
		for data := raw; len(data) > 0; {
			n := min(4093, len(data))
			p.FeedResponse(data[:n])
			data = data[n:]
		}
		if p.Err() != nil {
			t.Fatal(p.Err())
		}
		if packet := <-ch; !bytes.Equal(packet.Data, raw) {
			t.Fatal("large binary bulk changed")
		}
	}
	p.FeedRequest(redisCommand("SUBSCRIBE", "normal"))
	p.FeedResponse(redisPubsub("*", "subscribe", "normal", 1))
	p.FeedRequest(redisCommand("SSUBSCRIBE", "shard"))
	p.FeedResponse(redisPubsub("*", "ssubscribe", "shard", 1))
	p.FeedRequest(redisCommand("SUNSUBSCRIBE"))
	p.FeedResponse(redisPubsub("*", "sunsubscribe", "shard", 0))
	for len(ch) > 0 {
		<-ch
	}
	p.FeedResponse([]byte("*3\r\n$7\r\nmessage\r\n$6\r\nnormal\r\n$1\r\nx\r\n"))
	if got := <-ch; got.Metadata["kind"] != "push" {
		t.Fatal("sharded unsubscribe cleared normal subscription")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}
