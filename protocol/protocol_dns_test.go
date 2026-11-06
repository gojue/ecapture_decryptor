// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gojue/ecapture_decryptor/types"
	"golang.org/x/net/dns/dnsmessage"
)

func dnsTestWire(t *testing.T, id uint16, name string, response bool) []byte {
	t.Helper()
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: id, Response: response, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	if response {
		m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}}}
	}
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
func dnsTestFrame(wire []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(wire))), wire...)
}

func TestDNSWireValidationAndQuestionIdentity(t *testing.T) {
	// Fixed wire vector includes a compressed answer owner name.
	wire, err := hex.DecodeString("12348180000100010000000003777777076578616d706c6503636f6d0000010001c00c000100010000003c0004c0000201")
	if err != nil {
		t.Fatal(err)
	}
	meta, err := decodeDNSMessage(wire)
	if err != nil {
		t.Fatal(err)
	}
	if meta["id"] != uint16(0x1234) || meta["qr"] != true || meta["rcode"] != uint16(0) {
		t.Fatal(meta)
	}
	qs := meta["questions"].([]map[string]any)
	answers := meta["answers"].([]map[string]any)
	if qs[0]["name"] != "www.example.com." || answers[0]["address"] != "192.0.2.1" {
		t.Fatal(meta)
	}
	query := dnsTestWire(t, 0x1234, "WWW.Example.COM.", false)
	if !dnsQuestionsMatch(query, wire) {
		t.Fatal("case-insensitive name did not match")
	}
	if dnsQuestionsMatch(dnsTestWire(t, 7, "www.example.com.", false), wire) || dnsQuestionsMatch(dnsTestWire(t, 0x1234, "other.example.com.", false), wire) {
		t.Fatal("unrelated response matched")
	}
	// Counted labels distinguish an embedded dot from a label boundary.
	q := append([]byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}, 3, 'a', '.', 'b', 0, 0, 1, 0, 1)
	r := dnsTestWire(t, 1, "a.b.", true)
	if dnsQuestionsMatch(q, r) {
		t.Fatal("ambiguous dotted text caused false association")
	}
	for name, bad := range map[string][]byte{
		"short": wire[:11], "trailing": append(bytes.Clone(wire), 0),
		"pointer loop":    {0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1},
		"forward pointer": {0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 14, 0, 0, 1, 0, 1},
		"reserved label":  {0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x40, 0, 0, 1, 0, 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeDNSMessage(bad); err == nil {
				t.Fatal("malformed DNS accepted")
			}
		})
	}
	bad := bytes.Clone(wire)
	bad[len(bad)-6] = 0
	bad[len(bad)-5] = 3
	if _, err := decodeDNSMessage(bad); err == nil {
		t.Fatal("invalid A RDLENGTH accepted")
	}
	bad = []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for i := 0; i < 4; i++ {
		bad = append(bad, 63)
		bad = append(bad, bytes.Repeat([]byte{'a'}, 63)...)
	}
	bad = append(bad, 0, 0, 1, 0, 1)
	if _, err := decodeDNSMessage(bad); err == nil {
		t.Fatal("overlong DNS name accepted")
	}
	bad = make([]byte, 12)
	binary.BigEndian.PutUint16(bad[4:6], maxDNSQuestions+1)
	if _, err := decodeDNSMessage(bad); !errors.Is(err, ErrHTTPEventLimit) {
		t.Fatal(err)
	}
	if _, err := decodeDNSMessage(make([]byte, maxDNSMessage+1)); !errors.Is(err, ErrHTTPEventLimit) {
		t.Fatal(err)
	}
}

func TestDoTPipeliningFragmentsAndIsolation(t *testing.T) {
	ch := make(chan *types.DecryptedPacket, 16)
	ci := types.ConnectionKey{Proto: "tcp", SrcIP: net.IPv4(127, 0, 0, 1), DstIP: net.IPv4(127, 0, 0, 1), SrcPort: 40001, DstPort: 853}
	p := NewDNSStreamParser(ci, ch)
	first := time.Unix(10, 0)
	p.SetPacketTime(first)
	q1 := dnsTestWire(t, 7, "one.example.", false)
	q2 := dnsTestWire(t, 7, "two.example.", false)
	request := append(dnsTestFrame(q1), dnsTestFrame(q2)...)
	for _, b := range request {
		p.FeedRequest([]byte{b})
		p.SetPacketTime(first.Add(time.Second))
	}
	// Same ID, but questions select the correct out-of-order outstanding query.
	p.FeedResponse(append(dnsTestFrame(dnsTestWire(t, 7, "two.example.", true)), dnsTestFrame(dnsTestWire(t, 7, "one.example.", true))...))
	if p.Err() != nil || len(ch) != 4 || p.pendingCount != 0 {
		t.Fatalf("err=%v outputs=%d pending=%d", p.Err(), len(ch), p.pendingCount)
	}
	qPacket := <-ch
	if !qPacket.Timestamp.Equal(first) || !bytes.Equal(qPacket.Data, q1) || qPacket.Metadata["request_id"] != uint64(1) {
		t.Fatal(qPacket)
	}
	<-ch
	if r := <-ch; r.Metadata["request_id"] != uint64(2) || r.Metadata["matched"] != true {
		t.Fatal(r.Metadata)
	}
	if r := <-ch; r.Metadata["request_id"] != uint64(1) || r.Metadata["matched"] != true {
		t.Fatal(r.Metadata)
	}
	otherCI := ci
	otherCI.SrcPort++
	other := NewDNSStreamParser(otherCI, ch)
	p.FeedRequest(dnsTestFrame(q1))
	other.FeedRequest(dnsTestFrame(q2))
	<-ch
	<-ch
	other.FeedResponse(dnsTestFrame(dnsTestWire(t, 7, "one.example.", true)))
	if r := <-ch; r.Metadata["matched"] != false || r.ConnectionID() != otherCI.String() {
		t.Fatal(r.Metadata)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if p.pendingCount != 0 || p.questionBytes != 0 {
		t.Fatal("pending queries retained at EOF")
	}
}

func TestDoTAmbiguousErrorsTruncationAndBounds(t *testing.T) {
	ch := make(chan *types.DecryptedPacket, 8)
	p := NewDNSStreamParser(types.ConnectionKey{}, ch)
	p.FeedRequest(dnsTestFrame(dnsTestWire(t, 9, "one.example.", false)))
	p.FeedRequest(dnsTestFrame(dnsTestWire(t, 9, "two.example.", false)))
	<-ch
	<-ch
	errorReply := []byte{0, 9, 0x80, 2, 0, 0, 0, 0, 0, 0, 0, 0}
	p.FeedResponse(dnsTestFrame(errorReply))
	if r := <-ch; r.Metadata["matched"] != false {
		t.Fatal("ambiguous error matched")
	}
	p.FeedResponse(dnsTestFrame(dnsTestWire(t, 9, "one.example.", true)))
	<-ch
	p.FeedResponse(dnsTestFrame(errorReply))
	if r := <-ch; r.Metadata["matched"] != true || r.Metadata["request_id"] != uint64(2) {
		t.Fatal("unique error did not match", r.Metadata)
	}
	for _, wire := range [][]byte{{0}, {0, 20, 0, 0}, {0, 0}, {0, 11}} {
		p = NewDNSStreamParser(types.ConnectionKey{}, nil)
		p.FeedRequest(wire)
		if err := p.Close(); err == nil {
			t.Fatal("truncated/short length accepted")
		}
	}
	p = NewDNSStreamParser(types.ConnectionKey{}, nil)
	q := dnsTestFrame(dnsTestWire(t, 0, "pending.example.", false))
	for i := 0; i <= maxDNSPending; i++ {
		p.FeedRequest(q)
	}
	if !errors.Is(p.Err(), ErrHTTPEventLimit) || p.pendingCount != 0 || p.questionBytes != 0 {
		t.Fatal("pending cap did not release", p.Err())
	}
	p = NewDNSStreamParser(types.ConnectionKey{}, nil)
	p.FeedRequest(dnsTestFrame(dnsTestWire(t, 0, "response.example.", true)))
	if p.Err() == nil {
		t.Fatal("query direction accepted QR=1")
	}
}

func TestDoQConcurrentStreamsResponseFirstAndFIN(t *testing.T) {
	ch := make(chan *types.DecryptedPacket, 16)
	p := NewDoQStreamParser(types.ConnectionKey{Proto: "udp"}, ch)
	at := time.Unix(50, 0)
	for _, id := range []uint64{4, 0} {
		name := "zero.example."
		if id == 4 {
			name = "four.example."
		}
		r := dnsTestFrame(dnsTestWire(t, 0, name, true))
		q := dnsTestFrame(dnsTestWire(t, 0, name, false))
		if err := p.FeedQUICStream(id, false, r, true, at); err != nil {
			t.Fatal(err)
		}
		if len(ch) != 0 || p.streams[id].sides[1].decoded.meta != nil {
			t.Fatal("response emitted or expanded metadata retained before query association")
		}
		for _, b := range q {
			if err := p.FeedQUICStream(id, true, []byte{b}, false, at); err != nil {
				t.Fatal(err)
			}
		}
		if len(ch) != 0 {
			t.Fatal("query emitted before FIN")
		}
		if err := p.FeedQUICStream(id, true, nil, true, at); err != nil {
			t.Fatal(err)
		}
		for _, direction := range []string{"request", "response"} {
			packet := <-ch
			if packet.Direction != direction || packet.Metadata["stream_id"] != id || packet.Metadata["id"] != uint16(0) || packet.Metadata["stream_end"] != true {
				t.Fatal(packet.Metadata)
			}
		}
		if err := p.FeedQUICStream(id, true, nil, true, at); err != nil {
			t.Fatal(err)
		}
	}
	if p.buffered != 0 || p.questionBytes != 0 || len(ch) != 0 {
		t.Fatal("completed transaction retained or repeated")
	}
	if err := p.CloseQUICStreams(); err != nil {
		t.Fatal(err)
	}
	if err := p.CloseQUICStreams(); err != nil {
		t.Fatal(err)
	}
}

func TestDoQRejectsInvalidStreamsAndMessages(t *testing.T) {
	query := dnsTestFrame(dnsTestWire(t, 0, "query.example.", false))
	cases := []struct {
		name   string
		id     uint64
		client bool
		wire   []byte
		fin    bool
	}{
		{"server initiated", 1, true, query, true}, {"unidirectional", 2, true, query, true}, {"stream overflow", 1 << 62, true, query, true},
		{"nonzero DNS ID", 0, true, dnsTestFrame(dnsTestWire(t, 1, "query.example.", false)), true},
		{"second query", 0, true, append(bytes.Clone(query), query...), true},
		{"empty FIN", 0, true, nil, true}, {"partial prefix", 0, true, query[:1], true}, {"partial message", 0, true, query[:len(query)-1], true},
		{"wrong QR", 0, false, query, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewDoQStreamParser(types.ConnectionKey{}, nil)
			if err := p.FeedQUICStream(tc.id, tc.client, tc.wire, tc.fin, time.Time{}); err == nil {
				t.Fatal("invalid DoQ accepted")
			}
			if p.buffered != 0 || p.questionBytes != 0 {
				t.Fatal("error retained buffers")
			}
		})
	}
	p := NewDoQStreamParser(types.ConnectionKey{}, nil)
	if err := p.FeedQUICStream(0, true, query, false, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := p.CloseQUICStreams(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("missing FIN accepted", err)
	}
	p = NewDoQStreamParser(types.ConnectionKey{}, nil)
	if err := p.FeedQUICStream(0, true, query, true, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := p.FeedQUICStream(0, false, dnsTestFrame(dnsTestWire(t, 0, "wrong.example.", true)), true, time.Time{}); err == nil {
		t.Fatal("wrong question on same stream accepted")
	}
	m := dnsmessage.Message{Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("zone.example."), Type: 252, Class: dnsmessage.ClassINET}}}
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	p = NewDoQStreamParser(types.ConnectionKey{}, nil)
	if err := p.FeedQUICStream(0, true, dnsTestFrame(wire), true, time.Time{}); err == nil {
		t.Fatal("unsupported zone transfer accepted")
	}
	m.Questions[0].Type = dnsmessage.TypeA
	m.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 1232}, Body: &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 11}}}}}
	wire, err = m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	p = NewDoQStreamParser(types.ConnectionKey{}, nil)
	if err := p.FeedQUICStream(0, true, dnsTestFrame(wire), true, time.Time{}); err == nil {
		t.Fatal("EDNS TCP keepalive accepted")
	}
}

func TestDoQResetTombstonesAndConnectionBudget(t *testing.T) {
	ch := make(chan *types.DecryptedPacket, 2)
	p := NewDoQStreamParser(types.ConnectionKey{}, ch)
	query := dnsTestFrame(dnsTestWire(t, 0, "query.example.", false))
	if err := p.FeedQUICStream(4, true, query[:5], false, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := p.ResetQUICStream(4, true, 3); err != nil {
		t.Fatal(err)
	}
	if err := p.FeedQUICStream(4, true, query, true, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := p.ResetQUICStream(4, true, 3); err != nil {
		t.Fatal(err)
	}
	if p.buffered != 0 || p.questionBytes != 0 || len(ch) != 1 {
		t.Fatal("reset retained or re-emitted state")
	}
	if packet := <-ch; packet.Metadata["kind"] != "reset" || packet.Metadata["error_code"] != uint64(3) {
		t.Fatal(packet.Metadata)
	}
	if err := p.CloseQUICStreams(); err != nil {
		t.Fatal(err)
	}
	p = NewDoQStreamParser(types.ConnectionKey{}, nil)
	for i := 0; i < maxDNSPending; i++ {
		if err := p.ResetQUICStream(uint64(i)*4, false, 3); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.ResetQUICStream(maxDNSPending*4, false, 3); !errors.Is(err, ErrHTTPEventLimit) {
		t.Fatal("tombstones unbounded", err)
	}
	p = NewDoQStreamParser(types.ConnectionKey{}, nil)
	partial := make([]byte, 65536)
	binary.BigEndian.PutUint16(partial, maxDNSMessage)
	for i := 0; i < 64; i++ {
		if err := p.FeedQUICStream(uint64(i)*4, true, partial, false, time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.FeedQUICStream(256, true, partial, false, time.Time{}); !errors.Is(err, ErrHTTPEventLimit) {
		t.Fatal("aggregate partial bodies unbounded", err)
	}
}

func TestDNSBackpressureAndLongConnection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ch := make(chan *types.DecryptedPacket)
		p := NewDNSStreamParser(types.ConnectionKey{}, ch)
		q := dnsTestFrame(dnsTestWire(t, 1, "loop.example.", false))
		r := dnsTestFrame(dnsTestWire(t, 1, "loop.example.", true))
		done := make(chan struct{})
		go func() {
			for i := 0; i < 2000; i++ {
				p.FeedRequest(q)
				p.FeedResponse(r)
			}
			close(done)
		}()
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("producer bypassed backpressure")
		default:
		}
		for i := 0; i < 4000; i++ {
			packet := <-ch
			if packet.Metadata["request_id"] != uint64(i/2+1) {
				t.Fatal(packet.Metadata)
			}
		}
		<-done
		if p.pendingCount != 0 || p.questionBytes != 0 || p.Err() != nil {
			t.Fatal("long connection retained history")
		}
	})
}

func TestDNSQuestionRetentionBound(t *testing.T) {
	p := NewDNSStreamParser(types.ConnectionKey{}, nil)
	m := dnsmessage.Message{}
	name := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + ".example."
	for i := 0; i < maxDNSQuestions; i++ {
		m.Questions = append(m.Questions, dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	}
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100 && p.Err() == nil; i++ {
		p.FeedRequest(dnsTestFrame(wire))
	}
	if !errors.Is(p.Err(), ErrHTTPEventLimit) || p.questionBytes != 0 {
		t.Fatal("question association storage unbounded", p.Err())
	}
}

func FuzzDNSWireAndDoT(f *testing.F) {
	f.Add([]byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1})
	f.Add([]byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxDNSMessage {
			return
		}
		_, _ = decodeDNSMessage(data)
		p := NewDNSStreamParser(types.ConnectionKey{}, nil)
		framed := dnsTestFrame(data)
		for len(framed) > 0 {
			n := min(len(framed), 7)
			p.FeedRequest(framed[:n])
			framed = framed[n:]
		}
		_ = p.Close()
	})
}

func TestDNSOPTPlacementAndUniqueness(t *testing.T) {
	opt := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 1232}, Body: &dnsmessage.OPTResource{}}
	for _, mode := range []string{"answer", "owner", "duplicate"} {
		m := dnsmessage.Message{Additionals: []dnsmessage.Resource{opt}}
		switch mode {
		case "answer":
			m.Answers = m.Additionals
			m.Additionals = nil
		case "owner":
			m.Additionals[0].Header.Name = dnsmessage.MustNewName("bad.example.")
		case "duplicate":
			m.Additionals = append(m.Additionals, opt)
		}
		wire, err := m.Pack()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeDNSMessage(wire); err == nil {
			t.Fatalf("invalid OPT %s accepted", mode)
		}
	}
}
