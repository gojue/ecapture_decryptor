// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gojue/ecapture_decryptor/types"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	maxDNSMessage       = 65535
	maxDNSQuestions     = 64
	maxDNSRecords       = 1024
	maxDNSPending       = 1024
	maxDNSQuestionBytes = 1 << 20
	maxDoQBufferedBytes = 4 << 20
)

var errDNS = errors.New("invalid DNS message or stream")

type dnsDecoded struct {
	meta            map[string]any
	id              uint16
	opcode          uint16
	rcode           uint16
	qr              bool
	questions       string // Canonical counted labels and QTYPE/QCLASS, not dotted text.
	zone, keepalive bool
}

// decodeDNSMessage validates a complete DNS wire message, without a transport
// length prefix. Unknown RR types remain opaque in Data; metadata describes the
// header, questions and common answers. It never includes parser error text.
func decodeDNSMessage(data []byte) (map[string]any, error) {
	m, err := decodeDNS(data)
	return m.meta, err
}

// dnsQuestionsMatch compares one known request/response pair. A question-less
// error response may match its ID/opcode; callers must provide an unambiguous
// transport association (e.g. one HTTP stream), as the DoT matcher below does.
func dnsQuestionsMatch(query, response []byte) bool {
	q, err := decodeDNS(query)
	if err != nil {
		return false
	}
	r, err := decodeDNS(response)
	return err == nil && dnsMatches(q, r)
}
func dnsMatches(q, r dnsDecoded) bool {
	return !q.qr && r.qr && q.id == r.id && q.opcode == r.opcode &&
		(q.questions == r.questions || r.questions == "" && r.rcode != 0)
}

// dnsName walks compression pointers with strict bounds and retains label
// lengths in the comparison key, so a dot inside a label cannot alias a suffix.
func dnsName(data []byte, offset int) (int, []byte, error) {
	end, jumps := -1, 0
	var key []byte
	for {
		if offset >= len(data) {
			return 0, nil, errDNS
		}
		length := int(data[offset])
		if length&0xc0 == 0xc0 {
			if offset+1 >= len(data) {
				return 0, nil, errDNS
			}
			pointer := int(data[offset]&0x3f)<<8 | int(data[offset+1])
			if pointer >= offset || pointer < 12 || jumps >= 128 {
				return 0, nil, errDNS
			}
			if end < 0 {
				end = offset + 2
			}
			offset = pointer
			jumps++
			continue
		}
		if length&0xc0 != 0 || offset+1+length > len(data) || len(key)+length+1 > 255 {
			return 0, nil, errDNS
		}
		key = append(key, byte(length))
		offset++
		for _, c := range data[offset : offset+length] {
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			key = append(key, c)
		}
		offset += length
		if length == 0 {
			if end < 0 {
				end = offset
			}
			return end, key, nil
		}
	}
}

func decodeDNS(data []byte) (dnsDecoded, error) {
	var result dnsDecoded
	if len(data) > maxDNSMessage {
		return result, ErrHTTPEventLimit
	}
	if len(data) < 12 {
		return result, errDNS
	}
	if data[3]&0x40 != 0 {
		return result, errDNS
	}
	counts := [4]int{}
	total := 0
	for i := range counts {
		counts[i] = int(binary.BigEndian.Uint16(data[4+i*2:]))
		total += counts[i]
	}
	if counts[0] > maxDNSQuestions || total > maxDNSRecords {
		return result, ErrHTTPEventLimit
	}
	offset := 12
	var questions []byte
	for i := 0; i < counts[0]; i++ {
		next, name, err := dnsName(data, offset)
		if err != nil || next+4 > len(data) {
			return result, errDNS
		}
		questions = append(questions, name...)
		questions = append(questions, data[next:next+4]...)
		typ := binary.BigEndian.Uint16(data[next:])
		result.zone = result.zone || typ == 251 || typ == 252
		offset = next + 4
	}
	optSeen := false
	for section := 1; section < 4; section++ {
		for i := 0; i < counts[section]; i++ {
			next, owner, err := dnsName(data, offset)
			if err != nil || next+10 > len(data) {
				return result, errDNS
			}
			typ := binary.BigEndian.Uint16(data[next:])
			length := int(binary.BigEndian.Uint16(data[next+8:]))
			start, end := next+10, next+10+length
			if end > len(data) {
				return result, errDNS
			}
			if err := validateDNSRData(data, typ, start, end); err != nil {
				return result, err
			}
			if typ == 41 {
				if optSeen || section != 3 || len(owner) != 1 || owner[0] != 0 {
					return result, errDNS
				}
				optSeen = true
				for at := start; at < end; {
					code := binary.BigEndian.Uint16(data[at:])
					n := int(binary.BigEndian.Uint16(data[at+2:]))
					result.keepalive = result.keepalive || code == 11
					at += 4 + n
				}
			}
			offset = end
		}
	}
	if offset != len(data) {
		return result, errDNS
	}
	var message dnsmessage.Message
	if err := message.Unpack(data); err != nil {
		return result, errDNS
	}
	result.id = message.ID
	result.qr = message.Response
	result.opcode = uint16(message.OpCode)
	result.rcode = uint16(message.RCode)
	result.questions = string(questions)
	qs := make([]map[string]any, 0, len(message.Questions))
	for _, q := range message.Questions {
		qs = append(qs, map[string]any{"name": q.Name.String(), "type": uint16(q.Type), "class": uint16(q.Class)})
	}
	answers := make([]map[string]any, 0, len(message.Answers))
	for _, r := range message.Answers {
		meta := map[string]any{"name": r.Header.Name.String(), "type": uint16(r.Header.Type), "class": uint16(r.Header.Class), "ttl": r.Header.TTL}
		switch v := r.Body.(type) {
		case *dnsmessage.AResource:
			meta["address"] = net.IP(v.A[:]).String()
		case *dnsmessage.AAAAResource:
			meta["address"] = net.IP(v.AAAA[:]).String()
		case *dnsmessage.CNAMEResource:
			meta["target"] = v.CNAME.String()
		case *dnsmessage.NSResource:
			meta["target"] = v.NS.String()
		case *dnsmessage.PTRResource:
			meta["target"] = v.PTR.String()
		case *dnsmessage.MXResource:
			meta["preference"] = v.Pref
			meta["target"] = v.MX.String()
		case *dnsmessage.TXTResource:
			meta["text"] = v.TXT
		}
		answers = append(answers, meta)
	}
	for _, r := range message.Additionals {
		if r.Header.Type == dnsmessage.TypeOPT {
			result.rcode |= uint16(r.Header.TTL>>24) << 4
		}
	}
	result.meta = map[string]any{"id": result.id, "qr": result.qr, "opcode": result.opcode, "rcode": result.rcode, "truncated": message.Truncated, "questions": qs, "answers": answers, "question_count": counts[0], "answer_count": counts[1], "authority_count": counts[2], "additional_count": counts[3]}
	return result, nil
}

// The standard DNS unpacker validates names but does not require typed RDATA
// readers to stop at RDLENGTH, so check those boundaries before unpacking.
func validateDNSRData(data []byte, typ uint16, start, end int) error {
	at := start
	switch typ {
	case 1:
		if end-start != 4 {
			return errDNS
		}
	case 28:
		if end-start != 16 {
			return errDNS
		}
	case 2, 5, 12, 15, 33, 6:
		if typ == 15 {
			at += 2
		}
		if typ == 33 {
			at += 6
		}
		if at >= end {
			return errDNS
		}
		next, _, err := dnsName(data, at)
		if err != nil || next > end {
			return errDNS
		}
		at = next
		if typ == 6 {
			if at >= end {
				return errDNS
			}
			next, _, err = dnsName(data, at)
			if err != nil || next > end {
				return errDNS
			}
			at = next + 20
		}
		if at != end {
			return errDNS
		}
	case 64, 65:
		if end-start < 3 {
			return errDNS
		}
		next, _, err := dnsName(data, start+2)
		if err != nil || next > end {
			return errDNS
		}
		for at = next; at < end; {
			if end-at < 4 {
				return errDNS
			}
			n := int(binary.BigEndian.Uint16(data[at+2:]))
			at += 4
			if n > end-at {
				return errDNS
			}
			at += n
		}
	case 16:
		for at < end {
			n := int(data[at])
			at++
			if n > end-at {
				return errDNS
			}
			at += n
		}
	case 41:
		for at < end {
			if end-at < 4 {
				return errDNS
			}
			n := int(binary.BigEndian.Uint16(data[at+2:]))
			at += 4
			if n > end-at {
				return errDNS
			}
			at += n
		}
	}
	return nil
}

func emitDNS(ci types.ConnectionKey, ch chan *types.DecryptedPacket, data []byte, at time.Time, client bool, meta map[string]any) {
	if ch == nil {
		return
	}
	direction := "response"
	if client {
		direction = "request"
	}
	packet := types.NewDecryptedPacket(ci.Proto, "dns", direction, bytes.Clone(data), at, ci)
	for k, v := range meta {
		packet.WithMetadata(k, v)
	}
	ch <- packet
}

type dnsFrame struct {
	data []byte
	at   time.Time
}
type dnsPending struct {
	id      uint64
	decoded dnsDecoded
}

// DNSStreamParser reads ordinary DNS queries/responses over TLS. Pipelined
// replies may arrive out of order. Ambiguous or unsolicited replies are emitted
// with matched=false, never assigned an arbitrary pending request.
type DNSStreamParser struct {
	mu                          sync.Mutex
	conn                        types.ConnectionKey
	ch                          chan *types.DecryptedPacket
	at                          time.Time
	sides                       [2]dnsFrame
	pending                     map[uint16][]dnsPending
	next                        uint64
	pendingCount, questionBytes int
	err                         error
	closed                      bool
}

func NewDNSStreamParser(ci types.ConnectionKey, ch chan *types.DecryptedPacket) *DNSStreamParser {
	return &DNSStreamParser{conn: ci, ch: ch, pending: make(map[uint16][]dnsPending)}
}
func (p *DNSStreamParser) SetPacketTime(at time.Time) { p.mu.Lock(); defer p.mu.Unlock(); p.at = at }
func (p *DNSStreamParser) Err() error                 { p.mu.Lock(); defer p.mu.Unlock(); return p.err }
func (p *DNSStreamParser) FeedRequest(data []byte)    { p.feed(data, true) }
func (p *DNSStreamParser) FeedResponse(data []byte)   { p.feed(data, false) }
func (p *DNSStreamParser) feed(data []byte, client bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil || p.closed {
		return
	}
	d := &p.sides[http3Side(client)]
	for len(data) > 0 {
		if len(d.data) == 0 {
			d.at = p.at
		}
		if len(d.data) < 2 {
			n := min(2-len(d.data), len(data))
			d.data = append(d.data, data[:n]...)
			data = data[n:]
			if len(d.data) < 2 {
				return
			}
		}
		size := int(binary.BigEndian.Uint16(d.data))
		if size < 12 {
			p.fail(errDNS)
			return
		}
		n := min(size+2-len(d.data), len(data))
		d.data = append(d.data, data[:n]...)
		data = data[n:]
		if len(d.data) < size+2 {
			return
		}
		if err := p.message(d.data[2:], client, d.at); err != nil {
			p.fail(err)
			return
		}
		d.data = nil
	}
}
func (p *DNSStreamParser) message(data []byte, client bool, at time.Time) error {
	m, err := decodeDNS(data)
	if err != nil {
		return err
	}
	if m.qr == client || m.opcode != 0 || m.zone {
		return errDNS
	}
	m.meta["transport"] = "dot"
	m.meta["kind"] = "message"
	m.meta["matched"] = false
	if client {
		if m.questions == "" {
			return errDNS
		}
		if p.pendingCount >= maxDNSPending || len(m.questions) > maxDNSQuestionBytes-p.questionBytes {
			return ErrHTTPEventLimit
		}
		p.next++
		m.meta["request_id"] = p.next
		entry := m
		entry.meta = nil
		p.pending[m.id] = append(p.pending[m.id], dnsPending{p.next, entry})
		p.pendingCount++
		p.questionBytes += len(m.questions)
	} else {
		candidates := p.pending[m.id]
		found := -1
		for i, c := range candidates {
			if dnsMatches(c.decoded, m) {
				if found >= 0 {
					found = -2
					break
				}
				found = i
			}
		}
		if found >= 0 {
			m.meta["matched"] = true
			m.meta["request_id"] = candidates[found].id
			p.pendingCount--
			p.questionBytes -= len(candidates[found].decoded.questions)
			copy(candidates[found:], candidates[found+1:])
			candidates[len(candidates)-1] = dnsPending{}
			candidates = candidates[:len(candidates)-1]
			if len(candidates) == 0 {
				delete(p.pending, m.id)
			} else {
				p.pending[m.id] = candidates
			}
		}
	}
	emitDNS(p.conn, p.ch, data, at, client, m.meta)
	return nil
}
func (p *DNSStreamParser) fail(err error) { p.err = err; p.clear() }
func (p *DNSStreamParser) clear() {
	p.sides = [2]dnsFrame{}
	p.pending = nil
	p.pendingCount = 0
	p.questionBytes = 0
}
func (p *DNSStreamParser) Flush() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	if p.err == nil && len(p.sides[0].data)+len(p.sides[1].data) > 0 {
		p.err = io.ErrUnexpectedEOF
	}
	p.clear()
}
func (p *DNSStreamParser) Close() error { p.Flush(); return p.Err() }

// DoQStreamParser covers ordinary QUERY transactions, one request and one
// response per client-initiated bidirectional stream. AXFR/IXFR are not included.
type DoQStreamParser struct {
	mu                      sync.Mutex
	conn                    types.ConnectionKey
	ch                      chan *types.DecryptedPacket
	streams                 map[uint64]*doqStream
	buffered, questionBytes int
	err                     error
	closed                  bool
}
type doqHalf struct {
	dnsFrame
	fin, emitted bool
	decoded      dnsDecoded
}
type doqStream struct {
	sides [2]doqHalf
	reset bool
}

func NewDoQStreamParser(ci types.ConnectionKey, ch chan *types.DecryptedPacket) *DoQStreamParser {
	return &DoQStreamParser{conn: ci, ch: ch, streams: make(map[uint64]*doqStream)}
}
func (p *DoQStreamParser) Err() error { p.mu.Lock(); defer p.mu.Unlock(); return p.err }
func (p *DoQStreamParser) stream(id uint64) (*doqStream, error) {
	if id&3 != 0 || id > 1<<62-1 {
		return nil, errDNS
	}
	s := p.streams[id]
	if s == nil {
		if len(p.streams) >= maxDNSPending {
			return nil, ErrHTTPEventLimit
		}
		s = &doqStream{}
		p.streams[id] = s
	}
	return s, nil
}
func (p *DoQStreamParser) FeedQUICStream(id uint64, client bool, data []byte, fin bool, at time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	if p.closed {
		return io.ErrClosedPipe
	}
	s, err := p.stream(id)
	if err != nil {
		return p.fail(err)
	}
	if s.reset {
		return nil
	}
	d := &s.sides[http3Side(client)]
	if d.fin {
		if len(data) == 0 && fin {
			return nil
		}
		return p.fail(errDNS)
	}
	if len(data) > maxDNSMessage+2-len(d.data) || len(data) > maxDoQBufferedBytes-p.buffered {
		return p.fail(ErrHTTPEventLimit)
	}
	if len(d.data) == 0 {
		d.at = at
	}
	d.data = append(d.data, data...)
	p.buffered += len(data)
	if len(d.data) >= 2 {
		size := int(binary.BigEndian.Uint16(d.data))
		if size < 12 || len(d.data) > size+2 {
			return p.fail(errDNS)
		}
	}
	if !fin {
		return nil
	}
	if len(d.data) < 2 || len(d.data) != int(binary.BigEndian.Uint16(d.data))+2 {
		return p.fail(io.ErrUnexpectedEOF)
	}
	m, err := decodeDNS(d.data[2:])
	if err != nil {
		return p.fail(err)
	}
	if m.id != 0 || m.opcode != 0 || m.qr == client || m.zone || m.keepalive || client && m.questions == "" {
		return p.fail(errDNS)
	}
	if len(m.questions) > maxDNSQuestionBytes-p.questionBytes {
		return p.fail(ErrHTTPEventLimit)
	}
	p.questionBytes += len(m.questions)
	d.decoded = m
	if !client && !s.sides[0].fin {
		d.decoded.meta = nil
	} // Avoid retaining expanded RR metadata while awaiting the query.
	d.fin = true
	if s.sides[0].fin {
		if err := p.emit(id, &s.sides[0], true); err != nil {
			return p.fail(err)
		}
	}
	if s.sides[0].fin && s.sides[1].fin {
		if !dnsMatches(s.sides[0].decoded, s.sides[1].decoded) {
			return p.fail(errDNS)
		}
		if err := p.emit(id, &s.sides[1], false); err != nil {
			return p.fail(err)
		}
		for i := range s.sides {
			p.questionBytes -= len(s.sides[i].decoded.questions)
			s.sides[i].decoded = dnsDecoded{}
		}
	}
	return nil
}
func (p *DoQStreamParser) emit(id uint64, d *doqHalf, client bool) error {
	if d.emitted {
		return nil
	}
	meta := d.decoded.meta
	if meta == nil {
		decoded, err := decodeDNS(d.data[2:])
		if err != nil {
			return err
		}
		meta = decoded.meta
	}
	meta["transport"] = "doq"
	meta["kind"] = "message"
	meta["stream_id"] = id
	meta["request_id"] = id/4 + 1
	meta["matched"] = !client
	meta["stream_end"] = true
	emitDNS(p.conn, p.ch, d.data[2:], d.at, client, meta)
	d.decoded.meta = nil
	d.emitted = true
	p.buffered -= len(d.data)
	d.data = nil
	return nil
}
func (p *DoQStreamParser) ResetQUICStream(id uint64, client bool, code uint64) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	if p.closed {
		return io.ErrClosedPipe
	}
	s, err := p.stream(id)
	if err != nil {
		return p.fail(err)
	}
	if s.reset || s.sides[0].fin && s.sides[1].fin {
		return nil
	}
	for i := range s.sides {
		p.buffered -= len(s.sides[i].data)
		p.questionBytes -= len(s.sides[i].decoded.questions)
	}
	s.sides = [2]doqHalf{}
	s.reset = true
	emitDNS(p.conn, p.ch, nil, time.Time{}, client, map[string]any{"transport": "doq", "kind": "reset", "stream_id": id, "request_id": id/4 + 1, "error_code": code})
	return nil
}
func (p *DoQStreamParser) fail(err error) error {
	p.err = err
	p.streams = nil
	p.buffered = 0
	p.questionBytes = 0
	return err
}
func (p *DoQStreamParser) CloseQUICStreams() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return p.err
	}
	p.closed = true
	if p.err == nil {
		for _, s := range p.streams {
			if !s.reset && (!s.sides[0].fin || !s.sides[1].fin) {
				p.err = io.ErrUnexpectedEOF
				break
			}
		}
	}
	p.streams = nil
	p.buffered = 0
	p.questionBytes = 0
	return p.err
}

var _ types.StreamParserInterface = (*DNSStreamParser)(nil)
