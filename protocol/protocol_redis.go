// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package protocol

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gojue/ecapture_decryptor/types"
)

const (
	maxRedisValueBytes = 16 << 20
	maxRedisLineBytes  = 64 << 10
	maxRedisElements   = 65536
	maxRedisDepth      = 32
	maxRedisPending    = 1024
)

var errRedis = errors.New("invalid or unsupported Redis RESP stream")

type redisAtom struct {
	kind byte
	text []byte
}
type redisAggregate struct {
	remaining int
	attribute bool
}

// respScanner advances over each received byte once. It retains only framing
// state and up to four top-level atoms, not a recursive representation of data.
type respScanner struct {
	pos, scan, elements int
	root                byte
	count               int
	stack               []redisAggregate
	bulk                bool
	bulkKind            byte
	bulkStart, bulkEnd  int
	atoms               []redisAtom
	allBulk, resp3      bool
}

func redisDigits(b []byte, signed bool) bool {
	if signed && len(b) > 0 && (b[0] == '+' || b[0] == '-') {
		b = b[1:]
	}
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func redisLength(b []byte) (int, error) {
	if !redisDigits(b, false) {
		return 0, errRedis
	}
	n, err := strconv.ParseUint(string(b), 10, 64)
	if err != nil || n > maxRedisValueBytes {
		return 0, ErrHTTPEventLimit
	}
	return int(n), nil
}
func redisDouble(b []byte) bool {
	if bytes.Equal(b, []byte("inf")) || bytes.Equal(b, []byte("-inf")) || bytes.Equal(b, []byte("nan")) {
		return true
	}
	if len(b) > 0 && (b[0] == '+' || b[0] == '-') {
		b = b[1:]
	}
	i := 0
	for i < len(b) && b[i] >= '0' && b[i] <= '9' {
		i++
	}
	if i == 0 {
		return false
	}
	if i < len(b) && b[i] == '.' {
		start := i + 1
		i = start
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
			i++
		}
		if i == start {
			return false
		}
	}
	if i < len(b) && (b[i] == 'e' || b[i] == 'E') {
		return redisDigits(b[i+1:], true)
	}
	return i == len(b)
}
func (s *respScanner) atom(kind byte, text []byte) {
	if kind != '|' && len(s.stack) == 1 && (s.root == '*' || s.root == '>') {
		s.allBulk = s.allBulk && kind == '$' && text != nil
		if len(s.atoms) < 4 {
			s.atoms = append(s.atoms, redisAtom{kind, text})
		}
	}
}
func (s *respScanner) complete(attribute bool) bool {
	for len(s.stack) > 0 {
		parent := &s.stack[len(s.stack)-1]
		if attribute {
			return false
		}
		parent.remaining--
		if parent.remaining > 0 {
			return false
		}
		attribute = parent.attribute
		s.stack = s.stack[:len(s.stack)-1]
	}
	return true
}
func (s *respScanner) advance(b []byte) (bool, error) {
	for {
		if s.bulk {
			if len(b) < s.bulkEnd+2 {
				return false, nil
			}
			if b[s.bulkEnd] != '\r' || b[s.bulkEnd+1] != '\n' {
				return false, errRedis
			}
			payload := b[s.bulkStart:s.bulkEnd]
			if s.bulkKind == '=' && (len(payload) < 4 || payload[3] != ':') {
				return false, errRedis
			}
			s.atom(s.bulkKind, payload)
			s.pos = s.bulkEnd + 2
			s.scan = s.pos
			s.bulk = false
			if s.complete(false) {
				return true, nil
			}
		}
		if s.pos == len(b) {
			return false, nil
		}
		kind := b[s.pos]
		if !strings.ContainsRune("+-:$*_#,(!=%|~>", rune(kind)) {
			return false, errRedis
		}
		start := max(s.pos+1, s.scan)
		n := bytes.Index(b[start:], []byte("\r\n"))
		if n < 0 {
			if len(b)-s.pos > maxRedisLineBytes {
				return false, ErrHTTPEventLimit
			}
			s.scan = max(s.pos+1, len(b)-1)
			return false, nil
		}
		end := start + n
		if end-s.pos > maxRedisLineBytes {
			return false, ErrHTTPEventLimit
		}
		line := b[s.pos+1 : end]
		if bytes.ContainsAny(line, "\r\n") {
			return false, errRedis
		}
		s.pos = end + 2
		s.scan = s.pos
		s.elements++
		if s.elements > maxRedisElements {
			return false, ErrHTTPEventLimit
		}
		if s.root == 0 {
			s.root = kind
			s.allBulk = true
		}
		if strings.ContainsRune("_#,(!=%|~>", rune(kind)) {
			s.resp3 = true
		}
		switch kind {
		case '+', '-':
			s.atom(kind, line)
		case ':':
			if !redisDigits(line, true) {
				return false, errRedis
			}
			if _, err := strconv.ParseInt(string(line), 10, 64); err != nil {
				return false, errRedis
			}
			s.atom(kind, line)
		case '_':
			if len(line) != 0 {
				return false, errRedis
			}
			s.atom(kind, nil)
		case '#':
			if !bytes.Equal(line, []byte("t")) && !bytes.Equal(line, []byte("f")) {
				return false, errRedis
			}
			s.atom(kind, line)
		case ',':
			if !redisDouble(line) {
				return false, errRedis
			}
			if _, err := strconv.ParseFloat(string(line), 64); err != nil {
				return false, errRedis
			}
			s.atom(kind, line)
		case '(':
			if !redisDigits(line, true) {
				return false, errRedis
			}
			s.atom(kind, line)
		case '$', '!', '=':
			if kind == '$' && bytes.Equal(line, []byte("-1")) {
				s.atom(kind, nil)
				break
			}
			n, err := redisLength(line)
			if err != nil {
				return false, err
			}
			if n > maxRedisValueBytes-s.pos-2 {
				return false, ErrHTTPEventLimit
			}
			s.bulk = true
			s.bulkKind = kind
			s.bulkStart = s.pos
			s.bulkEnd = s.pos + n
			continue
		case '*', '%', '|', '~', '>':
			if kind == '*' && bytes.Equal(line, []byte("-1")) {
				s.atom(kind, nil)
				break
			}
			n, err := redisLength(line)
			if err != nil {
				return false, err
			}
			if kind == '%' || kind == '|' {
				n *= 2
			}
			if n > maxRedisElements {
				return false, ErrHTTPEventLimit
			}
			if kind == '>' && (len(s.stack) != 0 || n == 0) {
				return false, errRedis
			}
			if len(s.stack) == 0 {
				s.count = n
			}
			// Nested aggregates aren't legal command arguments. Their wire bytes are
			// still accepted in replies without allocating a tree of child values.
			s.atom(kind, nil)
			if len(s.stack) >= maxRedisDepth {
				return false, ErrHTTPEventLimit
			}
			if n == 0 {
				if s.complete(kind == '|') {
					return true, nil
				}
				continue
			}
			s.stack = append(s.stack, redisAggregate{remaining: n, attribute: kind == '|'})
			continue
		}
		if s.complete(false) {
			return true, nil
		}
	}
}

type redisDirection struct {
	data []byte
	scan respScanner
	at   time.Time
}
type redisRequest struct {
	id            uint64
	command       string
	acks, version int
}
type redisDeferred struct {
	data []byte
	at   time.Time
}

// RedisStreamParser accepts array-of-bulk-string commands and fixed-length
// RESP2/RESP3 replies. Data is an exact wire value. Push/attribute events never
// consume an ordinary reply slot. Inline, streamed, MONITOR and replication
// modes are explicitly unsupported rather than guessed from payload bytes.
type RedisStreamParser struct {
	mu                sync.Mutex
	addr              types.ConnectionKey
	ch                chan *types.DecryptedPacket
	at                time.Time
	directions        [2]redisDirection
	pending           []redisRequest
	deferred          []redisDeferred
	deferredBytes     int
	next              uint64
	resp3             bool
	subscriptions     map[string]struct{}
	subscriptionBytes int
	err               error
	closed            bool
}

func NewRedisStreamParser(addr types.ConnectionKey, ch chan *types.DecryptedPacket) *RedisStreamParser {
	return &RedisStreamParser{addr: addr, ch: ch, subscriptions: make(map[string]struct{})}
}
func (p *RedisStreamParser) SetPacketTime(at time.Time) { p.mu.Lock(); defer p.mu.Unlock(); p.at = at }
func (p *RedisStreamParser) Err() error                 { p.mu.Lock(); defer p.mu.Unlock(); return p.err }
func (p *RedisStreamParser) FeedRequest(data []byte)    { p.feed(data, true) }
func (p *RedisStreamParser) FeedResponse(data []byte)   { p.feed(data, false) }
func (p *RedisStreamParser) feed(data []byte, client bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil || p.closed {
		return
	}
	d := &p.directions[http3Side(client)]
	for len(data) > 0 {
		n := min(len(data), eventChunkSize, maxRedisValueBytes-len(d.data))
		if n == 0 {
			p.fail(ErrHTTPEventLimit)
			return
		}
		if len(d.data) == 0 {
			d.at = p.at
		}
		d.data = append(d.data, data[:n]...)
		data = data[n:]
		for len(d.data) > 0 {
			complete, err := d.scan.advance(d.data)
			if err != nil {
				p.fail(err)
				return
			}
			if !complete {
				break
			}
			if err = p.value(d.data[:d.scan.pos], &d.scan, client, d.at); err != nil {
				p.fail(err)
				return
			}
			d.data = d.data[d.scan.pos:]
			d.scan = respScanner{}
			d.at = p.at
			if len(d.data) == 0 {
				d.data = nil
			}
		}
	}
}
func redisText(a redisAtom) string {
	if a.kind != '$' && a.kind != '+' {
		return ""
	}
	return string(a.text)
}
func redisSubscription(command string) bool {
	switch command {
	case "SUBSCRIBE", "PSUBSCRIBE", "SSUBSCRIBE", "UNSUBSCRIBE", "PUNSUBSCRIBE", "SUNSUBSCRIBE":
		return true
	default:
		return false
	}
}
func (p *RedisStreamParser) value(raw []byte, s *respScanner, client bool, at time.Time) error {
	if !client && !p.responseReady(s) {
		if len(p.deferred) >= maxRedisPending || len(raw) > maxRedisValueBytes-p.deferredBytes {
			return ErrHTTPEventLimit
		}
		p.deferred = append(p.deferred, redisDeferred{bytes.Clone(raw), at})
		p.deferredBytes += len(raw)
		return nil
	}
	meta := map[string]any{"resp_type": string(s.root)}
	kind := "response"
	if client {
		if s.root != '*' || s.count == 0 || !s.allBulk || len(s.atoms) == 0 || len(s.atoms[0].text) == 0 || len(s.atoms[0].text) > 128 {
			return errRedis
		}
		command := strings.ToUpper(string(s.atoms[0].text))
		switch command {
		case "MONITOR", "SYNC", "PSYNC", "REPLCONF":
			return errRedis
		case "CLIENT":
			if len(s.atoms) > 1 && strings.EqualFold(string(s.atoms[1].text), "REPLY") {
				return errRedis
			}
		}
		if len(p.pending) >= maxRedisPending {
			return ErrHTTPEventLimit
		}
		p.next++
		req := redisRequest{id: p.next, command: command}
		if redisSubscription(command) {
			req.acks = s.count - 1
			if req.acks == 0 {
				if !strings.Contains(command, "UNSUBSCRIBE") {
					return errRedis
				}
				req.acks = -1
			}
		}
		if command == "HELLO" && len(s.atoms) > 1 {
			if string(s.atoms[1].text) == "3" {
				req.version = 3
			} else if string(s.atoms[1].text) == "2" {
				req.version = 2
			}
		}
		p.pending = append(p.pending, req)
		kind = "request"
		meta["request_id"] = req.id
		meta["command"] = command
		meta["argument_count"] = s.count - 1
	} else {
		if s.resp3 {
			p.resp3 = true
		}
		switch {
		case s.root == '|':
			kind = "attribute"
		case s.root == '>' || s.root == '*' && p.resp2Pubsub(s):
			kind = "push"
			if len(s.atoms) == 0 || redisText(s.atoms[0]) == "" {
				return errRedis
			}
			name := redisText(s.atoms[0])
			meta["push_type"] = name
			if name == strings.ToLower(name) && redisSubscription(strings.ToUpper(name)) {
				if err := p.subscriptionAck(s, name, meta); err != nil {
					return err
				}
			}
		default:
			if len(p.pending) > 0 {
				req := p.pending[0]
				p.remove(0)
				meta["request_id"] = req.id
				meta["command"] = req.command
				if req.version != 0 && s.root != '-' && s.root != '!' {
					p.resp3 = req.version == 3
				}
			} else {
				meta["unsolicited"] = true
			}
		}
	}
	meta["kind"] = kind
	if p.ch != nil {
		direction := "response"
		if client {
			direction = "request"
		}
		packet := types.NewDecryptedPacket(types.TransportProtocolTCP, "redis", direction, bytes.Clone(raw), at, p.addr)
		for k, v := range meta {
			packet.WithMetadata(k, v)
		}
		p.ch <- packet
	}
	if client {
		return p.drainResponses()
	}
	return nil
}

// TLS directions can advance independently while the request is fragmented.
// Keep only complete wire values until their request becomes available. Ordinary
// pushes and attributes need no request; subscription acknowledgements do.
func (p *RedisStreamParser) responseReady(s *respScanner) bool {
	if p.closed || s.root == '|' {
		return true
	}
	if s.root == '>' || s.root == '*' && p.resp2Pubsub(s) {
		if len(s.atoms) > 0 {
			name := redisText(s.atoms[0])
			if name == strings.ToLower(name) && redisSubscription(strings.ToUpper(name)) {
				for _, req := range p.pending {
					if strings.EqualFold(req.command, name) {
						return true
					}
				}
				return false
			}
		}
		return true
	}
	return len(p.pending) > 0
}
func (p *RedisStreamParser) drainResponses() error {
	for len(p.deferred) > 0 {
		v := p.deferred[0]
		s := respScanner{}
		if _, err := s.advance(v.data); err != nil {
			return err
		}
		if !p.responseReady(&s) {
			return nil
		}
		p.deferred[0] = redisDeferred{}
		p.deferred = p.deferred[1:]
		p.deferredBytes -= len(v.data)
		if err := p.value(v.data, &s, false, v.at); err != nil {
			return err
		}
	}
	p.deferred = nil
	return nil
}
func (p *RedisStreamParser) resp2Pubsub(s *respScanner) bool {
	if p.resp3 || len(s.atoms) == 0 {
		return false
	}
	name := redisText(s.atoms[0])
	if name == strings.ToLower(name) && redisSubscription(strings.ToUpper(name)) {
		for _, req := range p.pending {
			if strings.EqualFold(req.command, name) {
				return true
			}
		}
		return len(p.subscriptions) > 0
	}
	return len(p.subscriptions) > 0 && (name == "message" && s.count == 3 || name == "pmessage" && s.count == 4 || name == "smessage" && s.count == 3)
}
func (p *RedisStreamParser) subscriptionAck(s *respScanner, name string, meta map[string]any) error {
	if s.count != 3 || len(s.atoms) != 3 || s.atoms[2].kind != ':' || len(s.atoms[1].text) > maxRedisLineBytes {
		return errRedis
	}
	count, err := strconv.Atoi(string(s.atoms[2].text))
	if err != nil || count < 0 {
		return errRedis
	}
	if count > maxRedisPending {
		return ErrHTTPEventLimit
	}
	prefix := "c"
	if strings.HasPrefix(name, "p") {
		prefix = "p"
	}
	if strings.HasPrefix(name, "s") && (name == "ssubscribe" || name == "sunsubscribe") {
		prefix = "s"
	}
	channel := redisText(s.atoms[1])
	if s.atoms[1].kind != '$' && s.atoms[1].kind != '+' {
		return errRedis
	}
	key := prefix + channel
	removing := strings.Contains(name, "unsubscribe")
	if !removing && s.atoms[1].text == nil {
		return errRedis
	}
	pending := -1
	for i, req := range p.pending {
		if strings.EqualFold(req.command, name) {
			pending = i
			break
		}
	}
	if pending >= 0 && p.pending[pending].acks < 0 {
		n := 0
		for k := range p.subscriptions {
			if k[0] == prefix[0] {
				n++
			}
		}
		p.pending[pending].acks = max(1, n)
	}
	if removing {
		if _, ok := p.subscriptions[key]; ok {
			delete(p.subscriptions, key)
			p.subscriptionBytes -= len(key)
		}
	} else {
		if _, ok := p.subscriptions[key]; !ok {
			if len(p.subscriptions) >= maxRedisPending || len(key) > maxRedisLineBytes-p.subscriptionBytes {
				return ErrHTTPEventLimit
			}
			p.subscriptions[key] = struct{}{}
			p.subscriptionBytes += len(key)
		}
	}
	meta["subscription_count"] = count
	if pending >= 0 {
		req := &p.pending[pending]
		meta["request_id"] = req.id
		meta["command"] = req.command
		req.acks--
		if req.acks == 0 {
			p.remove(pending)
		}
	}
	return nil
}
func (p *RedisStreamParser) remove(index int) {
	copy(p.pending[index:], p.pending[index+1:])
	p.pending[len(p.pending)-1] = redisRequest{}
	p.pending = p.pending[:len(p.pending)-1]
}
func (p *RedisStreamParser) fail(err error) {
	p.err = err
	p.directions = [2]redisDirection{}
	p.pending = nil
	p.deferred = nil
	p.deferredBytes = 0
	p.subscriptions = nil
	p.subscriptionBytes = 0
}
func (p *RedisStreamParser) Flush() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	if p.err == nil {
		p.err = p.drainResponses()
	}
	if p.err == nil && (len(p.directions[0].data)+len(p.directions[1].data) > 0 || len(p.pending) > 0) {
		p.err = io.ErrUnexpectedEOF
	}
	p.directions = [2]redisDirection{}
	p.pending = nil
	p.deferred = nil
	p.deferredBytes = 0
	p.subscriptions = nil
	p.subscriptionBytes = 0
}
func (p *RedisStreamParser) Close() error { p.Flush(); return p.Err() }

var _ types.StreamParserInterface = (*RedisStreamParser)(nil)
