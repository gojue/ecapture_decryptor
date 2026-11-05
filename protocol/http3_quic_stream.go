package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gojue/ecapture_decryptor/types"
	"golang.org/x/net/http/httpguts"
)

const (
	maxHTTP3StreamBytes     = 16 << 20
	maxHTTP3ConnectionBytes = 32 << 20
	maxHTTP3Streams         = 1024
	maxHTTP3Pushes          = 128
)

var errHTTP3Message = errors.New("invalid HTTP/3 message or stream state")

type http3QUICStream struct{ request, response http3QUICMessage }
type http3QUICMessage struct {
	buffer, body                                                bytes.Buffer
	headers, trailers                                           http.Header
	method, path, scheme, authority, status                     string
	at, blockedAt                                               time.Time
	section                                                     qpackSection
	skip                                                        uint64
	headersDone, trailersDone, fin, finished, deferred, started bool
}
type http3UniStream struct {
	buffer    bytes.Buffer
	kind      uint64
	typed     bool
	pushID    uint64
	pushKnown bool
	reset     bool
	skip      uint64
}
type http3Deferred struct {
	id        uint64
	data      []byte
	fin       bool
	at, since time.Time
}
type http3Direction struct {
	settings                      bool
	capacity, blocked, fieldLimit uint64
	critical                      [3]bool // control, encoder, decoder
	table                         qpackDynamicTable
	deferred                      []http3Deferred // wire order while the opposite SETTINGS are unavailable
	goAway                        uint64
	hasGoAway                     bool
	maxPush                       uint64
	hasMaxPush                    bool
}
type http3Push struct {
	request, response               http3QUICMessage
	parent, streamID                uint64
	promised, streamKnown, canceled bool
	since                           time.Time
	informational                   []http3QUICMessage
}

func http3Side(client bool) int {
	if client {
		return 0
	}
	return 1
}

// FeedQUICStream accepts contiguous, authenticated bytes. QPACK tables belong to
// the connection and sender, not to an individual request. Output remains serial
// and applies backpressure; a blocked field section never blocks input handling.
func (p *HTTP3StreamParser) FeedQUICStream(id uint64, isClient bool, data []byte, fin bool, at time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.quicErr != nil {
		return p.quicErr
	}
	if p.quicClosed {
		return io.ErrClosedPipe
	}
	err := p.feedHTTP3(id, isClient, data, fin, at)
	if err == nil {
		err = p.checkHTTP3Bounds()
	}
	p.quicErr = err
	return err
}

func (p *HTTP3StreamParser) feedHTTP3(id uint64, client bool, data []byte, fin bool, at time.Time) error {
	if id&2 != 0 {
		if id&1 != uint64(http3Side(client)) {
			return errHTTP3Message
		}
		return p.feedHTTP3Uni(id, client, data, fin, at)
	}
	if id&1 != 0 {
		return errHTTP3Message
	}
	s := p.quicStreams[id]
	if s == nil {
		if len(p.quicStreams)+len(p.quicUni) >= maxHTTP3Streams {
			return ErrHTTP3ResourceLimit
		}
		s = &http3QUICStream{}
		p.quicStreams[id] = s
	}
	m := &s.request
	if !client {
		m = &s.response
	}
	return p.feedHTTP3Message(id, client, m, data, fin, at)
}

func (p *HTTP3StreamParser) deferHTTP3(id uint64, client bool, data []byte, fin bool, at time.Time) error {
	d := &p.quicState[http3Side(client)]
	if len(d.deferred) >= 4096 {
		return ErrHTTP3ResourceLimit
	}
	d.deferred = append(d.deferred, http3Deferred{id: id, data: bytes.Clone(data), fin: fin, at: at, since: time.Now()})
	return nil
}

func (p *HTTP3StreamParser) feedHTTP3Message(id uint64, client bool, m *http3QUICMessage, data []byte, fin bool, at time.Time) error {
	if m.finished {
		if len(data) > 0 {
			return errHTTP3Message
		}
		return nil
	}
	if m.fin && len(data) > 0 {
		return errHTTP3Message
	}
	if m.deferred {
		return p.deferHTTP3(id, client, data, fin, at)
	}
	if !m.started {
		m.at = at
		m.started = true
	}
	if m.buffer.Len()+m.body.Len()+len(data) > maxHTTP3StreamBytes {
		return ErrHTTP3ResourceLimit
	}
	_, _ = m.buffer.Write(data)
	m.fin = m.fin || fin
	err := p.parseHTTP3Message(id, client, m)
	if errors.Is(err, errQPACKBlocked) && !p.quicState[1-http3Side(client)].settings {
		err = p.deferHTTP3(id, client, m.buffer.Bytes(), m.fin, at)
		m.buffer = bytes.Buffer{}
		m.fin = false
		m.deferred = true
		return err
	}
	return err
}

// Unknown frames are skipped incrementally; their advertised lengths never
// allocate a buffer. Known field sections retain a frozen Required Insert Count.
func (p *HTTP3StreamParser) parseHTTP3Message(id uint64, client bool, m *http3QUICMessage) error {
	// Empty frame buffers must release their backing arrays even on open streams.
	defer func() {
		if m.buffer.Len() == 0 {
			m.buffer = bytes.Buffer{}
		}
	}()
	for m.buffer.Len() > 0 {
		if m.skip > 0 {
			n := min(m.skip, uint64(m.buffer.Len()))
			m.buffer.Next(int(n))
			m.skip -= n
			continue
		}
		b := m.buffer.Bytes()
		typ, n := readVarInt(b)
		if n == 0 {
			break
		}
		length, k := readVarInt(b[n:])
		if k == 0 {
			break
		}
		header := n + k
		switch typ {
		case HTTP3FrameSettings, HTTP3FrameGoAway, HTTP3FrameMaxPushID, HTTP3FrameCancelPush, 2, 6, 8, 9:
			return errHTTP3Message
		case HTTP3FrameData, HTTP3FrameHeaders, HTTP3FramePushPromise:
		default:
			m.buffer.Next(header)
			m.skip = length
			continue
		}
		limit := uint64(maxHTTP3FieldBytes + 8)
		if typ == HTTP3FrameData {
			limit = maxHTTP3StreamBytes
		}
		if length > limit {
			return ErrHTTP3ResourceLimit
		}
		if length > uint64(len(b)-header) {
			break
		}
		payload := b[header : header+int(length)]
		if typ == HTTP3FrameData {
			if !m.headersDone || m.trailersDone {
				return errHTTP3Message
			}
			_, _ = m.body.Write(payload)
		} else {
			fieldsData := payload
			var pushID uint64
			if typ == HTTP3FramePushPromise {
				if client || id&2 != 0 {
					return errHTTP3Message
				}
				var size int
				pushID, size = readVarInt(payload)
				if size == 0 {
					return errHTTP3Message
				}
				fieldsData = payload[size:]
			}
			fields, err := p.decodeHTTP3Fields(m, fieldsData, client)
			if errors.Is(err, errQPACKBlocked) {
				if m.blockedAt.IsZero() {
					m.blockedAt = time.Now()
				}
				if !p.quicState[1-http3Side(client)].settings {
					return err
				}
				return p.checkHTTP3Blocked(client)
			}
			if err != nil {
				return err
			}
			m.section = qpackSection{}
			m.blockedAt = time.Time{}
			if typ == HTTP3FramePushPromise {
				if err := p.promiseHTTP3(pushID, id, fields, m.at); err != nil {
					return err
				}
			} else {
				if err := p.applyHTTP3Headers(id, client, m, fields); err != nil {
					return err
				}
			}
		}
		m.buffer.Next(header + int(length))
	}
	if m.fin && !m.finished {
		if m.buffer.Len() != 0 || m.skip != 0 || !m.headersDone {
			return errHTTP3Message
		}
		if id&2 != 0 {
			push := p.quicPush[p.quicUni[id].pushID]
			if !push.promised || !p.quicState[0].hasMaxPush {
				return nil
			}
		}
		m.finished = true
		p.emitHTTP3(id, client, m, "")
		m.body = bytes.Buffer{}
		m.buffer = bytes.Buffer{}
		m.headers = nil
		m.trailers = nil
	}
	return nil
}

func (p *HTTP3StreamParser) decodeHTTP3Fields(m *http3QUICMessage, b []byte, client bool) ([]qpackField, error) {
	d := &p.quicState[http3Side(client)]
	peer := &p.quicState[1-http3Side(client)]
	if !m.section.initialized {
		s, err := d.table.sectionPrefix(b, peer.capacity, peer.settings)
		if err != nil {
			return nil, err
		}
		m.section = s
	}
	fields, err := d.table.decodeSection(b, m.section)
	if err != nil {
		return nil, err
	}
	if peer.settings {
		var size uint64
		for _, f := range fields {
			size += uint64(len(f.name) + len(f.value) + 32)
		}
		if size > peer.fieldLimit {
			return nil, errHTTP3Message
		}
	}
	return fields, nil
}

func parseHTTP3Headers(fields []qpackField, request, trailers bool) (http3QUICMessage, error) {
	m := http3QUICMessage{headers: make(http.Header)}
	pseudo := make(map[string]string)
	regular := false
	for _, f := range fields {
		if f.name == "" || strings.ToLower(f.name) != f.name || !httpguts.ValidHeaderFieldValue(f.value) {
			return m, errHTTP3Message
		}
		if strings.HasPrefix(f.name, ":") {
			if regular || trailers {
				return m, errHTTP3Message
			}
			if _, ok := pseudo[f.name]; ok {
				return m, errHTTP3Message
			}
			pseudo[f.name] = f.value
			switch f.name {
			case ":method":
				m.method = f.value
			case ":path":
				m.path = f.value
			case ":scheme":
				m.scheme = f.value
			case ":authority":
				m.authority = f.value
			case ":status":
				m.status = f.value
			default:
				return m, errHTTP3Message
			}
		} else {
			if !httpguts.ValidHeaderFieldName(f.name) {
				return m, errHTTP3Message
			}
			switch f.name {
			case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":
				return m, errHTTP3Message
			case "te":
				if f.value != "trailers" {
					return m, errHTTP3Message
				}
			}
			regular = true
			m.headers.Add(f.name, f.value)
		}
	}
	if trailers {
		return m, nil
	}
	if request {
		if _, hasStatus := pseudo[":status"]; m.method == "" || hasStatus {
			return m, errHTTP3Message
		}
		if m.method == "CONNECT" {
			if m.authority == "" || m.scheme != "" || m.path != "" {
				return m, errHTTP3Message
			}
		} else if m.scheme == "" || m.path == "" {
			return m, errHTTP3Message
		}
	} else {
		if len(pseudo) != 1 || len(m.status) != 3 {
			return m, errHTTP3Message
		}
		status, err := strconv.Atoi(m.status)
		if err != nil || status < 100 || status > 599 || status == 101 {
			return m, errHTTP3Message
		}
	}
	return m, nil
}
func (p *HTTP3StreamParser) applyHTTP3Headers(id uint64, client bool, m *http3QUICMessage, fields []qpackField) error {
	if m.trailersDone {
		return errHTTP3Message
	}
	h, err := parseHTTP3Headers(fields, client, m.headersDone)
	if err != nil {
		return err
	}
	if m.headersDone {
		m.trailers = h.headers
		m.trailersDone = true
		return nil
	}
	h.at = m.at
	if !client && h.status[0] == '1' {
		if id&2 != 0 {
			push := p.quicPush[p.quicUni[id].pushID]
			if !push.promised || !p.quicState[0].hasMaxPush {
				if len(push.informational) >= 16 {
					return ErrHTTP3ResourceLimit
				}
				push.informational = append(push.informational, h)
				return nil
			}
		}
		p.emitHTTP3(id, false, &h, "informational")
		return nil
	}
	m.headers = h.headers
	m.method = h.method
	m.path = h.path
	m.scheme = h.scheme
	m.authority = h.authority
	m.status = h.status
	m.headersDone = true
	return nil
}

func (p *HTTP3StreamParser) feedHTTP3Uni(id uint64, client bool, data []byte, fin bool, at time.Time) error {
	u := p.quicUni[id]
	if u == nil {
		if len(p.quicStreams)+len(p.quicUni) >= maxHTTP3Streams {
			return ErrHTTP3ResourceLimit
		}
		u = &http3UniStream{}
		p.quicUni[id] = u
	}
	if u.reset {
		if len(data) > 0 {
			return errHTTP3Message
		}
		return nil
	}
	defer func() {
		if u.buffer.Len() == 0 {
			u.buffer = bytes.Buffer{}
		}
	}()
	if u.buffer.Len()+len(data) > maxHTTP3StreamBytes {
		return ErrHTTP3ResourceLimit
	}
	_, _ = u.buffer.Write(data)
	if !u.typed {
		kind, n := readVarInt(u.buffer.Bytes())
		if n == 0 {
			if fin {
				return errHTTP3Message
			}
			return nil
		}
		u.kind = kind
		u.typed = true
		u.buffer.Next(n)
		if kind == 0 || kind == 2 || kind == 3 {
			index := 0
			if kind > 0 {
				index = int(kind) - 1
			}
			d := &p.quicState[http3Side(client)]
			if d.critical[index] {
				return errHTTP3Message
			}
			d.critical[index] = true
		}
	}
	if fin && (u.kind == 0 || u.kind == 2 || u.kind == 3) {
		return errHTTP3Message
	}
	switch u.kind {
	case 0:
		return p.parseHTTP3Control(u, client)
	case 1:
		if client {
			return errHTTP3Message
		}
		if !u.pushKnown {
			pushID, n := readVarInt(u.buffer.Bytes())
			if n == 0 {
				if fin {
					return errHTTP3Message
				}
				return nil
			}
			push, err := p.getHTTP3Push(pushID)
			if err != nil {
				return err
			}
			if push.streamKnown {
				return errHTTP3Message
			}
			push.streamID = id
			push.streamKnown = true
			u.pushID = pushID
			u.pushKnown = true
			u.buffer.Next(n)
		}
		push := p.quicPush[u.pushID]
		if push.promised && p.quicState[0].hasMaxPush {
			push.since = time.Time{}
			p.emitHTTP3PushInformation(push)
		}
		if push.canceled {
			u.buffer = bytes.Buffer{}
			return nil
		}
		b := bytes.Clone(u.buffer.Bytes())
		u.buffer = bytes.Buffer{}
		return p.feedHTTP3Message(id, false, &push.response, b, fin, at)
	case 2:
		peer := &p.quicState[1-http3Side(client)]
		if !peer.settings {
			err := p.deferHTTP3(id, client, u.buffer.Bytes(), false, at)
			u.buffer = bytes.Buffer{}
			return err
		}
		d := &p.quicState[http3Side(client)]
		for u.buffer.Len() > 0 {
			n, err := d.table.encoderInstruction(u.buffer.Bytes(), peer.capacity)
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			if err != nil {
				return err
			}
			u.buffer.Next(n)
			if err := p.resumeHTTP3(client); err != nil {
				return err
			}
		}
	case 3:
		// Observe decoder feedback without sending acknowledgments or deriving table
		// eviction from capture order. The encoder stream is authoritative for both.
		for u.buffer.Len() > 0 {
			b := u.buffer.Bytes()
			bits := uint8(6)
			if b[0]&0x80 != 0 {
				bits = 7
			}
			value, n, err := qpackInteger(b, bits)
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			if err != nil {
				return err
			}
			if b[0]&0xc0 == 0 && value == 0 {
				return errQPACKEncoding
			}
			u.buffer.Next(n)
		}
	default:
		u.buffer = bytes.Buffer{} // Unknown unidirectional stream type.
	}
	return nil
}

func (p *HTTP3StreamParser) parseHTTP3Control(u *http3UniStream, client bool) error {
	d := &p.quicState[http3Side(client)]
	for u.buffer.Len() > 0 {
		if u.skip > 0 {
			n := min(u.skip, uint64(u.buffer.Len()))
			u.buffer.Next(int(n))
			u.skip -= n
			continue
		}
		b := u.buffer.Bytes()
		typ, n := readVarInt(b)
		if n == 0 {
			return nil
		}
		length, k := readVarInt(b[n:])
		if k == 0 {
			return nil
		}
		header := n + k
		if !d.settings && typ != HTTP3FrameSettings {
			return errHTTP3Message
		}
		switch typ {
		case HTTP3FrameData, HTTP3FrameHeaders, HTTP3FramePushPromise, 2, 6, 8, 9:
			return errHTTP3Message
		case HTTP3FrameSettings, HTTP3FrameGoAway, HTTP3FrameMaxPushID, HTTP3FrameCancelPush:
		default:
			u.buffer.Next(header)
			u.skip = length
			continue
		}
		if length > maxHTTP3FieldBytes {
			return ErrHTTP3ResourceLimit
		}
		if length > uint64(len(b)-header) {
			return nil
		}
		payload := b[header : header+int(length)]
		if typ == HTTP3FrameSettings {
			if d.settings {
				return errHTTP3Message
			}
			d.fieldLimit = (1 << 62) - 1
			seen := make(map[uint64]bool)
			for len(payload) > 0 {
				key, n := readVarInt(payload)
				if n == 0 {
					return errHTTP3Message
				}
				value, k := readVarInt(payload[n:])
				if k == 0 {
					return errHTTP3Message
				}
				payload = payload[n+k:]
				if seen[key] || key >= 2 && key <= 5 {
					return errHTTP3Message
				}
				seen[key] = true
				switch key {
				case 8, 0x33:
					if value > 1 {
						return errHTTP3Message
					}
				case HTTP3SettingsQPackMaxTableCapacity:
					d.capacity = value
				case HTTP3SettingsQPackBlockedStreams:
					d.blocked = value
				case HTTP3SettingsMaxFieldSectionSize:
					d.fieldLimit = value
				}
			}
			d.settings = true
			// Replay bytes in their original order, including encoder/header interleaving,
			// when the peer SETTINGS themselves were held behind a late traffic secret.
			sender := &p.quicState[1-http3Side(client)]
			pending := sender.deferred
			sender.deferred = nil
			for i, event := range pending {
				if event.id&2 == 0 {
					s := p.quicStreams[event.id]
					m := &s.request
					if client {
						m = &s.response
					}
					m.deferred = false
				} else if uni := p.quicUni[event.id]; uni.kind == 1 {
					p.quicPush[uni.pushID].response.deferred = false
				}
				if err := p.feedHTTP3(event.id, !client, event.data, event.fin, event.at); err != nil {
					return err
				}
				pending[i] = http3Deferred{}
			}
		} else {
			value, n := readVarInt(payload)
			if n == 0 || n != len(payload) {
				return errHTTP3Message
			}
			switch typ {
			case HTTP3FrameGoAway:
				if !client && value%4 != 0 || d.hasGoAway && value > d.goAway {
					return errHTTP3Message
				}
				d.goAway = value
				d.hasGoAway = true
			case HTTP3FrameMaxPushID:
				if !client || d.hasMaxPush && value < d.maxPush {
					return errHTTP3Message
				}
				d.maxPush = value
				d.hasMaxPush = true
				for pushID, push := range p.quicPush {
					if pushID > value {
						return errHTTP3Message
					}
					if err := p.completeHTTP3Push(push); err != nil {
						return err
					}
				}
			case HTTP3FrameCancelPush:
				push, err := p.getHTTP3Push(value)
				if err != nil {
					return err
				}
				push.canceled = true
				push.informational = nil
				if push.streamKnown {
					p.discardHTTP3Deferred(push.streamID, false)
				}
				push.response = http3QUICMessage{finished: true}
			}
		}
		u.buffer.Next(header + int(length))
	}
	return nil
}

func (p *HTTP3StreamParser) getHTTP3Push(id uint64) (*http3Push, error) {
	grant := &p.quicState[0]
	if grant.hasMaxPush && id > grant.maxPush {
		return nil, errHTTP3Message
	}
	push := p.quicPush[id]
	if push == nil {
		if len(p.quicPush) >= maxHTTP3Pushes {
			return nil, ErrHTTP3ResourceLimit
		}
		push = &http3Push{since: time.Now()}
		p.quicPush[id] = push
	}
	return push, nil
}
func (p *HTTP3StreamParser) promiseHTTP3(id, parent uint64, fields []qpackField, at time.Time) error {
	request, err := parseHTTP3Headers(fields, true, false)
	if err != nil {
		return err
	}
	push, err := p.getHTTP3Push(id)
	if err != nil {
		return err
	}
	if push.promised {
		if request.method != push.request.method || request.path != push.request.path || request.scheme != push.request.scheme || request.authority != push.request.authority || !http3HeadersEqual(request.headers, push.request.headers) {
			return errHTTP3Message
		}
		return nil
	}
	request.at = at
	push.request = request
	push.parent = parent
	push.promised = true
	return p.completeHTTP3Push(push)
}
func http3HeadersEqual(a, b http.Header) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		w := b[k]
		if len(v) != len(w) {
			return false
		}
		for i := range v {
			if v[i] != w[i] {
				return false
			}
		}
	}
	return true
}
func (p *HTTP3StreamParser) completeHTTP3Push(push *http3Push) error {
	if push.canceled || !push.promised || !push.streamKnown || !p.quicState[0].hasMaxPush {
		return nil
	}
	push.since = time.Time{}
	p.emitHTTP3PushInformation(push)
	if push.response.deferred {
		return nil
	}
	return p.parseHTTP3Message(push.streamID, false, &push.response)
}
func (p *HTTP3StreamParser) emitHTTP3PushInformation(push *http3Push) {
	for i := range push.informational {
		p.emitHTTP3(push.streamID, false, &push.informational[i], "informational")
	}
	push.informational = nil
}
func (p *HTTP3StreamParser) resumeHTTP3(client bool) error {
	for id, s := range p.quicStreams {
		m := &s.request
		if !client {
			m = &s.response
		}
		if !m.blockedAt.IsZero() && !m.deferred && !m.finished {
			if err := p.parseHTTP3Message(id, client, m); err != nil {
				return err
			}
		}
	}
	if !client {
		for _, push := range p.quicPush {
			if push.streamKnown && !push.response.blockedAt.IsZero() && !push.response.deferred && !push.canceled {
				if err := p.parseHTTP3Message(push.streamID, false, &push.response); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func (p *HTTP3StreamParser) checkHTTP3Blocked(client bool) error {
	peer := &p.quicState[1-http3Side(client)]
	count := 0
	for _, s := range p.quicStreams {
		m := &s.request
		if !client {
			m = &s.response
		}
		if !m.blockedAt.IsZero() && (!m.deferred || !peer.settings) {
			count++
		}
	}
	if !client {
		for _, push := range p.quicPush {
			if !push.response.blockedAt.IsZero() && (!push.response.deferred || !peer.settings) {
				count++
			}
		}
	}
	limit := uint64(maxHTTP3BlockedStreams)
	if peer.settings {
		limit = min(limit, peer.blocked)
	}
	if uint64(count) > limit {
		return ErrHTTP3ResourceLimit
	}
	return nil
}
func (p *HTTP3StreamParser) checkHTTP3Bounds() error {
	total := 0
	messageBytes := func(m *http3QUICMessage) int {
		n := m.buffer.Cap() + m.body.Cap() + len(m.method) + len(m.path) + len(m.scheme) + len(m.authority) + len(m.status)
		for _, h := range []http.Header{m.headers, m.trailers} {
			for k, v := range h {
				for _, s := range v {
					n += len(k) + len(s) + 32
				}
			}
		}
		return n
	}
	for _, s := range p.quicStreams {
		total += messageBytes(&s.request) + messageBytes(&s.response)
	}
	for _, u := range p.quicUni {
		total += u.buffer.Cap()
	}
	for _, push := range p.quicPush {
		total += messageBytes(&push.request) + messageBytes(&push.response)
		for i := range push.informational {
			total += messageBytes(&push.informational[i])
		}
	}
	for i := range p.quicState {
		for _, event := range p.quicState[i].deferred {
			total += len(event.data)
		}
	}
	if total > maxHTTP3ConnectionBytes {
		return ErrHTTP3ResourceLimit
	}
	if err := p.checkHTTP3Blocked(true); err != nil {
		return err
	}
	return p.checkHTTP3Blocked(false)
}

// PendingSince exposes only the real-time start of unresolved compression/push
// state. The QUIC worker applies the same finite wait policy as late secrets.
func (p *HTTP3StreamParser) PendingSince() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	var since time.Time
	add := func(t time.Time) {
		if !t.IsZero() && (since.IsZero() || t.Before(since)) {
			since = t
		}
	}
	for _, s := range p.quicStreams {
		add(s.request.blockedAt)
		add(s.response.blockedAt)
	}
	for _, push := range p.quicPush {
		if !push.canceled {
			add(push.since)
			add(push.response.blockedAt)
		}
	}
	for i := range p.quicState {
		if len(p.quicState[i].deferred) > 0 {
			add(p.quicState[i].deferred[0].since)
		}
	}
	return since
}

// ResetQUICStream discards an incomplete direction without fabricating a final
// HTTP message. Critical streams cannot be reset. Completed messages stay final.
func (p *HTTP3StreamParser) ResetQUICStream(id uint64, client bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.quicErr != nil {
		return p.quicErr
	}
	if id&2 != 0 {
		u := p.quicUni[id]
		if u != nil && u.typed && (u.kind == 0 || u.kind == 2 || u.kind == 3) {
			p.quicErr = errHTTP3Message
			return p.quicErr
		}
		if u != nil {
			u.reset = true
			u.buffer = bytes.Buffer{}
			if u.pushKnown {
				push := p.quicPush[u.pushID]
				push.canceled = true
				push.informational = nil
				if push.streamKnown {
					p.discardHTTP3Deferred(push.streamID, false)
				}
				push.response = http3QUICMessage{finished: true}
			}
		}
	} else {
		s := p.quicStreams[id]
		if s != nil {
			m := &s.request
			if !client {
				m = &s.response
			}
			*m = http3QUICMessage{finished: true}
		}
	}
	p.discardHTTP3Deferred(id, client)
	return nil
}

func (p *HTTP3StreamParser) discardHTTP3Deferred(id uint64, client bool) {
	d := &p.quicState[http3Side(client)]
	kept := d.deferred[:0]
	for _, event := range d.deferred {
		if event.id != id {
			kept = append(kept, event)
		}
	}
	clear(d.deferred[len(kept):])
	d.deferred = kept
}
func (p *HTTP3StreamParser) closeHTTP3() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.quicClosed {
		return p.quicErr
	}
	p.quicClosed = true
	incomplete := false
	for _, s := range p.quicStreams {
		for _, m := range []*http3QUICMessage{&s.request, &s.response} {
			if m.started && !m.finished {
				incomplete = true
			}
		}
	}
	for id, u := range p.quicUni {
		if !u.reset && (!u.typed || u.buffer.Len() != 0 || u.skip != 0 || u.kind == 0 && !p.quicState[id&1].settings) {
			incomplete = true
		}
	}
	for _, push := range p.quicPush {
		if !push.canceled && (!push.promised || !push.streamKnown || !push.response.finished) {
			incomplete = true
		}
	}
	for i := range p.quicState {
		if len(p.quicState[i].deferred) > 0 {
			incomplete = true
		}
	}
	if p.quicErr == nil && incomplete {
		p.quicErr = errors.New("HTTP/3 input ended with incomplete streams or QPACK state")
	}
	p.quicStreams = nil
	p.quicUni = nil
	p.quicPush = nil
	p.quicState = [2]http3Direction{}
	return p.quicErr
}

func (p *HTTP3StreamParser) emitHTTP3(id uint64, client bool, m *http3QUICMessage, kind string) {
	if p.packetChan == nil {
		return
	}
	var text bytes.Buffer
	direction := "response"
	if client {
		direction = "request"
		fmt.Fprintf(&text, "%s %s HTTP/3.0\r\n", m.method, m.path)
	} else {
		fmt.Fprintf(&text, "HTTP/3.0 %s\r\n", m.status)
	}
	for name, values := range m.headers {
		for _, value := range values {
			fmt.Fprintf(&text, "%s: %s\r\n", name, value)
		}
	}
	text.WriteString("\r\n")
	text.Write(m.body.Bytes())
	packet := types.NewDecryptedPacket(types.TransportProtocolUDP, "http/3", direction, text.Bytes(), m.at, p.addr)
	packet.WithMetadata("stream_id", id).WithMetadata("headers", m.headers)
	if len(m.trailers) > 0 {
		packet.WithMetadata("trailers", m.trailers)
	}
	if kind != "" {
		packet.WithMetadata("kind", kind)
	}
	if client {
		packet.WithMetadata("method", m.method).WithMetadata("path", m.path).WithMetadata("scheme", m.scheme).WithMetadata("authority", m.authority)
	} else {
		status, _ := strconv.Atoi(m.status)
		packet.WithMetadata("status", status)
		if id&2 == 0 {
			packet.WithMetadata("authority", p.quicStreams[id].request.authority)
		} else {
			pushID := p.quicUni[id].pushID
			push := p.quicPush[pushID]
			if kind == "" {
				packet.WithMetadata("kind", "push_response")
			}
			packet.WithMetadata("push_id", pushID).WithMetadata("parent_stream_id", push.parent).
				WithMetadata("method", push.request.method).WithMetadata("path", push.request.path).
				WithMetadata("scheme", push.request.scheme).WithMetadata("authority", push.request.authority).
				WithMetadata("promise_headers", push.request.headers.Clone())
		}
	}
	p.packetChan <- packet
}
