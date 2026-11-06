// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gojue/ecapture_decryptor/types"
)

const maxMQTTPacketBytes = 16 << 20
const maxMQTTTopics = 1024

var errMQTT = errors.New("invalid MQTT 3.1.1 packet")
var errMQTTVersion = errors.New("unsupported MQTT protocol version")

var mqttPacketNames = [...]string{
	"", "CONNECT", "CONNACK", "PUBLISH", "PUBACK", "PUBREC", "PUBREL", "PUBCOMP",
	"SUBSCRIBE", "SUBACK", "UNSUBSCRIBE", "UNSUBACK", "PINGREQ", "PINGRESP", "DISCONNECT",
}

type mqttDirection struct {
	buf   bytes.Buffer
	at    time.Time
	index uint64
}

// MQTTStreamParser decodes MQTT 3.1.1 control packets, beginning with CONNECT.
// Data is the exact complete wire packet. QoS identifiers and DUP are exposed;
// retransmitted application packets are not deduplicated and the parser does
// not simulate a broker's acknowledgement or exactly-once delivery state.
type MQTTStreamParser struct {
	mu           sync.Mutex
	addr         types.ConnectionKey
	ch           chan *types.DecryptedPacket
	at           time.Time
	directions   [2]mqttDirection
	connected    bool
	connack      bool
	refused      bool
	cleanSession bool
	disconnected bool
	closed       bool
	err          error
}

func NewMQTTStreamParser(addr types.ConnectionKey, ch chan *types.DecryptedPacket) *MQTTStreamParser {
	return &MQTTStreamParser{addr: addr, ch: ch}
}

func (p *MQTTStreamParser) SetPacketTime(at time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.at = at
}
func (p *MQTTStreamParser) FeedRequest(data []byte)  { p.feed(data, true) }
func (p *MQTTStreamParser) FeedResponse(data []byte) { p.feed(data, false) }
func (p *MQTTStreamParser) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}
func (p *MQTTStreamParser) fail(err error) {
	p.err = err
	for i := range p.directions {
		p.directions[i].buf = bytes.Buffer{}
	}
}
func (p *MQTTStreamParser) feed(data []byte, client bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil || p.closed {
		return
	}
	side := 1
	if client {
		side = 0
	}
	d := &p.directions[side]
	for len(data) > 0 {
		n := min(len(data), eventChunkSize, maxMQTTPacketBytes-d.buf.Len())
		if n == 0 {
			p.fail(ErrHTTPEventLimit)
			return
		}
		if d.buf.Len() == 0 {
			d.at = p.at
		}
		d.buf.Write(data[:n])
		data = data[n:]
		if err := p.parse(side); err != nil {
			p.fail(err)
			return
		}
		// Authenticated server records may arrive before a fragmented CONNECT.
		if client && p.connected {
			if err := p.parse(1); err != nil {
				p.fail(err)
				return
			}
		}
	}
}

// Validate the fixed header before buffering the declared payload. Remaining
// Length uses at most four base-128 bytes, with no nonminimal representation.
func mqttPacketLength(data []byte) (header, total int, err error) {
	if len(data) == 0 {
		return 0, 0, nil
	}
	typ, flags := data[0]>>4, data[0]&15
	if typ == 0 || typ >= 15 {
		return 0, 0, errMQTT
	}
	if typ == 3 {
		qos := (flags >> 1) & 3
		if qos == 3 || qos == 0 && flags&8 != 0 {
			return 0, 0, errMQTT
		}
	} else {
		want := byte(0)
		if typ == 6 || typ == 8 || typ == 10 {
			want = 2
		}
		if flags != want {
			return 0, 0, errMQTT
		}
	}
	remaining := 0
	for i := 1; i <= 4; i++ {
		if len(data) <= i {
			return 0, 0, nil
		}
		b := data[i]
		remaining |= int(b&127) << (7 * (i - 1))
		if b&128 == 0 {
			if i > 1 && b == 0 {
				return 0, 0, errMQTT
			}
			header = i + 1
			if remaining > maxMQTTPacketBytes-header {
				return 0, 0, ErrHTTPEventLimit
			}
			return header, header + remaining, nil
		}
	}
	return 0, 0, errMQTT
}
func (p *MQTTStreamParser) parse(side int) error {
	if side == 1 && !p.connected {
		return nil
	}
	d := &p.directions[side]
	for d.buf.Len() > 0 {
		data := d.buf.Bytes()
		header, total, err := mqttPacketLength(data)
		if err != nil {
			return err
		}
		if total == 0 || len(data) < total {
			return nil
		}
		typ := data[0] >> 4
		if side == 0 && (!p.connected && typ != 1 || p.disconnected) ||
			side == 1 && (p.refused || !p.connack && typ != 2) {
			return errMQTT
		}
		meta, err := p.packet(data[0], data[header:total], side == 0)
		if err != nil {
			return err
		}
		meta["packet_type"] = typ
		meta["packet_name"] = mqttPacketNames[typ]
		meta["message_index"] = d.index
		if offset, ok := meta["payload_offset"].(int); ok {
			meta["payload_offset"] = header + offset
		}
		if p.ch != nil {
			direction := "response"
			if side == 0 {
				direction = "request"
			}
			out := types.NewDecryptedPacket(types.TransportProtocolTCP, "mqtt", direction, bytes.Clone(data[:total]), d.at, p.addr)
			for k, v := range meta {
				out.WithMetadata(k, v)
			}
			p.ch <- out
		}
		d.index++
		d.buf.Next(total)
		d.at = p.at
	}
	return nil
}

func mqttBytes(data *[]byte) ([]byte, error) {
	if len(*data) < 2 {
		return nil, errMQTT
	}
	n := int(binary.BigEndian.Uint16(*data))
	if n > len(*data)-2 {
		return nil, errMQTT
	}
	value := (*data)[2 : 2+n]
	*data = (*data)[2+n:]
	return value, nil
}
func mqttString(data *[]byte) (string, error) {
	b, err := mqttBytes(data)
	if err != nil || !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return "", errMQTT
	}
	return string(b), nil
}
func mqttTopic(topic string, filter bool) bool {
	if topic == "" {
		return false
	}
	if !filter {
		return !strings.ContainsAny(topic, "+#")
	}
	levels := strings.Split(topic, "/")
	for i, level := range levels {
		if strings.Contains(level, "#") && (level != "#" || i != len(levels)-1) ||
			strings.Contains(level, "+") && level != "+" {
			return false
		}
	}
	return true
}
func mqttPacketID(data *[]byte) (uint16, error) {
	if len(*data) < 2 {
		return 0, errMQTT
	}
	id := binary.BigEndian.Uint16(*data)
	*data = (*data)[2:]
	if id == 0 {
		return 0, errMQTT
	}
	return id, nil
}
func (p *MQTTStreamParser) packet(first byte, data []byte, client bool) (map[string]any, error) {
	typ := first >> 4
	m := map[string]any{"kind": "control"}
	switch typ {
	case 1:
		if !client || p.connected {
			return nil, errMQTT
		}
		if err := p.connect(data, m); err != nil {
			return nil, err
		}
		p.connected = true
	case 2:
		if client || p.connack || len(data) != 2 || data[0]&0xfe != 0 || data[1] > 5 ||
			data[0] != 0 && (data[1] != 0 || p.cleanSession) {
			return nil, errMQTT
		}
		p.connack = true
		p.refused = data[1] != 0
		m["session_present"] = data[0] != 0
		m["return_code"] = data[1]
	case 3:
		size := len(data)
		topic, err := mqttString(&data)
		if err != nil || !mqttTopic(topic, false) {
			return nil, errMQTT
		}
		qos := (first >> 1) & 3
		if qos > 0 {
			id, err := mqttPacketID(&data)
			if err != nil {
				return nil, err
			}
			m["packet_id"] = id
		}
		m["kind"], m["topic"] = "publish", topic
		m["qos"], m["dup"], m["retain"] = qos, first&8 != 0, first&1 != 0
		m["payload_offset"], m["payload_length"] = size-len(data), len(data)
	case 4, 5, 6, 7, 11:
		if len(data) != 2 || typ == 11 && client {
			return nil, errMQTT
		}
		id, err := mqttPacketID(&data)
		if err != nil {
			return nil, err
		}
		m["packet_id"] = id
	case 8, 10:
		if !client {
			return nil, errMQTT
		}
		id, err := mqttPacketID(&data)
		if err != nil || len(data) == 0 {
			return nil, errMQTT
		}
		m["packet_id"] = id
		var topics []string
		var qos []int
		for len(data) > 0 {
			if len(topics) >= maxMQTTTopics {
				return nil, ErrHTTPEventLimit
			}
			topic, err := mqttString(&data)
			if err != nil || !mqttTopic(topic, true) {
				return nil, errMQTT
			}
			topics = append(topics, topic)
			if typ == 8 {
				if len(data) == 0 || data[0] > 2 {
					return nil, errMQTT
				}
				qos = append(qos, int(data[0]))
				data = data[1:]
			}
		}
		m["topics"] = topics
		if typ == 8 {
			m["kind"], m["requested_qos"] = "subscribe", qos
		} else {
			m["kind"] = "unsubscribe"
		}
	case 9:
		if client {
			return nil, errMQTT
		}
		id, err := mqttPacketID(&data)
		if err != nil || len(data) == 0 {
			return nil, errMQTT
		}
		if len(data) > maxMQTTTopics {
			return nil, ErrHTTPEventLimit
		}
		codes := make([]int, len(data))
		for i, code := range data {
			if code > 2 && code != 128 {
				return nil, errMQTT
			}
			codes[i] = int(code)
		}
		m["packet_id"], m["return_codes"] = id, codes
	case 12, 13, 14:
		if len(data) != 0 || client != (typ != 13) {
			return nil, errMQTT
		}
		if typ == 14 {
			p.disconnected = true
		}
	}
	return m, nil
}
func (p *MQTTStreamParser) connect(data []byte, m map[string]any) error {
	name, err := mqttString(&data)
	if err != nil || len(data) < 4 {
		return errMQTT
	}
	if name != "MQTT" || data[0] != 4 {
		return errMQTTVersion
	}
	flags := data[1]
	will := flags&4 != 0
	if flags&1 != 0 || !will && flags&0x38 != 0 || will && (flags>>3)&3 == 3 || flags&0x40 != 0 && flags&0x80 == 0 {
		return errMQTT
	}
	m["protocol_level"], m["keep_alive"] = data[0], binary.BigEndian.Uint16(data[2:4])
	data = data[4:]
	clientID, err := mqttString(&data)
	if err != nil || clientID == "" && flags&2 == 0 {
		return errMQTT
	}
	if will {
		topic, err := mqttString(&data)
		if err != nil || !mqttTopic(topic, false) {
			return errMQTT
		}
		if _, err := mqttBytes(&data); err != nil {
			return err
		}
	}
	if flags&0x80 != 0 {
		if _, err := mqttString(&data); err != nil {
			return err
		}
	}
	if flags&0x40 != 0 {
		if _, err := mqttBytes(&data); err != nil {
			return err
		}
	}
	if len(data) != 0 {
		return errMQTT
	}
	p.cleanSession = flags&2 != 0
	m["client_id"], m["clean_session"], m["will"] = clientID, p.cleanSession, will
	return nil
}

// Flush accepts EOF at a complete packet boundary, even if capture ended before
// CONNACK or acknowledgements. It does not infer endpoint delivery outcomes.
func (p *MQTTStreamParser) Flush() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	if p.err == nil && (!p.connected || p.directions[0].buf.Len()+p.directions[1].buf.Len() != 0) {
		p.err = io.ErrUnexpectedEOF
	}
	for i := range p.directions {
		p.directions[i].buf = bytes.Buffer{}
	}
}
func (p *MQTTStreamParser) Close() error { p.Flush(); return p.Err() }

var _ types.StreamParserInterface = (*MQTTStreamParser)(nil)
