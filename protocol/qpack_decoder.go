// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package protocol

import (
	"errors"
	"io"

	"golang.org/x/net/http2/hpack"
)

const (
	maxQPACKTableBytes     = 64 << 10
	maxHTTP3FieldBytes     = 64 << 10
	maxHTTP3Fields         = 1024
	maxHTTP3BlockedStreams = 64
)

var (
	// ErrHTTP3ResourceLimit identifies bounded HTTP/3 parser state exhaustion.
	ErrHTTP3ResourceLimit = errors.New("HTTP/3 resource limit exceeded")
	errQPACKBlocked       = errors.New("QPACK field section awaits encoder state or SETTINGS")
	errQPACKEncoding      = errors.New("invalid QPACK encoding")
)

type qpackField struct{ name, value string }
type qpackDynamicTable struct {
	entries                  []qpackField // oldest first; absolute indices never reset on eviction
	inserted, capacity, size uint64
}
type qpackSection struct {
	required, base uint64
	prefix         int
	initialized    bool
}

// QPACK uses HPACK-style prefixed integers, not QUIC variable-length integers.
func qpackInteger(data []byte, bits uint8) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	mask := uint64(1<<bits) - 1
	n := uint64(data[0]) & mask
	if n < mask {
		return n, 1, nil
	}
	for i, shift := 1, uint(0); ; i, shift = i+1, shift+7 {
		if i >= len(data) {
			return 0, 0, io.ErrUnexpectedEOF
		}
		b := uint64(data[i] & 0x7f)
		if shift >= 62 || b > ((1<<62)-1-n)>>shift {
			return 0, 0, errQPACKEncoding
		}
		n += b << shift
		if data[i]&0x80 == 0 {
			return n, i + 1, nil
		}
	}
}

type qpackString struct {
	wire    []byte
	huffman bool
}

func qpackStringAt(data []byte, bits uint8, huffman byte) (qpackString, int, error) {
	n, prefix, err := qpackInteger(data, bits)
	if err != nil {
		return qpackString{}, 0, err
	}
	if n > maxHTTP3FieldBytes {
		return qpackString{}, 0, ErrHTTP3ResourceLimit
	}
	if n > uint64(len(data)-prefix) {
		return qpackString{}, 0, io.ErrUnexpectedEOF
	}
	return qpackString{wire: data[prefix : prefix+int(n)], huffman: data[0]&huffman != 0}, prefix + int(n), nil
}
func (s qpackString) decode() (string, error) {
	if !s.huffman {
		return string(s.wire), nil
	}
	v, err := hpack.HuffmanDecodeToString(s.wire)
	if err != nil {
		return "", errQPACKEncoding
	}
	if len(v) > maxHTTP3FieldBytes {
		return "", ErrHTTP3ResourceLimit
	}
	return v, nil
}
func qpackStatic(index uint64) (qpackField, error) {
	if index >= uint64(len(qpackStaticTable)) {
		return qpackField{}, errQPACKEncoding
	}
	v := qpackStaticTable[index]
	return qpackField{name: v.name, value: v.value}, nil
}
func (d *qpackDynamicTable) at(index uint64) (qpackField, error) {
	oldest := d.inserted - uint64(len(d.entries))
	if index < oldest || index >= d.inserted {
		return qpackField{}, errQPACKEncoding
	}
	return d.entries[index-oldest], nil
}
func (d *qpackDynamicTable) relative(base, index uint64) (qpackField, uint64, error) {
	if index >= base {
		return qpackField{}, 0, errQPACKEncoding
	}
	absolute := base - index - 1
	f, err := d.at(absolute)
	return f, absolute, err
}
func (d *qpackDynamicTable) evict(needed uint64) {
	for d.size+needed > d.capacity && len(d.entries) > 0 {
		old := d.entries[0]
		d.size -= uint64(len(old.name) + len(old.value) + 32)
		d.entries[0] = qpackField{}
		d.entries = d.entries[1:]
	}
}
func (d *qpackDynamicTable) insert(f qpackField) error {
	size := uint64(len(f.name) + len(f.value) + 32)
	if size > d.capacity || d.inserted == (1<<62)-1 {
		return errQPACKEncoding
	}
	d.evict(size)
	d.entries = append(d.entries, f)
	d.size += size
	d.inserted++
	return nil
}

// Consume exactly one complete encoder instruction. The caller retries blocked
// sections after each insertion, before a later instruction can evict an entry.
func (d *qpackDynamicTable) encoderInstruction(data []byte, maximum uint64) (int, error) {
	if len(data) == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	first := data[0]
	var f qpackField
	var consumed int
	switch {
	case first&0x80 != 0: // Insert with name reference.
		index, n, err := qpackInteger(data, 6)
		if err != nil {
			return 0, err
		}
		value, m, err := qpackStringAt(data[n:], 7, 0x80)
		if err != nil {
			return 0, err
		}
		if first&0x40 != 0 {
			f, err = qpackStatic(index)
		} else {
			f, _, err = d.relative(d.inserted, index)
		}
		if err != nil {
			return 0, err
		}
		f.value, err = value.decode()
		if err != nil {
			return 0, err
		}
		consumed = n + m
	case first&0x40 != 0: // Insert with literal name.
		name, n, err := qpackStringAt(data, 5, 0x20)
		if err != nil {
			return 0, err
		}
		value, m, err := qpackStringAt(data[n:], 7, 0x80)
		if err != nil {
			return 0, err
		}
		f.name, err = name.decode()
		if err != nil {
			return 0, err
		}
		f.value, err = value.decode()
		if err != nil {
			return 0, err
		}
		consumed = n + m
	case first&0x20 != 0: // Set capacity, constrained by the peer's SETTINGS.
		capacity, n, err := qpackInteger(data, 5)
		if err != nil {
			return 0, err
		}
		if capacity > maximum {
			return 0, errQPACKEncoding
		}
		if capacity > maxQPACKTableBytes {
			return 0, ErrHTTP3ResourceLimit
		}
		d.capacity = capacity
		d.evict(0)
		return n, nil
	default: // Duplicate relative to the current insert count.
		index, n, err := qpackInteger(data, 5)
		if err != nil {
			return 0, err
		}
		f, _, err = d.relative(d.inserted, index)
		if err != nil {
			return 0, err
		}
		consumed = n
	}
	return consumed, d.insert(f)
}

func (d *qpackDynamicTable) sectionPrefix(data []byte, maximum uint64, settingsKnown bool) (qpackSection, error) {
	encoded, n, err := qpackInteger(data, 8)
	if err != nil {
		return qpackSection{}, errQPACKEncoding
	}
	if len(data) <= n {
		return qpackSection{}, errQPACKEncoding
	}
	negative := data[n]&0x80 != 0
	delta, m, err := qpackInteger(data[n:], 7)
	if err != nil {
		return qpackSection{}, errQPACKEncoding
	}
	required := uint64(0)
	if encoded != 0 {
		if !settingsKnown {
			return qpackSection{}, errQPACKBlocked
		}
		entries := maximum / 32
		full := 2 * entries
		if full == 0 || encoded > full {
			return qpackSection{}, errQPACKEncoding
		}
		upper := d.inserted + entries
		required = upper/full*full + encoded - 1
		if required > upper {
			if required <= full {
				return qpackSection{}, errQPACKEncoding
			}
			required -= full
		}
		if required == 0 {
			return qpackSection{}, errQPACKEncoding
		}
	}
	base := required + delta
	if negative {
		if delta >= required {
			return qpackSection{}, errQPACKEncoding
		}
		base = required - delta - 1
	}
	if base >= (1 << 62) {
		return qpackSection{}, errQPACKEncoding
	}
	return qpackSection{required: required, base: base, prefix: n + m, initialized: true}, nil
}

func (d *qpackDynamicTable) decodeSection(data []byte, s qpackSection) ([]qpackField, error) {
	if s.required > d.inserted {
		return nil, errQPACKBlocked
	}
	data = data[s.prefix:]
	var fields []qpackField
	var largestReference uint64
	size := 0
	for len(data) > 0 {
		first := data[0]
		var f qpackField
		var index uint64
		var n int
		var err error
		dynamic := false
		switch {
		case first&0x80 != 0:
			index, n, err = qpackInteger(data, 6)
			if err == nil {
				if first&0x40 != 0 {
					f, err = qpackStatic(index)
				} else {
					f, index, err = d.relative(s.base, index)
					dynamic = true
				}
			}
		case first&0x40 != 0:
			index, n, err = qpackInteger(data, 4)
			if err == nil {
				if first&0x10 != 0 {
					f, err = qpackStatic(index)
				} else {
					f, index, err = d.relative(s.base, index)
					dynamic = true
				}
			}
		case first&0x20 != 0:
			var name qpackString
			name, n, err = qpackStringAt(data, 3, 0x08)
			if err == nil {
				f.name, err = name.decode()
			}
		default:
			bits := uint8(3)
			if first&0x10 != 0 {
				bits = 4
			}
			index, n, err = qpackInteger(data, bits)
			if err == nil {
				index += s.base
				f, err = d.at(index)
				dynamic = true
			}
		}
		if err != nil {
			return nil, err
		}
		if dynamic {
			if index >= s.required {
				return nil, errQPACKEncoding
			}
			largestReference = max(largestReference, index+1)
		}
		data = data[n:]
		if first&0x80 == 0 && first&0xf0 != 0x10 {
			value, m, err := qpackStringAt(data, 7, 0x80)
			if err != nil {
				return nil, err
			}
			f.value, err = value.decode()
			if err != nil {
				return nil, err
			}
			data = data[m:]
		}
		size += len(f.name) + len(f.value) + 32
		if size > maxHTTP3FieldBytes || len(fields) >= maxHTTP3Fields {
			return nil, ErrHTTP3ResourceLimit
		}
		fields = append(fields, f)
	}
	if largestReference != s.required {
		return nil, errQPACKEncoding
	}
	return fields, nil
}
