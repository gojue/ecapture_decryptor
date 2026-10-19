// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package ecapture_decryptor

import "fmt"

const maxOutOfOrderBytes = 4 << 20

// tcpDirection assembles payloads by TCP sequence number. Signed differences
// implement the normal TCP serial-number comparison within a 2 GiB window.
type tcpDirection struct {
	next         uint32
	started      bool
	pending      map[uint32][]byte
	pendingBytes int
}

func (d *tcpDirection) Start(next uint32) {
	d.next = next
	d.started = true
	if d.pending == nil {
		d.pending = make(map[uint32][]byte)
	}
}

func (d *tcpDirection) Push(seq uint32, payload []byte) ([][]byte, error) {
	if len(payload) == 0 {
		return nil, nil
	}
	if !d.started {
		d.Start(seq)
	}
	var ready [][]byte
	if int32(seq-d.next) > 0 {
		if old := d.pending[seq]; len(old) >= len(payload) {
			return nil, nil
		}
		if d.pendingBytes-len(d.pending[seq])+len(payload) > maxOutOfOrderBytes {
			return nil, fmt.Errorf("TCP reassembly pending limit exceeded")
		}
		d.pendingBytes -= len(d.pending[seq])
		d.pending[seq] = append([]byte(nil), payload...)
		d.pendingBytes += len(payload)
		return nil, nil
	}
	if skip := uint32(d.next - seq); skip < uint32(len(payload)) {
		part := append([]byte(nil), payload[skip:]...)
		ready = append(ready, part)
		d.next += uint32(len(part))
	}
	for {
		found := false
		for start, bytes := range d.pending {
			if int32(start-d.next) > 0 {
				continue
			}
			delete(d.pending, start)
			d.pendingBytes -= len(bytes)
			if skip := uint32(d.next - start); skip < uint32(len(bytes)) {
				part := bytes[skip:]
				ready = append(ready, part)
				d.next += uint32(len(part))
			}
			found = true
			break
		}
		if !found {
			break
		}
	}
	return ready, nil
}

type tcpConnection struct {
	client tcpDirection
	server tcpDirection
}
