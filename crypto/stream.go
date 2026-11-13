// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

package crypto

import (
	"bytes"
	"errors"
	"io"
	"sync"
)

// StreamBuffer is a thread-safe buffer for streaming TLS data
type StreamBuffer struct {
	buf       bytes.Buffer
	mu        sync.Mutex
	newData   chan struct{}
	Closed    chan struct{} // Exported for external waiting
	limit     int
	closeOnce sync.Once
}

const defaultStreamLimit = 8 << 20

func NewStreamBuffer() *StreamBuffer {
	return &StreamBuffer{
		newData: make(chan struct{}, 1),
		Closed:  make(chan struct{}),
		limit:   defaultStreamLimit,
	}
}

func (sb *StreamBuffer) Write(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	sb.mu.Lock()
	defer sb.mu.Unlock()

	select {
	case <-sb.Closed:
		return io.ErrClosedPipe
	default:
	}
	if sb.buf.Len()+len(data) > sb.limit {
		return errors.New("TLS stream buffer limit exceeded")
	}

	sb.buf.Write(data)

	// Signal new data available
	select {
	case sb.newData <- struct{}{}:
	default:
	}

	return nil
}

func (sb *StreamBuffer) Read(p []byte) (int, error) {
	for {
		sb.mu.Lock()
		if sb.buf.Len() >= len(p) {
			n, err := sb.buf.Read(p)
			sb.mu.Unlock()
			return n, err
		}
		sb.mu.Unlock()

		select {
		case <-sb.newData:
			// New data available, try again
		case <-sb.Closed:
			// Write and Close may both happen after the length check. Prefer the
			// final buffered bytes even when select chooses Close over newData.
			sb.mu.Lock()
			if sb.buf.Len() >= len(p) {
				n, err := sb.buf.Read(p)
				sb.mu.Unlock()
				return n, err
			}
			sb.mu.Unlock()
			return 0, io.EOF
		}
	}
}

func (sb *StreamBuffer) ReadExact(n int) ([]byte, error) {
	buf := make([]byte, n)
	totalRead := 0
	for totalRead < n {
		read, err := sb.Read(buf[totalRead:])
		if err != nil {
			return nil, err
		}
		totalRead += read
	}
	return buf, nil
}

func (sb *StreamBuffer) ReadRecord() ([]byte, error) {
	// Read TLS record header (5 bytes)
	header, err := sb.ReadExact(5)
	if err != nil {
		return nil, err
	}

	// Parse record length from header
	recordLen := int(header[3])<<8 | int(header[4])

	// Read record payload
	payload, err := sb.ReadExact(recordLen)
	if err != nil {
		return nil, err
	}

	// Return full record (header + payload)
	record := make([]byte, 5+recordLen)
	copy(record, header)
	copy(record[5:], payload)

	return record, nil
}

// unreadRecord preserves a coalesced handshake tail without consuming bytes
// from the following TLS record. It is used only by the serialized handshake
// reader; concurrent producers remain subject to the shared input budget.
func (sb *StreamBuffer) unreadRecord(record []byte) error {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if len(record) > sb.limit-sb.buf.Len() {
		return ErrHandshakeResourceLimit
	}
	var pending bytes.Buffer
	pending.Grow(len(record) + sb.buf.Len())
	pending.Write(record)
	pending.Write(sb.buf.Bytes())
	sb.buf = pending
	return nil
}

// TryReadRecord attempts to read a complete TLS record without blocking.
// Returns nil if not enough data is available.
func (sb *StreamBuffer) TryReadRecord() []byte {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	// Need at least 5 bytes for TLS record header
	if sb.buf.Len() < 5 {
		return nil
	}

	// Peek at header to get record length
	headerBytes := sb.buf.Bytes()[:5]
	recordLen := int(headerBytes[3])<<8 | int(headerBytes[4])
	totalLen := 5 + recordLen

	// Check if we have the complete record
	if sb.buf.Len() < totalLen {
		return nil
	}

	// Read the complete record
	record := make([]byte, totalLen)
	if _, err := sb.buf.Read(record); err != nil {
		return nil
	}
	return record
}

func (sb *StreamBuffer) Close() error {
	sb.closeOnce.Do(func() { close(sb.Closed) })
	return nil
}

// Len returns the number of bytes not yet consumed by record processing.
func (sb *StreamBuffer) Len() int {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.Len()
}

// Discard releases buffered storage after the closed stream has been drained.
// Close itself preserves unread bytes for final record processing.
func (sb *StreamBuffer) Discard() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.buf = bytes.Buffer{}
}
