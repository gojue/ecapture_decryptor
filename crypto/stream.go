// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

package crypto

import (
	"bytes"
	"io"
	"sync"
)

// StreamBuffer is a thread-safe buffer for streaming TLS data
type StreamBuffer struct {
	buf     bytes.Buffer
	mu      sync.Mutex
	newData chan struct{}
	Closed  chan struct{} // Exported for external waiting
}

func NewStreamBuffer() *StreamBuffer {
	return &StreamBuffer{
		newData: make(chan struct{}, 1),
		Closed:  make(chan struct{}),
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
	sb.buf.Read(record)
	return record
}

func (sb *StreamBuffer) Close() error {
	select {
	case <-sb.Closed:
		// Already closed
	default:
		close(sb.Closed)
	}
	return nil
}
