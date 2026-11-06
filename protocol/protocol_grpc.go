// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package protocol

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

var errGRPC = errors.New("invalid gRPC message stream")

// gRPC is an additional semantic view of HTTP/2 event bodies, like SSE. HTTP
// body chunks retain the exact envelope bytes. No protobuf schema is assumed.
type grpcMessages struct {
	encoding     string
	prefix       [5]byte
	prefixLen    int
	length       int
	data         []byte
	index, start uint64
	status       map[string]any
}

func isGRPC(media string) bool {
	return media == "application/grpc" || strings.HasPrefix(media, "application/grpc+")
}

func (g *grpcMessages) feed(b *eventBody, data []byte, offset uint64) error {
	for len(data) > 0 {
		if g.status != nil {
			return errGRPC
		}
		if g.prefixLen < 5 {
			if g.prefixLen == 0 {
				g.start = offset
			}
			n := copy(g.prefix[g.prefixLen:], data)
			g.prefixLen += n
			data = data[n:]
			offset += uint64(n)
			if g.prefixLen < 5 {
				return nil
			}
			if g.prefix[0] > 1 {
				return errGRPC
			}
			length := binary.BigEndian.Uint32(g.prefix[1:])
			if length > maxHTTPMessageBytes {
				return ErrHTTPEventLimit
			}
			g.length = int(length)
		}
		n := min(g.length-len(g.data), len(data))
		if n > 2*maxHTTPMessageBytes-b.out.grpcBuffered {
			return ErrHTTPEventLimit
		}
		g.data = append(g.data, data[:n]...)
		b.out.grpcBuffered += n
		data = data[n:]
		offset += uint64(n)
		if len(g.data) < g.length {
			return nil
		}
		message := g.data
		compressed := g.prefix[0] == 1
		if compressed {
			if g.encoding != "gzip" {
				return errors.New("unsupported gRPC message compression")
			}
			z, err := gzip.NewReader(bytes.NewReader(g.data))
			if err != nil {
				return errGRPC
			}
			message, err = io.ReadAll(io.LimitReader(z, maxHTTPMessageBytes+1))
			_ = z.Close()
			if len(message) > maxHTTPMessageBytes {
				return ErrHTTPEventLimit
			}
			if err != nil {
				return errGRPC
			}
		}
		b.emit("grpc_message", message, map[string]any{"message_index": g.index, "compressed": compressed, "grpc_encoding": g.encoding, "wire_length": uint32(g.length)}, g.start)
		g.index++
		g.release(b)
		g.prefixLen = 0
	}
	return nil
}
func (g *grpcMessages) release(b *eventBody) {
	b.out.grpcBuffered -= len(g.data)
	g.data = nil
}
func (g *grpcMessages) complete() error {
	if g.prefixLen != 0 {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (g *grpcMessages) trailers(h http.Header) (map[string]any, error) {
	if err := g.complete(); err != nil {
		return nil, err
	}
	if g.status != nil || len(h.Values("Grpc-Status")) != 1 {
		return nil, errGRPC
	}
	value := h.Get("Grpc-Status")
	// Keep the received status rather than interpreting protobuf status-details.
	n, err := strconv.ParseUint(value, 10, 32)
	if err != nil || strconv.FormatUint(n, 10) != value {
		return nil, errGRPC
	}
	message := h.Get("Grpc-Message")
	if decoded, err := url.PathUnescape(message); err == nil {
		message = decoded
	}
	g.status = map[string]any{"grpc_status": uint32(n), "grpc_message": message}
	return g.status, nil
}
