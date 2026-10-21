// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gojue/ecapture_decryptor/types"
)

func testGzipBody(t *testing.T, body []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := gzip.NewWriter(&output)
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestConvertToHAREntryDecodesGzipText(t *testing.T) {
	body := []byte("# Robots.txt\nUser-agent: *\nAllow: /\n")
	compressed := testGzipBody(t, body)
	connection := types.ConnectionKey{
		SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2),
		SrcPort: 12345, DstPort: 443, Proto: "tcp",
	}
	request := types.NewDecryptedPacket("tcp", "http/1.1", "request",
		[]byte("GET /robots.txt HTTP/1.1\r\nHost: example.test\r\n\r\n"),
		time.Unix(1, 0), connection)
	responseBytes := append([]byte(fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n",
		len(compressed))), compressed...)
	response := types.NewDecryptedPacket("tcp", "http/1.1", "response",
		responseBytes, time.Unix(2, 0), connection)

	entry, err := convertToHAREntry(HTTPPair{Request: request, Response: response})
	if err != nil {
		t.Fatal(err)
	}
	if entry.Request.URL != "https://example.test/robots.txt" || entry.Response.Status != 200 {
		t.Fatalf("wrong exchange: %s, status %d", entry.Request.URL, entry.Response.Status)
	}
	content := entry.Response.Content
	if content.Text != string(body) || content.Encoding != "" || content.Size != len(body) {
		t.Fatalf("gzip text was not decoded: %+v", content)
	}
	if entry.Response.BodySize != len(compressed) || content.Compression != len(body)-len(compressed) {
		t.Fatalf("wrong wire/decoded sizes: bodySize=%d content=%+v", entry.Response.BodySize, content)
	}
}

func TestHARResponseContentPreservesBinaryAndUnknownEncodings(t *testing.T) {
	t.Run("gzip binary", func(t *testing.T) {
		png := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0, 0, 0}
		compressed := testGzipBody(t, png)
		content := harResponseContent(compressed, http.Header{
			"Content-Type":     {"image/png"},
			"Content-Encoding": {"gzip"},
		})
		decoded, err := base64.StdEncoding.DecodeString(content.Text)
		if err != nil || content.Encoding != "base64" || !bytes.Equal(decoded, png) || content.Size != len(png) {
			t.Fatalf("binary body was corrupted: content=%+v err=%v", content, err)
		}
	})

	t.Run("invalid gzip", func(t *testing.T) {
		body := []byte{0x1f, 0x8b, 0x08, 0xff}
		content := harResponseContent(body, http.Header{
			"Content-Type":     {"text/plain"},
			"Content-Encoding": {"gzip"},
		})
		decoded, err := base64.StdEncoding.DecodeString(content.Text)
		if err != nil || content.Encoding != "base64" || !bytes.Equal(decoded, body) || content.Size != len(body) {
			t.Fatalf("invalid gzip bytes were lost: content=%+v err=%v", content, err)
		}
	})

	t.Run("unsupported coding", func(t *testing.T) {
		body := []byte{0x00, 0xff, 0x10}
		content := harResponseContent(body, http.Header{
			"Content-Type":     {"text/plain"},
			"Content-Encoding": {"br"},
		})
		decoded, err := base64.StdEncoding.DecodeString(content.Text)
		if err != nil || content.Encoding != "base64" || !bytes.Equal(decoded, body) {
			t.Fatalf("unsupported coding bytes were lost: content=%+v err=%v", content, err)
		}
	})
}

func TestHARResponseContentUsesTextTypeWhenServerSendsTwo(t *testing.T) {
	content := harResponseContent([]byte("Hello TLS!"), http.Header{
		"Content-Type": {"application/octet-stream", "text/plain"},
	})
	if content.MimeType != "text/plain" || content.Text != "Hello TLS!" || content.Encoding != "" {
		t.Fatalf("readable text was encoded as binary: %+v", content)
	}
}

func TestPairHTTPPacketsMatchesHTTP1ByConnectionAndHTTP2ByStream(t *testing.T) {
	http1Connection := types.ConnectionKey{SrcPort: 12345, DstPort: 443, Proto: "tcp"}
	http2Connection := types.ConnectionKey{SrcPort: 12346, DstPort: 443, Proto: "tcp"}
	packet := func(connection types.ConnectionKey, protocol, direction string) *types.DecryptedPacket {
		return types.NewDecryptedPacket("tcp", protocol, direction, nil, time.Time{}, connection)
	}
	request10 := packet(http1Connection, "http/1.0", "request")
	request11 := packet(http1Connection, "http/1.1", "request")
	response10 := packet(http1Connection, "http/1.1", "response")
	response11 := packet(http1Connection, "http/1.1", "response")
	request2a := packet(http2Connection, "http/2", "request").WithMetadata("stream_id", uint64(1))
	request2b := packet(http2Connection, "http/2", "request").WithMetadata("stream_id", uint64(3))
	response2a := packet(http2Connection, "http/2", "response").WithMetadata("stream_id", uint64(1))
	response2b := packet(http2Connection, "http/2", "response").WithMetadata("stream_id", uint64(3))

	pairs := pairHTTPPackets([]*types.DecryptedPacket{
		request10, request11, request2a, request2b,
		response2b, response10, response2a, response11,
	})
	if len(pairs) != 4 {
		t.Fatalf("got %d pairs, want 4", len(pairs))
	}
	actual := make(map[*types.DecryptedPacket]*types.DecryptedPacket)
	for _, pair := range pairs {
		actual[pair.Request] = pair.Response
	}
	for request, response := range map[*types.DecryptedPacket]*types.DecryptedPacket{
		request10: response10, request11: response11,
		request2a: response2a, request2b: response2b,
	} {
		if actual[request] != response {
			t.Fatalf("request %p paired with %p, want %p", request, actual[request], response)
		}
	}
}
