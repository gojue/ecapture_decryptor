// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

// har_converter.go - 将 DecryptedPacket 转换为 HAR 格式
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gojue/ecapture_decryptor/types"
)

// saveAsHAR 将解密的包保存为 HAR 格式
func saveAsHAR(packets []*types.DecryptedPacket, filename string, verbose bool) error {
	// 将 packets 配对成 request/response
	pairs := pairHTTPPackets(packets)

	// 转换为 HAR entries
	entries := make([]HAREntry, 0, len(pairs))
	for _, pair := range pairs {
		if entry, err := convertToHAREntry(pair); err == nil {
			entries = append(entries, entry)
		} else if verbose {
			fmt.Printf("Warning: failed to convert pair to HAR: %v\n", err)
		}
	}

	// 创建 HAR 对象
	har := HAR{
		Log: HARLog{
			Version: "1.2",
			Creator: HARCreator{
				Name:    "eCapture Decryptor",
				Version: "2.0",
			},
			Entries: entries,
		},
	}

	// 写入文件
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(har)
}

// HTTPPair 表示一对 HTTP 请求和响应
type HTTPPair struct {
	Request  *types.DecryptedPacket
	Response *types.DecryptedPacket
}

// pairHTTPPackets 将请求和响应配对
func pairHTTPPackets(packets []*types.DecryptedPacket) []HTTPPair {
	type exchangeGroup struct {
		requests  []*types.DecryptedPacket
		responses []*types.DecryptedPacket
	}
	groups := make(map[string]*exchangeGroup)
	var groupOrder []string

	for _, pkt := range packets {
		if !strings.HasPrefix(pkt.Protocol, "http") {
			continue
		}
		// HTTP/2 and HTTP/3 may complete streams out of order. HTTP/1.x
		// responses follow request order within a connection, even when a
		// server replies with a different minor HTTP version.
		protocolKey := pkt.Protocol
		if strings.HasPrefix(protocolKey, "http/1.") {
			protocolKey = "http/1.x"
		}
		key := pkt.ConnectionID() + "/" + protocolKey
		if pkt.Protocol == "http/2" || pkt.Protocol == "http/3" {
			if streamID, ok := pkt.Metadata["stream_id"]; ok {
				key = fmt.Sprintf("%s/stream/%v", key, streamID)
			}
		}
		group := groups[key]
		if group == nil {
			group = &exchangeGroup{}
			groups[key] = group
			groupOrder = append(groupOrder, key)
		}
		switch pkt.Direction {
		case "request":
			group.requests = append(group.requests, pkt)
		case "response":
			group.responses = append(group.responses, pkt)
		}
	}
	pairs := make([]HTTPPair, 0)
	for _, key := range groupOrder {
		group := groups[key]
		for index := 0; index < len(group.requests) && index < len(group.responses); index++ {
			pairs = append(pairs, HTTPPair{
				Request:  group.requests[index],
				Response: group.responses[index],
			})
		}
	}

	return pairs
}

// convertToHAREntry 将一对 HTTP 请求/响应转换为 HAR Entry
func convertToHAREntry(pair HTTPPair) (HAREntry, error) {
	req := pair.Request
	resp := pair.Response

	// 解析 HTTP 请求
	httpReq, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(req.Data)))
	if err != nil {
		return HAREntry{}, fmt.Errorf("parse request: %w", err)
	}
	defer func() { _ = httpReq.Body.Close() }()

	reqBody, _ := io.ReadAll(httpReq.Body)

	// 解析 HTTP 响应
	httpResp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(resp.Data)), httpReq)
	if err != nil {
		return HAREntry{}, fmt.Errorf("parse response: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	respBody, _ := io.ReadAll(httpResp.Body)
	content := harResponseContent(respBody, httpResp.Header)

	// 构建 HAR Entry
	duration := resp.Timestamp.Sub(req.Timestamp).Milliseconds()
	if duration < 0 {
		duration = 0
	}

	// 构建请求头
	reqHeaders := make([]HARHeader, 0)
	for name, values := range httpReq.Header {
		for _, value := range values {
			reqHeaders = append(reqHeaders, HARHeader{
				Name:  name,
				Value: value,
			})
		}
	}

	// 构建响应头
	respHeaders := make([]HARHeader, 0)
	for name, values := range httpResp.Header {
		for _, value := range values {
			respHeaders = append(respHeaders, HARHeader{
				Name:  name,
				Value: value,
			})
		}
	}

	// 构建 URL
	fullURL := httpReq.URL.String()
	if !httpReq.URL.IsAbs() {
		authority := httpReq.Host
		if authority == "" {
			authority, _ = req.Metadata["authority"].(string)
		}
		if authority == "" {
			authority = net.JoinHostPort(req.DstIP, strconv.Itoa(int(req.DstPort)))
		}
		// Captured packets are decrypted TLS/QUIC traffic. ReadRequest sees
		// synthetic HTTP bytes, so httpReq.TLS cannot indicate the scheme.
		fullURL = "https://" + authority + httpReq.URL.RequestURI()
	}

	entry := HAREntry{
		StartedDateTime: req.Timestamp.Format(time.RFC3339Nano),
		Time:            float64(duration),
		Request: HARRequest{
			Method:      httpReq.Method,
			URL:         fullURL,
			HTTPVersion: httpReq.Proto,
			Cookies:     []HARCookie{},
			Headers:     reqHeaders,
			QueryString: []HARQueryString{},
			HeadersSize: -1,
			BodySize:    len(reqBody),
		},
		Response: HARResponse{
			Status:      httpResp.StatusCode,
			StatusText:  httpResp.Status,
			HTTPVersion: httpResp.Proto,
			Cookies:     []HARCookie{},
			Headers:     respHeaders,
			Content:     content,
			RedirectURL: "",
			HeadersSize: -1,
			BodySize:    len(respBody),
		},
		Cache: HARCache{},
		Timings: HARTimings{
			Blocked: -1,
			DNS:     -1,
			Connect: -1,
			Send:    0,
			Wait:    float64(duration),
			Receive: 0,
			SSL:     -1,
		},
		Connection: req.ConnectionID(),
	}

	// 从 metadata 中提取额外信息
	if serverIP, ok := req.Metadata["server_ip"].(string); ok {
		entry.ServerIPAddress = serverIP
	}
	if clientIP, ok := req.Metadata["client_ip"].(string); ok {
		entry.ClientIPAddress = clientIP
	}

	return entry, nil
}

// harResponseContent decodes HTTP content coding for readable text. HAR's
// bodySize still records the encoded size sent on the wire. Binary or unknown
// encodings are base64 encoded so JSON serialization cannot lose bytes.
func harResponseContent(body []byte, header http.Header) HARContent {
	content := HARContent{Size: len(body), MimeType: header.Get("Content-Type")}
	decoded := body
	switch strings.ToLower(strings.TrimSpace(header.Get("Content-Encoding"))) {
	case "", "identity":
	case "gzip", "x-gzip":
		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err == nil {
			decoded, err = io.ReadAll(reader)
			_ = reader.Close()
		}
		if err != nil {
			content.Text = base64.StdEncoding.EncodeToString(body)
			content.Encoding = "base64"
			return content
		}
		content.Size = len(decoded)
		content.Compression = len(decoded) - len(body)
	default:
		content.Text = base64.StdEncoding.EncodeToString(body)
		content.Encoding = "base64"
		return content
	}

	textual := isTextualMediaType(content.MimeType)
	if !textual && utf8.Valid(decoded) {
		// Some servers send both a generic and a specific Content-Type.
		// Keep all original headers in the HAR, but select the text type
		// for content when the decoded bytes are valid UTF-8.
		for _, candidate := range header.Values("Content-Type") {
			if isTextualMediaType(candidate) {
				content.MimeType = candidate
				textual = true
				break
			}
		}
	}
	if textual && utf8.Valid(decoded) {
		content.Text = string(decoded)
	} else {
		content.Text = base64.StdEncoding.EncodeToString(decoded)
		content.Encoding = "base64"
	}
	return content
}

func isTextualMediaType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return false
	}
	return strings.HasPrefix(mediaType, "text/") ||
		mediaType == "application/json" || strings.HasSuffix(mediaType, "+json") ||
		mediaType == "application/xml" || strings.HasSuffix(mediaType, "+xml") ||
		mediaType == "application/javascript" || mediaType == "application/x-javascript" ||
		mediaType == "image/svg+xml"
}
