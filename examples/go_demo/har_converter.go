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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cfc4n/ecapture_decryptor/types"
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
	defer file.Close()

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
	pairs := make([]HTTPPair, 0)
	pendingRequests := make(map[string]*types.DecryptedPacket)

	for _, pkt := range packets {
		// 只处理 HTTP 协议
		if !strings.HasPrefix(pkt.Protocol, "http") {
			continue
		}

		connID := pkt.ConnectionID()
		if pkt.Direction == "request" {
			// 保存请求，等待响应
			pendingRequests[connID] = pkt
		} else if pkt.Direction == "response" {
			// 找到对应的请求
			if req, ok := pendingRequests[connID]; ok {
				pairs = append(pairs, HTTPPair{
					Request:  req,
					Response: pkt,
				})
				delete(pendingRequests, connID)
			}
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
	defer httpReq.Body.Close()

	reqBody, _ := io.ReadAll(httpReq.Body)

	// 解析 HTTP 响应
	httpResp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(resp.Data)), httpReq)
	if err != nil {
		return HAREntry{}, fmt.Errorf("parse response: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, _ := io.ReadAll(httpResp.Body)

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
	if !strings.HasPrefix(fullURL, "http") {
		scheme := "https"
		if httpReq.TLS == nil {
			scheme = "http"
		}
		fullURL = fmt.Sprintf("%s://%s%s", scheme, httpReq.Host, httpReq.URL.String())
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
			Content: HARContent{
				Size:     len(respBody),
				MimeType: httpResp.Header.Get("Content-Type"),
				Text:     string(respBody),
			},
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
