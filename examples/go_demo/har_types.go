// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

// har_types.go - HAR format types for examples
package main

// HAR represents the HTTP Archive format
type HAR struct {
	Log HARLog `json:"log"`
}

// HARLog is the root of HAR
type HARLog struct {
	Version string     `json:"version"`
	Creator HARCreator `json:"creator"`
	Entries []HAREntry `json:"entries"`
}

// HARCreator contains info about the creator of the HAR file
type HARCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// HAREntry represents a single HTTP request/response pair
type HAREntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         HARRequest  `json:"request"`
	Response        HARResponse `json:"response"`
	Cache           HARCache    `json:"cache"`
	Timings         HARTimings  `json:"timings"`
	ServerIPAddress string      `json:"serverIPAddress,omitempty"`
	ClientIPAddress string      `json:"clientIPAddress,omitempty"`
	Connection      string      `json:"connection,omitempty"`
}

// HARRequest represents an HTTP request
type HARRequest struct {
	Method      string           `json:"method"`
	URL         string           `json:"url"`
	HTTPVersion string           `json:"httpVersion"`
	Cookies     []HARCookie      `json:"cookies"`
	Headers     []HARHeader      `json:"headers"`
	QueryString []HARQueryString `json:"queryString"`
	PostData    *HARPostData     `json:"postData,omitempty"`
	HeadersSize int              `json:"headersSize"`
	BodySize    int              `json:"bodySize"`
}

// HARResponse represents an HTTP response
type HARResponse struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Cookies     []HARCookie `json:"cookies"`
	Headers     []HARHeader `json:"headers"`
	Content     HARContent  `json:"content"`
	RedirectURL string      `json:"redirectURL"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int         `json:"bodySize"`
}

// HARCookie represents a cookie
type HARCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Expires  string `json:"expires,omitempty"`
	HTTPOnly bool   `json:"httpOnly,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
}

// HARHeader represents an HTTP header
type HARHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HARQueryString represents a query string parameter
type HARQueryString struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HARPostData represents POST data
type HARPostData struct {
	MimeType string         `json:"mimeType"`
	Params   []HARPostParam `json:"params,omitempty"`
	Text     string         `json:"text,omitempty"`
}

// HARPostParam represents a POST parameter
type HARPostParam struct {
	Name        string `json:"name"`
	Value       string `json:"value,omitempty"`
	FileName    string `json:"fileName,omitempty"`
	ContentType string `json:"contentType,omitempty"`
}

// HARContent represents response content
type HARContent struct {
	Size        int    `json:"size"`
	Compression int    `json:"compression,omitempty"`
	MimeType    string `json:"mimeType"`
	Text        string `json:"text,omitempty"`
	Encoding    string `json:"encoding,omitempty"`
}

// HARCache represents cache info (usually empty for decrypted traffic)
type HARCache struct{}

// HARTimings represents timing info
type HARTimings struct {
	Blocked float64 `json:"blocked"`
	DNS     float64 `json:"dns"`
	Connect float64 `json:"connect"`
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
	SSL     float64 `json:"ssl"`
}
