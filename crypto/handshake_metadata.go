// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package crypto

import (
	"crypto/md5" // JA3 mandates MD5; this is identification, not authentication.
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ClientHelloMetadata describes the first on-wire ClientHello, including the
// Outer hello when ECH is offered. Invalid optional metadata never changes the
// decryptor's acceptance or error semantics. It contains no randoms or secrets.
func ClientHelloMetadata(message []byte, transport string) map[string]string {
	h, err := parseClientHello(message)
	if err != nil || (transport != "t" && transport != "q") {
		return nil
	}
	result := map[string]string{"client_hello": "initial_wire"}
	if h.ECHOffered {
		result["client_hello"] = "initial_outer"
	}
	p := 39 + int(message[38])
	ciphers := metadataWords(message[p+2 : p+2+int(binary.BigEndian.Uint16(message[p:]))])
	var extensions, groups, sigs []uint16
	var points []string
	version := binary.BigEndian.Uint16(message[4:])
	sni, alpn := "i", ""
	for _, e := range h.extensions {
		if metadataGREASE(e.typ) {
			continue
		}
		extensions = append(extensions, e.typ)
		switch e.typ {
		case 0:
			sni = "d"
			if len(e.data) < 2 || int(binary.BigEndian.Uint16(e.data)) != len(e.data)-2 {
				return nil
			}
			for b := e.data[2:]; len(b) > 0; {
				if len(b) < 3 {
					return nil
				}
				n := int(binary.BigEndian.Uint16(b[1:]))
				if n > len(b)-3 {
					return nil
				}
				if b[0] == 0 {
					result["server_name"] = string(b[3 : 3+n])
				}
				b = b[3+n:]
			}
		case 10, 13:
			if len(e.data) < 2 || int(binary.BigEndian.Uint16(e.data)) != len(e.data)-2 || (len(e.data)-2)%2 != 0 {
				return nil
			}
			if e.typ == 10 {
				groups = metadataWords(e.data[2:])
			} else {
				sigs = metadataWords(e.data[2:])
			}
		case 11:
			if len(e.data) < 1 || int(e.data[0]) != len(e.data)-1 {
				return nil
			}
			for _, x := range e.data[1:] {
				points = append(points, strconv.Itoa(int(x)))
			}
		case 16:
			offered, ok := metadataALPN(e.data)
			if !ok {
				return nil
			}
			if len(offered) > 0 {
				alpn = offered[0]
				result["offered_alpn"] = strings.Join(offered, ", ")
			}
		case 43:
			if len(e.data) < 1 || int(e.data[0]) != len(e.data)-1 || (len(e.data)-1)%2 != 0 {
				return nil
			}
			version = 0
			for _, v := range metadataWords(e.data[1:]) {
				if v > version {
					version = v
				}
			}
		}
	}
	raw := fmt.Sprintf("%d,%s,%s,%s,%s", binary.BigEndian.Uint16(message[4:]), metadataDecimal(ciphers), metadataDecimal(extensions), metadataDecimal(groups), strings.Join(points, "-"))
	result["ja3"] = fmt.Sprintf("%x", md5.Sum([]byte(raw))) //nolint:gosec // JA3 fingerprint format.
	if len(raw) <= 8192 {
		result["ja3_raw"] = raw
	}
	var hashedExtensions []uint16
	for _, x := range extensions {
		if x != 0 && x != 16 {
			hashedExtensions = append(hashedExtensions, x)
		}
	}
	extensionText := metadataHex(hashedExtensions, true)
	if len(sigs) > 0 {
		extensionText += "_" + metadataHex(sigs, false)
	}
	tag := "00"
	if alpn != "" {
		first, last := alpn[0], alpn[len(alpn)-1]
		if !metadataAlphaNum(first) || !metadataAlphaNum(last) {
			encoded := hex.EncodeToString([]byte(alpn))
			tag = string([]byte{encoded[0], encoded[len(encoded)-1]})
		} else {
			tag = string([]byte{first, last})
		}
	}
	versionTag := map[uint16]string{0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2"}[version]
	if versionTag == "" {
		versionTag = "00"
	}
	result["ja4"] = fmt.Sprintf("%s%s%s%02d%02d%s_%s_%s", transport, versionTag, sni, min(len(ciphers), 99), min(len(extensions), 99), tag, metadataHash(metadataHex(ciphers, true), len(ciphers)), metadataHash(extensionText, len(hashedExtensions)))
	return result
}

// ServerHelloMetadata describes the actual selection, never the client's offer.
func ServerHelloMetadata(message []byte) map[string]string {
	version, suite, extensions, err := serverHello(message)
	if err != nil || IsHelloRetryRequest(message) {
		return nil
	}
	result := map[string]string{"version": GetTLSVersionName(version), "cipher_suite": tls.CipherSuiteName(suite), "cipher_suite_id": fmt.Sprintf("0x%04x", suite)}
	for _, e := range extensions {
		if e.typ == 16 && version != tls.VersionTLS13 {
			if values, ok := metadataALPN(e.data); ok && len(values) == 1 {
				result["alpn"] = values[0]
			}
		}
		if e.typ == 51 && version == tls.VersionTLS13 && len(e.data) >= 4 && int(binary.BigEndian.Uint16(e.data[2:])) == len(e.data)-4 {
			result["key_exchange_group"] = metadataGroup(binary.BigEndian.Uint16(e.data))
		}
	}
	return result
}

// EncryptedExtensionsMetadata must only receive an authenticated TLS 1.3
// handshake message. An absent ALPN stays absent, not inferred from HTTP.
func EncryptedExtensionsMetadata(message []byte) map[string]string {
	if !validHandshake(message, 8) {
		return nil
	}
	extensions, err := parseHelloExtensions(message, 4)
	if err != nil {
		return nil
	}
	for _, e := range extensions {
		if e.typ == 16 {
			values, ok := metadataALPN(e.data)
			if ok && len(values) == 1 {
				return map[string]string{"alpn": values[0]}
			}
			return nil
		}
	}
	return nil
}

// CertificateVerifyMetadata reads the server's authenticated TLS 1.3 message.
func CertificateVerifyMetadata(message []byte) map[string]string {
	if !validHandshake(message, 15) || len(message) < 8 || int(binary.BigEndian.Uint16(message[6:])) != len(message)-8 {
		return nil
	}
	scheme := binary.BigEndian.Uint16(message[4:])
	return map[string]string{"signature_algorithm": fmt.Sprintf("%s (0x%04x)", tls.SignatureScheme(scheme), scheme)}
}

func metadataALPN(data []byte) ([]string, bool) {
	if len(data) < 2 || int(binary.BigEndian.Uint16(data)) != len(data)-2 {
		return nil, false
	}
	var values []string
	for b := data[2:]; len(b) > 0; {
		n := int(b[0])
		if n == 0 || n > len(b)-1 {
			return nil, false
		}
		values = append(values, string(b[1:1+n]))
		b = b[1+n:]
	}
	return values, true
}
func metadataGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v) }
func metadataWords(data []byte) []uint16 {
	var result []uint16
	for len(data) >= 2 {
		v := binary.BigEndian.Uint16(data)
		if !metadataGREASE(v) {
			result = append(result, v)
		}
		data = data[2:]
	}
	return result
}
func metadataDecimal(values []uint16) string {
	text := make([]string, len(values))
	for i, v := range values {
		text[i] = strconv.Itoa(int(v))
	}
	return strings.Join(text, "-")
}
func metadataHex(values []uint16, sorted bool) string {
	text := make([]string, len(values))
	for i, v := range values {
		text[i] = fmt.Sprintf("%04x", v)
	}
	if sorted {
		sort.Strings(text)
	}
	return strings.Join(text, ",")
}
func metadataHash(text string, count int) string {
	if count == 0 {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:6])
}
func metadataAlphaNum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
}
func metadataGroup(group uint16) string {
	switch group {
	case 23:
		return "secp256r1"
	case 24:
		return "secp384r1"
	case 25:
		return "secp521r1"
	case 29:
		return "X25519"
	case 30:
		return "X448"
	case 0x11ec:
		return "X25519MLKEM768"
	}
	return fmt.Sprintf("0x%04x", group)
}
