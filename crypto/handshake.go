// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

package crypto

import (
	"encoding/binary"
	"fmt"
	"io"
)

// readHandshakeMessage reads TLS records from the stream until a full handshake message is assembled.
func readHandshakeMessage(s *StreamBuffer) ([]byte, error) {
	// Read the first record to get the handshake message header
	record, err := s.ReadRecord()
	if err != nil {
		return nil, err
	}

	if len(record) < 5+4 { // Record header + handshake header
		return nil, fmt.Errorf("handshake record too short")
	}

	handshakeData := record[5:]
	if handshakeData[0] == 0x14 { // ChangeCipherSpec
		// This can happen in TLS 1.2. We should read the next record.
		return readHandshakeMessage(s)
	}

	// Handshake message length (3 bytes)
	msgLen := int(handshakeData[1])<<16 | int(handshakeData[2])<<8 | int(handshakeData[3])
	totalHandshakeMsgLen := 4 + msgLen // type + length + body

	// Keep reading records if the full message hasn't been received
	for len(handshakeData) < totalHandshakeMsgLen {
		nextRecord, err := s.ReadRecord()
		if err != nil {
			if err == io.EOF {
				return nil, fmt.Errorf("handshake message truncated, unexpected EOF")
			}
			return nil, err
		}
		if len(nextRecord) < 5 {
			return nil, fmt.Errorf("invalid subsequent record")
		}
		handshakeData = append(handshakeData, nextRecord[5:]...)
	}

	// Return the full handshake message (without record layer headers)
	return handshakeData[:totalHandshakeMsgLen], nil
}

// ExtractClientRandom extracts the client random from a ClientHello record
func ExtractClientRandom(s *StreamBuffer) ([]byte, error) {
	handshake, err := readHandshakeMessage(s)
	if err != nil {
		return nil, err
	}

	// Handshake message type (1 byte) should be ClientHello (0x01)
	if handshake[0] != 0x01 {
		return nil, fmt.Errorf("not a ClientHello message: got 0x%02x", handshake[0])
	}

	// Handshake message length (3 bytes)
	msgLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])

	if len(handshake) < 4+msgLen {
		return nil, fmt.Errorf("handshake message truncated")
	}

	msg := handshake[4 : 4+msgLen]

	// ClientHello structure:
	// - Version (2 bytes)
	// - Random (32 bytes)
	if len(msg) < 2+32 {
		return nil, fmt.Errorf("ClientHello too short")
	}

	// Skip version (2 bytes), return random (32 bytes)
	random := make([]byte, 32)
	copy(random, msg[2:34])

	return random, nil
}

// ExtractServerRandom extracts the server random from a ServerHello record
func ExtractServerRandom(handshake []byte) ([]byte, error) {
	if len(handshake) < 4 {
		return nil, fmt.Errorf("handshake message too short")
	}

	// Handshake message type (1 byte) should be ServerHello (0x02)
	if handshake[0] != 0x02 {
		return nil, fmt.Errorf("not a ServerHello message: got 0x%02x", handshake[0])
	}

	// Handshake message length (3 bytes)
	msgLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])

	if len(handshake) < 4+msgLen {
		return nil, fmt.Errorf("handshake message truncated")
	}

	msg := handshake[4 : 4+msgLen]

	// ServerHello structure:
	// - Version (2 bytes)
	// - Random (32 bytes)
	if len(msg) < 2+32 {
		return nil, fmt.Errorf("ServerHello too short")
	}

	// Skip version (2 bytes), return random (32 bytes)
	random := make([]byte, 32)
	copy(random, msg[2:34])

	return random, nil
}

// ParseServerHello extracts version and cipher suite from ServerHello
func ParseServerHello(s *StreamBuffer) (version uint16, cipherSuite uint16, handshakeMsg []byte, err error) {
	handshake, err := readHandshakeMessage(s)
	if err != nil {
		return 0, 0, nil, err
	}
	handshakeMsg = handshake

	if len(handshake) < 4 {
		return 0, 0, nil, fmt.Errorf("handshake message too short")
	}

	// Handshake message type (1 byte) should be ServerHello (0x02)
	if handshake[0] != 0x02 {
		return 0, 0, nil, fmt.Errorf("not a ServerHello message")
	}

	// Handshake message length (3 bytes)
	msgLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])

	if len(handshake) < 4+msgLen {
		return 0, 0, nil, fmt.Errorf("handshake message truncated")
	}

	msg := handshake[4 : 4+msgLen]

	// ServerHello structure:
	// - Version (2 bytes)
	// - Random (32 bytes)
	// - Session ID length (1 byte)
	// - Session ID (variable)
	// - Cipher suite (2 bytes)
	// - Compression method (1 byte)
	// - Extensions (optional)

	if len(msg) < 2+32+1 {
		return 0, 0, nil, fmt.Errorf("ServerHello too short")
	}

	// Parse version
	version = binary.BigEndian.Uint16(msg[0:2])

	// Skip random (32 bytes)
	pos := 2 + 32

	// Parse session ID
	sessionIDLen := int(msg[pos])
	pos++

	if len(msg) < pos+sessionIDLen+2 {
		return 0, 0, nil, fmt.Errorf("ServerHello truncated at session ID")
	}

	pos += sessionIDLen

	// Parse cipher suite
	cipherSuite = binary.BigEndian.Uint16(msg[pos : pos+2])
	pos += 2

	// Skip compression method
	pos++

	// Check for extensions (TLS 1.3 uses supported_versions extension)
	if len(msg) > pos+2 {
		extensionsLen := binary.BigEndian.Uint16(msg[pos : pos+2])
		pos += 2

		if len(msg) >= pos+int(extensionsLen) {
			// Parse extensions to find supported_versions
			extensions := msg[pos : pos+int(extensionsLen)]
			actualVersion := parseSupportedVersionExtension(extensions)
			if actualVersion != 0 {
				version = actualVersion
			}
		}
	}

	return version, cipherSuite, handshakeMsg, nil
}

// parseSupportedVersionExtension extracts the TLS version from supported_versions extension
func parseSupportedVersionExtension(extensions []byte) uint16 {
	pos := 0
	for pos+4 <= len(extensions) {
		extType := binary.BigEndian.Uint16(extensions[pos : pos+2])
		extLen := binary.BigEndian.Uint16(extensions[pos+2 : pos+4])
		pos += 4

		if pos+int(extLen) > len(extensions) {
			break
		}

		// supported_versions extension type is 43 (0x002b)
		if extType == 43 {
			if int(extLen) >= 2 {
				// In ServerHello, this contains a single version
				return binary.BigEndian.Uint16(extensions[pos : pos+2])
			}
		}

		pos += int(extLen)
	}

	return 0
}

// TLS version constants
const (
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304
)
