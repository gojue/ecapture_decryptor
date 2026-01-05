// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

// api_new_test.go - Tests for new library API
package ecapture_decryptor

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cfc4n/ecapture_decryptor/types"
)

func TestDecryptPcapFile(t *testing.T) {
	// Open test SSL keylog file
	keylogFile, err := os.Open("test/testdata/all_clients_sslkey.log")
	if err != nil {
		t.Skipf("Test keylog file not found: %v", err)
		return
	}
	defer keylogFile.Close()

	// Open test pcap file
	pcapFile, err := os.Open("test/testdata/all_clients.pcap")
	if err != nil {
		t.Skipf("Test pcap file not found: %v", err)
		return
	}
	defer pcapFile.Close()

	// Create output channel
	packetChan := make(chan *types.DecryptedPacket, 100)

	// Run decryption in background
	done := make(chan error)
	go func() {
		done <- DecryptPcapFile(keylogFile, pcapFile, packetChan)
	}()

	// Collect packets with timeout
	packets := make([]*types.DecryptedPacket, 0)
	timeout := time.After(5 * time.Second)

collectLoop:
	for {
		select {
		case packet := <-packetChan:
			packets = append(packets, packet)
			// 详细日志：检查是否是 POST 请求
			method := ""
			url := ""
			if m, ok := packet.Metadata["method"]; ok {
				method = fmt.Sprintf("%v", m)
			}
			if u, ok := packet.Metadata["url"]; ok {
				url = fmt.Sprintf("%v", u)
			} else if p, ok := packet.Metadata["path"]; ok {
				// HTTP/2 uses 'path' instead of 'url'
				url = fmt.Sprintf("%v", p)
			}
			t.Logf("Received packet: protocol=%s, direction=%s, size=%d, method=%s, url=%s",
				packet.Protocol, packet.Direction, len(packet.Data), method, url)
		case err := <-done:
			if err != nil {
				t.Errorf("Decryption failed: %v", err)
			}
			// Drain remaining packets
			for len(packetChan) > 0 {
				packets = append(packets, <-packetChan)
			}
			break collectLoop
		case <-timeout:
			t.Error("Test timed out")
			break collectLoop
		}
	}

	t.Logf("Total packets decrypted: %d", len(packets))

	// Verify we got some packets
	if len(packets) == 0 {
		t.Error("Expected to decrypt some packets, got none")
	}
}

func TestDecryptedPacket(t *testing.T) {
	// Test DecryptedPacket creation
	packet := types.NewDecryptedPacket("tcp",
		"http/1.1",
		"request",
		[]byte("GET / HTTP/1.1\r\n\r\n"),
		time.Now(),
		types.ConnectionKey{
			SrcIP:       net.IP{192, 168, 0, 1},
			DstIP:       net.IP{93, 184, 216, 34},
			SrcPort:     12345,
			DstPort:     443,
			Proto:       "tcp",
			Pid:         1234,
			FD:          5,
			ProcessName: "test_process",
		},
	)

	if packet.Protocol != "http/1.1" {
		t.Errorf("Expected protocol http/1.1, got %s", packet.Protocol)
	}

	if !packet.IsRequest() {
		t.Error("Expected IsRequest() to be true")
	}

	if packet.IsResponse() {
		t.Error("Expected IsResponse() to be false")
	}

	// Test DataLength
	if packet.DataLength != uint32(len(packet.Data)) {
		t.Errorf("Expected DataLength %d, got %d", len(packet.Data), packet.DataLength)
	}

	// Test metadata
	packet.WithMetadata("method", "GET")
	if method, ok := packet.Metadata["method"]; !ok || method != "GET" {
		t.Error("Expected metadata method=GET")
	}
}
