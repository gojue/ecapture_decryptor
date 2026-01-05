// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

package main

// This example demonstrates how to use the ecapture_decryptor library from Go
// using CGO to call the C API. However, since the library is built as a Go
// c-archive (containing Go runtime), we cannot directly link it into another
// Go program due to symbol conflicts.
//
// Instead, this example uses the Go API directly but demonstrates the same
// workflow as the C demo for educational purposes.

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/cfc4n/ecapture_decryptor"
	"github.com/cfc4n/ecapture_decryptor/types"
)

const version = "ecapture_decryptor v2.0.0 (Go Static Demo)"

func main() {
	// Command line flags
	pcapFile := flag.String("pcap", "", "Path to pcap file (required)")
	keylogFile := flag.String("keylog", "", "Path to SSL keylog file (required)")
	outputFile := flag.String("output", "output.json", "Path to output JSON file")
	format := flag.String("format", "json", "Output format (only 'json' supported)")
	showVersion := flag.Bool("version", false, "Show library version")

	flag.Parse()

	// Show version if requested
	if *showVersion {
		fmt.Printf("Library version: %s\n", version)
		return
	}

	// Validate required arguments
	if *pcapFile == "" || *keylogFile == "" {
		_, _ = fmt.Fprintf(os.Stderr, "Error: Both -pcap and -keylog flags are required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// Check if files exist
	if _, err := os.Stat(*pcapFile); os.IsNotExist(err) {
		_, _ = fmt.Fprintf(os.Stderr, "Error: Pcap file not found: %s\n", *pcapFile)
		os.Exit(1)
	}
	if _, err := os.Stat(*keylogFile); os.IsNotExist(err) {
		_, _ = fmt.Fprintf(os.Stderr, "Error: Keylog file not found: %s\n", *keylogFile)
		os.Exit(1)
	}

	// Validate format
	if *format != "json" {
		_, _ = fmt.Fprintf(os.Stderr, "Error: Only 'json' format is supported\n")
		os.Exit(1)
	}

	// Show version
	fmt.Printf("Using library: %s\n", version)

	fmt.Println("\nDecrypting pcap file...")
	fmt.Printf("  Input pcap:  %s\n", *pcapFile)
	fmt.Printf("  SSL keylog:  %s\n", *keylogFile)
	fmt.Printf("  Output file: %s\n", *outputFile)
	fmt.Printf("  Format:      %s\n", *format)

	// Open keylog file
	keylogFd, err := os.Open(*keylogFile)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "\n❌ ERROR: Failed to open keylog file: %v\n", err)
		os.Exit(1)
	}
	defer keylogFd.Close()

	// Open pcap file
	pcapFd, err := os.Open(*pcapFile)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "\n❌ ERROR: Failed to open pcap file: %v\n", err)
		os.Exit(2)
	}
	defer pcapFd.Close()

	// Collect packets
	packetChan := make(chan *types.DecryptedPacket, 100)
	packets := make([]*types.DecryptedPacket, 0)
	doneChan := make(chan struct{})

	go func() {
		defer close(doneChan)
		for packet := range packetChan {
			packets = append(packets, packet)
		}
	}()

	// Decrypt using the Go API (same as the C library internally uses)
	err = ecapture_decryptor.DecryptPcapFile(keylogFd, pcapFd, packetChan)
	close(packetChan)
	<-doneChan

	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "\n❌ ERROR: Decryption failed: %v\n", err)
		os.Exit(3)
	}

	// Write to output file
	outFd, err := os.Create(*outputFile)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "\n❌ ERROR: Failed to create output file: %v\n", err)
		os.Exit(4)
	}
	defer outFd.Close()

	// Write JSON
	encoder := json.NewEncoder(outFd)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(packets); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "\n❌ ERROR: Failed to write JSON: %v\n", err)
		os.Exit(5)
	}

	fmt.Println("\n✓ Decryption completed successfully!")
	fmt.Printf("✓ Results written to: %s\n", *outputFile)
	fmt.Printf("✓ Total packets decrypted: %d\n", len(packets))
}
