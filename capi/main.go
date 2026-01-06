// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// PROPRIETARY SOURCE CODE - ALL RIGHTS RESERVED
// Unauthorized copying, modification, distribution, or use of this file,
// via any medium, is strictly prohibited without explicit written permission.
//
// The compiled binary library is licensed for non-commercial use only.
// See LICENSE-BINARY for binary library usage terms.
// Contact cfc4n.cs@gmail.com for commercial licensing.

package main

/*
#include <stdlib.h>
#include <string.h>
*/
import "C"
import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/cfc4n/ecapture_decryptor"
	"github.com/cfc4n/ecapture_decryptor/types"
)

//export GetVersion
func GetVersion() *C.char {
	return C.CString("eCapture Decryptor v1.0.8 - Copyright (c) 2024-2026 CFC4N - Non-Commercial License")
}

// DecryptPcapToFile decrypts a pcap file using SSL keylog and writes packets to output file
// format: "json" (writes packet data)
// Returns 0 on success, non-zero on error
//
//export DecryptPcapToFile
func DecryptPcapToFile(
	pcapPath *C.char,
	keylogPath *C.char,
	outputPath *C.char,
	format *C.char,
	errorBuf *C.char,
	errorBufLen C.int,
) C.int {
	pcapFile := C.GoString(pcapPath)
	keylogFile := C.GoString(keylogPath)
	outputFile := C.GoString(outputPath)
	formatStr := C.GoString(format)

	// Open keylog file
	keylogFd, err := os.Open(keylogFile)
	if err != nil {
		writeError(errorBuf, errorBufLen, "Failed to open keylog file: "+err.Error())
		return 1
	}
	defer keylogFd.Close()

	// Open pcap file
	pcapFd, err := os.Open(pcapFile)
	if err != nil {
		writeError(errorBuf, errorBufLen, "Failed to open pcap file: "+err.Error())
		return 2
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

	// Decrypt
	err = ecapture_decryptor.DecryptPcapFile(keylogFd, pcapFd, packetChan)
	close(packetChan)
	<-doneChan

	if err != nil {
		writeError(errorBuf, errorBufLen, "Decryption failed: "+err.Error())
		return 3
	}

	// Write to output file
	outFd, err := os.Create(outputFile)
	if err != nil {
		writeError(errorBuf, errorBufLen, "Failed to create output file: "+err.Error())
		return 4
	}
	defer outFd.Close()

	// Write based on format (currently only JSON supported in C API)
	if formatStr != "json" {
		writeError(errorBuf, errorBufLen, "Only 'json' format supported in C API")
		return 6
	}

	encoder := json.NewEncoder(outFd)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(packets); err != nil {
		writeError(errorBuf, errorBufLen, "Failed to write JSON: "+err.Error())
		return 5
	}

	return 0
}

// LiveTrafficHandle represents a handle to a live traffic decryption session
type LiveTrafficHandle struct {
	stopChan   chan struct{}
	doneChan   chan struct{}
	errorMsg   string
	mu         sync.Mutex
	outputFile *os.File
	encoder    *json.Encoder
}

var (
	liveHandles  = make(map[int]*LiveTrafficHandle)
	liveHandleMu sync.Mutex
	nextHandleID = 1
)

// DecryptLiveTrafficToFile starts decrypting live traffic from a network interface
// This function returns immediately and runs decryption in background
// deviceName: network interface name (e.g., "eth0", "en0")
// keylogPath: path to SSL keylog file
// outputPath: path to output JSON file (appended continuously)
// errorBuf: buffer for error messages
// Returns: handle ID (>0) on success, 0 on error
//
//export DecryptLiveTrafficToFile
func DecryptLiveTrafficToFile(
	deviceName *C.char,
	keylogPath *C.char,
	outputPath *C.char,
	errorBuf *C.char,
	errorBufLen C.int,
) C.int {
	devName := C.GoString(deviceName)
	keylogFile := C.GoString(keylogPath)
	outputFile := C.GoString(outputPath)

	// Open keylog file
	keylogFd, err := os.Open(keylogFile)
	if err != nil {
		writeError(errorBuf, errorBufLen, "Failed to open keylog file: "+err.Error())
		return 0
	}

	// Open output file for appending
	outFd, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		keylogFd.Close()
		writeError(errorBuf, errorBufLen, "Failed to open output file: "+err.Error())
		return 0
	}

	// Create handle
	handle := &LiveTrafficHandle{
		stopChan:   make(chan struct{}),
		doneChan:   make(chan struct{}),
		outputFile: outFd,
		encoder:    json.NewEncoder(outFd),
	}

	// Allocate handle ID
	liveHandleMu.Lock()
	handleID := nextHandleID
	nextHandleID++
	liveHandles[handleID] = handle
	liveHandleMu.Unlock()

	// Start live capture in background
	go func() {
		defer close(handle.doneChan)
		defer keylogFd.Close()
		defer outFd.Close()

		// Create packet channel
		packetChan := make(chan *types.DecryptedPacket, 100)
		errorChan := make(chan error, 1)

		// Process packets and write to file
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case packet, ok := <-packetChan:
					if !ok {
						return
					}
					// Write packet immediately to file
					if err := handle.encoder.Encode(packet); err != nil {
						handle.mu.Lock()
						handle.errorMsg = "Failed to write packet: " + err.Error()
						handle.mu.Unlock()
					}
					// Flush to ensure data is written
					_ = outFd.Sync()
				case <-handle.stopChan:
					return
				}
			}
		}()

		// Start decryption in another goroutine
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(packetChan)

			// Note: For live capture, we need to use pcap library directly
			// Since Go's DecryptLiveTraffic expects io.Reader, we need to create
			// a pipe from pcap handle. For now, we'll use a simpler approach:
			// open the device with pcap and create a reader

			// This is a placeholder - in real implementation, you'd need to:
			// 1. Use github.com/google/gopacket/pcap to open live device
			// 2. Create a reader from the handle
			// 3. Pass to DecryptLiveTraffic

			// For demonstration, we'll show the error
			handle.mu.Lock()
			handle.errorMsg = "Live capture from device '" + devName + "' requires pcap library integration"
			handle.mu.Unlock()
			errorChan <- io.EOF
		}()

		// Wait for completion or stop signal
		wg.Wait()
	}()

	return C.int(handleID)
}

// StopLiveTraffic stops a live traffic decryption session
// handleID: handle returned by DecryptLiveTrafficToFile
// Returns: 0 on success, non-zero on error
//
//export StopLiveTraffic
func StopLiveTraffic(handleID C.int) C.int {
	liveHandleMu.Lock()
	handle, ok := liveHandles[int(handleID)]
	if !ok {
		liveHandleMu.Unlock()
		return 1
	}
	delete(liveHandles, int(handleID))
	liveHandleMu.Unlock()

	// Signal stop
	close(handle.stopChan)

	// Wait for completion with timeout
	select {
	case <-handle.doneChan:
		return 0
	case <-time.After(5 * time.Second):
		return 2 // Timeout
	}
}

// GetLiveTrafficError gets the last error from a live traffic session
// handleID: handle returned by DecryptLiveTrafficToFile
// errorBuf: buffer to store error message
// Returns: 0 if no error, 1 if error exists
//
//export GetLiveTrafficError
func GetLiveTrafficError(handleID C.int, errorBuf *C.char, errorBufLen C.int) C.int {
	liveHandleMu.Lock()
	handle, ok := liveHandles[int(handleID)]
	liveHandleMu.Unlock()

	if !ok {
		writeError(errorBuf, errorBufLen, "Invalid handle ID")
		return 1
	}

	handle.mu.Lock()
	errMsg := handle.errorMsg
	handle.mu.Unlock()

	if errMsg != "" {
		writeError(errorBuf, errorBufLen, errMsg)
		return 1
	}

	return 0
}

// DecryptPcapStreamToFile decrypts pcap data from a stream (e.g., stdin or named pipe)
// This is useful for piping live capture: tcpdump -i eth0 -w - | your_program
// keylogPath: path to SSL keylog file
// outputPath: path to output JSON file
// maxPackets: maximum number of packets to process (0 = unlimited)
// errorBuf: buffer for error messages
// Returns: 0 on success, non-zero on error
//
//export DecryptPcapStreamToFile
func DecryptPcapStreamToFile(
	keylogPath *C.char,
	outputPath *C.char,
	maxPackets C.int,
	errorBuf *C.char,
	errorBufLen C.int,
) C.int {
	keylogFile := C.GoString(keylogPath)
	outputFile := C.GoString(outputPath)
	maxPkts := int(maxPackets)

	// Open keylog file
	keylogFd, err := os.Open(keylogFile)
	if err != nil {
		writeError(errorBuf, errorBufLen, "Failed to open keylog file: "+err.Error())
		return 1
	}
	defer keylogFd.Close()

	// Open output file
	outFd, err := os.Create(outputFile)
	if err != nil {
		writeError(errorBuf, errorBufLen, "Failed to create output file: "+err.Error())
		return 2
	}
	defer outFd.Close()

	// Use stdin as pcap source
	pcapReader := bufio.NewReader(os.Stdin)

	// Create packet channel
	packetChan := make(chan *types.DecryptedPacket, 100)
	packets := make([]*types.DecryptedPacket, 0)
	doneChan := make(chan struct{})

	go func() {
		defer close(doneChan)
		count := 0
		for packet := range packetChan {
			packets = append(packets, packet)
			count++
			if maxPkts > 0 && count >= maxPkts {
				break
			}
		}
	}()

	// Decrypt from stream
	err = ecapture_decryptor.DecryptLiveTraffic(keylogFd, pcapReader, packetChan)
	close(packetChan)
	<-doneChan

	if err != nil {
		writeError(errorBuf, errorBufLen, "Decryption failed: "+err.Error())
		return 3
	}

	// Write to output file
	encoder := json.NewEncoder(outFd)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(packets); err != nil {
		writeError(errorBuf, errorBufLen, "Failed to write JSON: "+err.Error())
		return 4
	}

	return 0
}

// FreeString frees a string allocated by Go
//
//export FreeString
func FreeString(str *C.char) {
	C.free(unsafe.Pointer(str))
}

// Helper function to write error messages to C buffer
func writeError(buf *C.char, bufLen C.int, errMsg string) {
	if buf == nil || bufLen <= 0 {
		return
	}
	maxLen := int(bufLen) - 1
	if len(errMsg) > maxLen {
		errMsg = errMsg[:maxLen]
	}

	// Copy error message byte by byte
	for i := 0; i < len(errMsg); i++ {
		*(*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(buf)) + uintptr(i))) = C.char(errMsg[i])
	}
	// Null terminate
	*(*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(buf)) + uintptr(len(errMsg)))) = 0
}

func main() {
	// Required for buildmode=c-archive
	log.SetOutput(io.Discard)
}
