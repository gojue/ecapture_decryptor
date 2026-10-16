// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package ecapture_decryptor

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"

	"github.com/cfc4n/ecapture_decryptor/crypto"
	"github.com/cfc4n/ecapture_decryptor/types"
)

const maxPcapngBlock = 16 << 20

// DecryptPcapngStream decrypts a growing pcapng stream. The callback is called
// once for each reconstructed application message. Closing ctx closes input,
// which must be an io.ReadCloser so a blocked read can be interrupted.
func DecryptPcapngStream(ctx context.Context, input io.ReadCloser, emit func(*types.DecryptedPacket) error) error {
	if ctx == nil || input == nil || emit == nil {
		return errors.New("context, pcapng input and packet callback are required")
	}
	keyLog := crypto.NewKeyLogStore()
	reader := &pcapngBlockReader{source: input, onTLSSecrets: func(payload []byte) error {
		_, err := keyLog.Write(payload)
		return err
	}}
	packetChan := make(chan *types.DecryptedPacket, 256)
	var callbackErr error
	var callbackMu sync.Mutex
	callbackDone := make(chan struct{})
	go func() {
		defer close(callbackDone)
		for packet := range packetChan {
			callbackMu.Lock()
			failed := callbackErr != nil
			callbackMu.Unlock()
			if failed {
				continue // Drain producers after reporting the first callback failure.
			}
			if err := emit(packet); err != nil {
				callbackMu.Lock()
				callbackErr = err
				callbackMu.Unlock()
				_ = input.Close()
			}
		}
	}()
	stopCancel := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = input.Close()
		case <-stopCancel:
		}
	}()
	logger := log.New(io.Discard, "", 0)
	engine := &DecryptorEngine{
		config: &DecryptorConfig{
			pcapReader: reader, packetChan: packetChan, logger: logger,
			strictPcapng: true,
		},
		keyLog: keyLog, logger: logger,
		factory:   NewDecryptorFactory(keyLog, logger, packetChan),
		conntrack: make(map[string]types.Decryptor),
		tcpFlows:  make(map[string]*tcpConnection),
	}
	engine.factory.SetOutput(io.Discard, io.Discard)
	runErr := engine.Run()
	close(stopCancel)
	close(packetChan)
	<-callbackDone
	callbackMu.Lock()
	defer callbackMu.Unlock()
	return errors.Join(runErr, callbackErr, ctx.Err())
}

// pcapngBlockReader passes complete blocks through unchanged and observes DSBs
// as soon as their bytes arrive, including a DSB after the final packet. It
// validates block boundaries before the pcapgo reader sees the same bytes.
type pcapngBlockReader struct {
	source       io.Reader
	order        binary.ByteOrder
	pending      []byte
	onTLSSecrets func([]byte) error
}

func (r *pcapngBlockReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.pending) == 0 {
		block, err := r.nextBlock()
		if err != nil {
			return 0, err
		}
		r.pending = block
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

func (r *pcapngBlockReader) nextBlock() ([]byte, error) {
	header := make([]byte, 8)
	if _, err := io.ReadFull(r.source, header); err != nil {
		return nil, err
	}
	section := header[0] == 0x0a && header[1] == 0x0d && header[2] == 0x0d && header[3] == 0x0a
	prefix := header
	if section {
		magic := make([]byte, 4)
		if _, err := io.ReadFull(r.source, magic); err != nil {
			return nil, err
		}
		switch {
		case binary.LittleEndian.Uint32(magic) == 0x1a2b3c4d:
			r.order = binary.LittleEndian
		case binary.BigEndian.Uint32(magic) == 0x1a2b3c4d:
			r.order = binary.BigEndian
		default:
			return nil, errors.New("invalid pcapng byte order magic")
		}
		prefix = append(prefix, magic...)
	} else if r.order == nil {
		return nil, errors.New("pcapng stream must begin with a section header")
	}
	length := r.order.Uint32(header[4:8])
	if length < uint32(len(prefix)+4) || length > maxPcapngBlock || length%4 != 0 {
		return nil, fmt.Errorf("invalid pcapng block length %d", length)
	}
	block := make([]byte, length)
	copy(block, prefix)
	if _, err := io.ReadFull(r.source, block[len(prefix):]); err != nil {
		return nil, err
	}
	if r.order.Uint32(block[length-4:]) != length {
		return nil, errors.New("pcapng block length trailer mismatch")
	}
	if !section && r.order.Uint32(header[:4]) == 0x0000000a {
		if length < 20 {
			return nil, errors.New("short pcapng decryption secrets block")
		}
		secretType := r.order.Uint32(block[8:12])
		secretLen := r.order.Uint32(block[12:16])
		if secretLen > length-20 {
			return nil, errors.New("pcapng decryption secrets length exceeds block")
		}
		if secretType == 0x544c534b && r.onTLSSecrets != nil {
			if err := r.onTLSSecrets(block[16 : 16+secretLen]); err != nil {
				return nil, fmt.Errorf("load pcapng TLS secrets: %w", err)
			}
		}
	}
	return block, nil
}
