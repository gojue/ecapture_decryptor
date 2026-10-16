// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

package crypto

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
)

// KeyLogStore stores TLS secrets from NSS key log format
type KeyLogStore struct {
	mu sync.RWMutex
	// Map from client random (hex) to secrets
	secrets map[string]*TLSSecrets
	// buffer for partial lines when used as an io.Writer
	partial bytes.Buffer
	updated chan struct{}
}

/*
https://github.com/cloudflare/ngtcp2/blob/e4d0b67e78c0cedc32f1c6e5c48e75c4d4282ff7/examples/keylog.cc#L47

client_early_traffic_secret: "QUIC_CLIENT_EARLY_TRAFFIC_SECRET",
client_handshake_traffic_secret: "QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET",
server_handshake_traffic_secret: "QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET",
client_traffic_secret_0: "QUIC_CLIENT_TRAFFIC_SECRET_0",
server_traffic_secret_0: "QUIC_SERVER_TRAFFIC_SECRET_0",
*/

type TLSSecrets struct {
	ClientTrafficSecret          []byte
	ServerTrafficSecret          []byte
	ClientHandshakeTrafficSecret []byte
	ServerHandshakeTrafficSecret []byte
	MasterSecret                 []byte // For TLS 1.2 and earlier
	ClientEarlyTrafficSecret     []byte // For 0-RTT
	ExporterSecret               []byte // Exporter secret
}

// NewKeyLogStore constructs an empty KeyLogStore.
func NewKeyLogStore() *KeyLogStore {
	return &KeyLogStore{
		secrets: make(map[string]*TLSSecrets),
		updated: make(chan struct{}),
	}
}

// NewKeyLogStoreFromReader constructs a KeyLogStore and loads entries from the provided io.Reader.
func NewKeyLogStoreFromReader(f io.Reader) (*KeyLogStore, error) {
	kl := NewKeyLogStore()
	if f == nil {
		return kl, nil
	}
	if err := kl.LoadFromReader(f); err != nil {
		return kl, err
	}
	return kl, nil
}

// LoadFromReader scans the reader line-by-line and adds secrets found in NSS keylog format.
func (kl *KeyLogStore) LoadFromReader(f io.Reader) error {
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		kl.parseLine(line)
	}
	return scanner.Err()
}

// AddSecret adds a parsed secret to the store. clientRandomHex should be the hex representation
// of the client random (as found in NSS key log files). The function is concurrency-safe.
func (kl *KeyLogStore) AddSecret(label string, clientRandomHex string, secret []byte) {
	if clientRandomHex == "" || len(secret) == 0 {
		return
	}
	key := strings.ToLower(clientRandomHex)
	secret = append([]byte(nil), secret...)
	kl.mu.Lock()
	defer kl.mu.Unlock()
	if kl.secrets[key] == nil {
		kl.secrets[key] = &TLSSecrets{}
	}

	s := kl.secrets[key]
	switch label {
	case "CLIENT_TRAFFIC_SECRET_0":
		s.ClientTrafficSecret = secret
	case "SERVER_TRAFFIC_SECRET_0":
		s.ServerTrafficSecret = secret
	case "CLIENT_HANDSHAKE_TRAFFIC_SECRET":
		s.ClientHandshakeTrafficSecret = secret
	case "SERVER_HANDSHAKE_TRAFFIC_SECRET":
		s.ServerHandshakeTrafficSecret = secret
	case "CLIENT_RANDOM":
		s.MasterSecret = secret
	case "CLIENT_EARLY_TRAFFIC_SECRET":
		s.ClientEarlyTrafficSecret = secret
	case "EXPORTER_SECRET":
		s.ExporterSecret = secret

	// QUIC specific labels
	case "QUIC_CLIENT_EARLY_TRAFFIC_SECRET":
		s.ClientEarlyTrafficSecret = secret
	case "QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET":
		s.ClientHandshakeTrafficSecret = secret
	case "QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET":
		s.ServerHandshakeTrafficSecret = secret
	case "QUIC_CLIENT_TRAFFIC_SECRET_0":
		s.ClientTrafficSecret = secret
	case "QUIC_SERVER_TRAFFIC_SECRET_0":
		s.ServerTrafficSecret = secret
	}
	kl.secrets[key] = s
	close(kl.updated)
	kl.updated = make(chan struct{})
}

// Write implements io.Writer to accept streaming keylog data. It buffers incomplete lines.
func (kl *KeyLogStore) Write(p []byte) (n int, err error) {
	// Append to partial buffer and extract complete lines.
	kl.mu.Lock()
	defer kl.mu.Unlock()
	n = len(p)
	if n == 0 {
		return 0, nil
	}
	kl.partial.Write(p)

	var lines []string
	for {
		data := kl.partial.Bytes()
		idx := bytes.IndexByte(data, '\n')
		if idx == -1 {
			break
		}
		line := string(data[:idx])
		// remove processed line including the newline
		kl.partial.Next(idx + 1)
		// strip optional CR
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		lines = append(lines, line)
	}
	// We released processing of lines while still holding lock, but actual parsing
	// (which uses AddSecret) will also lock; to avoid double-locking issues, we
	// copy lines out and process them after releasing the lock.
	kl.mu.Unlock()
	for _, line := range lines {
		kl.parseLine(line)
	}
	kl.mu.Lock()
	// leave any remaining partial data in the buffer
	return n, nil
}

// parseLine parses a single keylog line and adds the secret if valid.
func (kl *KeyLogStore) parseLine(raw string) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}
	fields := strings.Fields(line)
	if len(fields) != 3 {
		return
	}
	label := fields[0]
	clientRandom := fields[1]
	secretHex := fields[2]
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		return
	}
	kl.AddSecret(label, clientRandom, secret)
}

func (kl *KeyLogStore) GetSecrets(clientRandom []byte) *TLSSecrets {
	key := hex.EncodeToString(clientRandom)
	kl.mu.RLock()
	defer kl.mu.RUnlock()
	return cloneSecrets(kl.secrets[key])
}

func cloneSecrets(s *TLSSecrets) *TLSSecrets {
	if s == nil {
		return nil
	}
	clone := *s
	clone.ClientTrafficSecret = bytes.Clone(s.ClientTrafficSecret)
	clone.ServerTrafficSecret = bytes.Clone(s.ServerTrafficSecret)
	clone.ClientHandshakeTrafficSecret = bytes.Clone(s.ClientHandshakeTrafficSecret)
	clone.ServerHandshakeTrafficSecret = bytes.Clone(s.ServerHandshakeTrafficSecret)
	clone.MasterSecret = bytes.Clone(s.MasterSecret)
	clone.ClientEarlyTrafficSecret = bytes.Clone(s.ClientEarlyTrafficSecret)
	clone.ExporterSecret = bytes.Clone(s.ExporterSecret)
	return &clone
}

// WaitForSecrets waits for the required key material without polling. The stop
// channel is closed when the connection is abandoned.
func (kl *KeyLogStore) WaitForSecrets(clientRandom []byte, ready func(*TLSSecrets) bool, stop <-chan struct{}, timeout time.Duration) (*TLSSecrets, error) {
	key := hex.EncodeToString(clientRandom)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		kl.mu.RLock()
		secrets := cloneSecrets(kl.secrets[key])
		updated := kl.updated
		kl.mu.RUnlock()
		if ready(secrets) {
			return secrets, nil
		}
		select {
		case <-updated:
		case <-stop:
			return nil, io.ErrClosedPipe
		case <-timer.C:
			return nil, errors.New("timed out waiting for TLS secrets")
		}
	}
}
