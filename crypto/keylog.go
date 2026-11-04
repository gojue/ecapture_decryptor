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

const (
	maxKeyLogLineBytes   = 4096
	maxKeyLogEntries     = 16384
	maxKeyLogSecretBytes = 16 << 20
)

// ErrKeyLogResourceLimit reports a Write or LoadFromReader import limit without
// including any keylog contents in the error.
var ErrKeyLogResourceLimit = errors.New("keylog import resource limit exceeded")

// KeyLogStore stores TLS secrets from NSS key log format
type KeyLogStore struct {
	mu sync.RWMutex
	// Map from client random (hex) to secrets
	secrets map[string]*TLSSecrets
	// buffer for partial lines when used as an io.Writer
	partial     bytes.Buffer
	secretBytes int
	updated     chan struct{}
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

// LoadFromReader scans NSS keylog lines with the same import limits as Write.
// Unlike Write, a final line without a newline is also processed.
func (kl *KeyLogStore) LoadFromReader(f io.Reader) error {
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, maxKeyLogLineBytes+1), maxKeyLogLineBytes+1)
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		end := bytes.IndexByte(data, '\n')
		if end < 0 {
			end = len(data)
		}
		if end > maxKeyLogLineBytes {
			return 0, nil, ErrKeyLogResourceLimit
		}
		return bufio.ScanLines(data, atEOF)
	})
	for scanner.Scan() {
		kl.mu.Lock()
		err := kl.parseLineLocked(scanner.Text())
		kl.mu.Unlock()
		if err != nil {
			return err
		}
	}
	return scanner.Err()
}

// AddSecret adds a parsed secret to the store. clientRandomHex should be the hex representation
// of the client random (as found in NSS key log files). The function is concurrency-safe.
// This compatibility entry point trusts the caller to bound memory use and does
// not apply import limits. Use Write or LoadFromReader for bounded imports with
// explicit errors. Unsupported labels are ignored without creating an entry.
func (kl *KeyLogStore) AddSecret(label string, clientRandomHex string, secret []byte) {
	kl.mu.Lock()
	defer kl.mu.Unlock()
	_ = kl.addSecretLocked(label, clientRandomHex, secret, false)
}

func (kl *KeyLogStore) addSecretLocked(label, clientRandomHex string, secret []byte, limited bool) error {
	if clientRandomHex == "" || len(secret) == 0 {
		return nil
	}
	key := strings.ToLower(clientRandomHex)
	s := kl.secrets[key]
	if s == nil {
		s = &TLSSecrets{}
	}
	var target *[]byte
	switch label {
	case "CLIENT_TRAFFIC_SECRET_0", "QUIC_CLIENT_TRAFFIC_SECRET_0":
		target = &s.ClientTrafficSecret
	case "SERVER_TRAFFIC_SECRET_0", "QUIC_SERVER_TRAFFIC_SECRET_0":
		target = &s.ServerTrafficSecret
	case "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET":
		target = &s.ClientHandshakeTrafficSecret
	case "SERVER_HANDSHAKE_TRAFFIC_SECRET", "QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET":
		target = &s.ServerHandshakeTrafficSecret
	case "CLIENT_RANDOM":
		target = &s.MasterSecret
	case "CLIENT_EARLY_TRAFFIC_SECRET", "QUIC_CLIENT_EARLY_TRAFFIC_SECRET":
		target = &s.ClientEarlyTrafficSecret
	case "EXPORTER_SECRET":
		target = &s.ExporterSecret
	default:
		return nil
	}
	delta := len(secret) - len(*target)
	if limited && (kl.secrets[key] == nil && len(kl.secrets) >= maxKeyLogEntries ||
		delta > 0 && delta > maxKeyLogSecretBytes-kl.secretBytes) {
		return ErrKeyLogResourceLimit
	}
	*target = bytes.Clone(secret)
	kl.secretBytes += delta
	kl.secrets[key] = s
	close(kl.updated)
	kl.updated = make(chan struct{})
	return nil
}

// Write accepts streaming NSS keylog data, buffering incomplete lines. Imports
// allow at most 4096 bytes before each LF, 16384 distinct client randoms and
// 16 MiB of stored secret bytes. Existing entries may still be updated at the
// entry limit; byte growth is checked by replacement delta. Resource failures
// return ErrKeyLogResourceLimit and discard partial input, without deleting
// previously imported secrets. A batch may contain any number of bounded lines.
func (kl *KeyLogStore) Write(p []byte) (n int, err error) {
	kl.mu.Lock()
	defer kl.mu.Unlock()
	for len(p) > 0 {
		end := bytes.IndexByte(p, '\n')
		length := end
		if length < 0 {
			length = len(p)
		}
		if length > maxKeyLogLineBytes-kl.partial.Len() {
			kl.partial = bytes.Buffer{}
			return n, ErrKeyLogResourceLimit
		}
		kl.partial.Write(p[:length])
		n += length
		p = p[length:]
		if end < 0 {
			break
		}
		n++
		p = p[1:]
		if err := kl.parseLineLocked(kl.partial.String()); err != nil {
			kl.partial = bytes.Buffer{}
			return n, err
		}
		kl.partial.Reset()
	}
	return n, nil
}

// parseLineLocked ignores malformed lines and reports bounded-import failures.
func (kl *KeyLogStore) parseLineLocked(raw string) error {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	fields := strings.Fields(line)
	if len(fields) != 3 {
		return nil
	}
	label := fields[0]
	clientRandom := fields[1]
	secretHex := fields[2]
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		return nil
	}
	return kl.addSecretLocked(label, clientRandom, secret, true)
}

func (kl *KeyLogStore) GetSecrets(clientRandom []byte) *TLSSecrets {
	key := hex.EncodeToString(clientRandom)
	kl.mu.RLock()
	defer kl.mu.RUnlock()
	return cloneSecrets(kl.secrets[key])
}

// Updates returns the current broadcast channel, which closes when secrets are
// added. Subscribe before reading secrets, and subscribe again before rechecking
// them after a notification, so updates cannot be missed between reads and waits.
// Notifications may concern another connection or repeat an existing secret.
func (kl *KeyLogStore) Updates() <-chan struct{} {
	kl.mu.RLock()
	defer kl.mu.RUnlock()
	return kl.updated
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
			// The final DSB and EOF may make both channels ready together.
			// Recheck published keys once, without extending the wait.
			kl.mu.RLock()
			secrets = cloneSecrets(kl.secrets[key])
			kl.mu.RUnlock()
			if ready(secrets) {
				return secrets, nil
			}
			return nil, io.ErrClosedPipe
		case <-timer.C:
			return nil, errors.New("timed out waiting for TLS secrets")
		}
	}
}
