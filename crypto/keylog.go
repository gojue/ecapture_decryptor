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
	"fmt"
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

// KeyLogResourceLimitError contains only safe resource counters. Current is the
// usage before the rejected addition (or observed line length for scanning);
// Requested is additional usage rejected by the importer.
// Resource is line_bytes, entries, or secret_bytes.
type KeyLogResourceLimitError struct {
	Resource                  string
	Current, Limit, Requested int
}

func (e *KeyLogResourceLimitError) Error() string {
	return fmt.Sprintf("%s: %s current=%d limit=%d requested=%d", ErrKeyLogResourceLimit, e.Resource, e.Current, e.Limit, e.Requested)
}
func (e *KeyLogResourceLimitError) Unwrap() error { return ErrKeyLogResourceLimit }

// KeyLogStore stores TLS secrets from NSS key log format. Connection scopes
// share the store and notification channel, but own independent references.
type KeyLogStore struct {
	*keyLogData
	scope *keyLogScope
}

type keyLogData struct {
	mu sync.RWMutex
	// Map from client random (hex) to secrets
	secrets map[string]*TLSSecrets
	// buffer for partial lines when used as an io.Writer
	partial     bytes.Buffer
	secretBytes int
	updated     chan struct{}
	retention   time.Duration
	entries     map[string]*keyLogEntry
	pending     map[*keyLogScope]struct{}
	nextScope   uint64
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
	ECHSecret                    []byte // RFC 9850 HPKE shared_secret, indexed by outer random
	ECHConfig                    []byte // RFC 9850 serialized ECHConfig, indexed by outer random
}

// NewKeyLogStore constructs an empty KeyLogStore.
func NewKeyLogStore() *KeyLogStore {
	return &KeyLogStore{keyLogData: &keyLogData{
		secrets: make(map[string]*TLSSecrets), updated: make(chan struct{}),
	}}
}

// A pending scope protects keys whose identity its worker has not yet parsed.
// Once discovery completes, only that scope's exact randoms remain pinned.
type keyLogScope struct {
	id       uint64
	started  time.Time
	keys     map[string]struct{}
	released bool
	broad    bool
}
type keyLogEntry struct {
	refs           int
	bytes          int
	expires        time.Time
	retired        bool
	retiredThrough uint64
}

// NewStreamingKeyLogStore enables lifecycle reclamation. Unassociated entries
// are eligible for expiry after retention from their first import (default 5m).
// Persistent/file stores constructed with NewKeyLogStore never expire entries.
func NewStreamingKeyLogStore(retention time.Duration) *KeyLogStore {
	if retention <= 0 {
		retention = 5 * time.Minute
	}
	kl := NewKeyLogStore()
	kl.retention = retention
	kl.entries = make(map[string]*keyLogEntry)
	kl.pending = make(map[*keyLogScope]struct{})
	return kl
}

// NewConnectionScope must run before feeding a new connection. Until
// ResolveKeyReferences, it protects undiscovered identities, including early
// DSBs and nested TLS. Protection does not extend to history retired before
// admission or orphan windows already expired at admission. Reads pin even
// absent keys for later imports; callers must bound discovery with a deadline.
// A child of a still-pending scope (nested TLS) inherits its admission boundary;
// it is part of the same connection and must share its bounded discovery wait.
// Persistent stores return themselves, preserving their historical behavior.
func (kl *KeyLogStore) NewConnectionScope() *KeyLogStore {
	if kl == nil || kl.retention == 0 {
		return kl
	}
	kl.mu.Lock()
	defer kl.mu.Unlock()
	kl.reapLocked(time.Now())
	kl.nextScope++
	scope := &keyLogScope{id: kl.nextScope, started: time.Now(), keys: make(map[string]struct{})}
	if _, discovering := kl.pending[kl.scope]; discovering {
		// Transfer protection within the same admitted connection before the
		// outer scope resolves. This is not a new independent admission.
		scope.id, scope.started = kl.scope.id, kl.scope.started
	}
	kl.pending[scope] = struct{}{}
	return &KeyLogStore{keyLogData: kl.keyLogData, scope: scope}
}

// ResolveKeyReferences ends discovery only after every potentially needed
// random has been read/pinned, including identities without secrets yet. False
// means the bounded identity set overflowed; the worker must terminate instead
// of treating discovery as complete and retaining its protection indefinitely.
func (kl *KeyLogStore) ResolveKeyReferences() bool {
	if kl == nil || kl.scope == nil {
		return true
	}
	kl.mu.Lock()
	defer kl.mu.Unlock()
	if kl.scope.broad {
		return false
	}
	if _, pending := kl.pending[kl.scope]; pending {
		delete(kl.pending, kl.scope)
		kl.reapLocked(time.Now())
	}
	return true
}

// ReleaseKeyReferences is idempotent and must run after the worker and its
// output drain finish, never merely when Close signals cancellation.
func (kl *KeyLogStore) ReleaseKeyReferences() {
	if kl == nil || kl.scope == nil {
		return
	}
	kl.mu.Lock()
	defer kl.mu.Unlock()
	if kl.scope.released {
		return
	}
	kl.scope.released = true
	delete(kl.pending, kl.scope)
	for key := range kl.scope.keys {
		entry := kl.entries[key]
		entry.refs--
		if entry.refs == 0 {
			entry.retired = true
			entry.retiredThrough = kl.nextScope
		}
	}
	kl.scope.keys = nil
	kl.reapLocked(time.Now())
}

func (kl *KeyLogStore) pinLocked(key string) {
	if kl.scope == nil || kl.scope.released || key == "" {
		return
	}
	if _, ok := kl.scope.keys[key]; ok {
		return
	}
	// Supported TLS layers use at most three identities. Repeated QUIC
	// negotiation must not grow an unbounded missing-key reference map. If an
	// unusual peer exceeds eight, conservatively retain the discovery barrier
	// until this worker exits instead of evicting any potentially needed keys.
	if len(kl.scope.keys) >= 8 {
		kl.scope.broad = true
		kl.pending[kl.scope] = struct{}{}
		return
	}
	kl.scope.keys[key] = struct{}{}
	entry := kl.entries[key]
	if entry == nil {
		entry = &keyLogEntry{}
		kl.entries[key] = entry
	}
	entry.refs++
	entry.retired = false
}

// ReapUnusedKeys also runs on imports and scope transitions. Engines call it
// from their existing reaper so a blocked input does not retain orphan secrets.
func (kl *KeyLogStore) ReapUnusedKeys() {
	if kl == nil || kl.retention == 0 {
		return
	}
	kl.mu.Lock()
	defer kl.mu.Unlock()
	kl.reapLocked(time.Now())
}

func (kl *KeyLogStore) reapLocked(now time.Time) {
	if kl.retention == 0 {
		return
	}
	// An unresolved worker protects history available during its admission,
	// not history inherited from other unresolved workers that have since left.
	// IDs order simultaneous admissions/retirements without relying on clock
	// resolution. Start time bounds which scopes can protect expired orphans.
	var oldest *keyLogScope
	for scope := range kl.pending {
		if oldest == nil || scope.id < oldest.id {
			oldest = scope
		}
	}
	for key, entry := range kl.entries {
		if entry.refs != 0 {
			continue
		}
		if entry.bytes == 0 {
			delete(kl.entries, key) // No secret exists for an undiscovered worker to lose.
			continue
		}
		retired := entry.retired && (oldest == nil || oldest.id > entry.retiredThrough)
		orphan := !entry.retired && !entry.expires.IsZero() && !now.Before(entry.expires) &&
			(oldest == nil || !oldest.started.Before(entry.expires))
		if retired || orphan {
			kl.secretBytes -= entry.bytes
			delete(kl.secrets, key)
			delete(kl.entries, key)
		}
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
			return 0, nil, &KeyLogResourceLimitError{Resource: "line_bytes", Current: end, Limit: maxKeyLogLineBytes}
		}
		return bufio.ScanLines(data, atEOF)
	})
	for scanner.Scan() {
		kl.mu.Lock()
		kl.reapLocked(time.Now())
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
	case "ECH_SECRET", "ECH_CONFIG":
		random, err := hex.DecodeString(key)
		if err != nil || len(random) != 32 {
			return nil
		}
		if label == "ECH_SECRET" {
			target = &s.ECHSecret
		} else {
			target = &s.ECHConfig
		}
	default:
		return nil
	}
	delta := len(secret) - len(*target)
	if limited && kl.secrets[key] == nil && len(kl.secrets) >= maxKeyLogEntries {
		return &KeyLogResourceLimitError{Resource: "entries", Current: len(kl.secrets), Limit: maxKeyLogEntries, Requested: 1}
	}
	if limited && delta > 0 && delta > maxKeyLogSecretBytes-kl.secretBytes {
		return &KeyLogResourceLimitError{Resource: "secret_bytes", Current: kl.secretBytes, Limit: maxKeyLogSecretBytes, Requested: delta}
	}
	if kl.retention > 0 {
		entry := kl.entries[key]
		if entry == nil {
			entry = &keyLogEntry{}
			kl.entries[key] = entry
		}
		now := time.Now()
		if entry.expires.IsZero() || entry.refs == 0 && (entry.retired || !now.Before(entry.expires)) {
			// A fresh publication makes retained history available to new connections.
			// Duplicates within an unassociated retention window do not renew it.
			entry.expires = now.Add(kl.retention)
			entry.retired = false
			entry.retiredThrough = 0
		}
		entry.bytes += delta
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
// wrap ErrKeyLogResourceLimit and discard partial input. Streaming stores first
// reclaim only unused entries; live references are never evicted. A batch may
// contain any number of bounded lines.
func (kl *KeyLogStore) Write(p []byte) (n int, err error) {
	kl.mu.Lock()
	defer kl.mu.Unlock()
	kl.reapLocked(time.Now())
	for len(p) > 0 {
		end := bytes.IndexByte(p, '\n')
		length := end
		if length < 0 {
			length = len(p)
		}
		if length > maxKeyLogLineBytes-kl.partial.Len() {
			err := &KeyLogResourceLimitError{Resource: "line_bytes", Current: kl.partial.Len(), Limit: maxKeyLogLineBytes, Requested: length}
			kl.partial = bytes.Buffer{}
			return n, err
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
	kl.mu.Lock()
	defer kl.mu.Unlock()
	kl.pinLocked(key)
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
	clone.ECHSecret = bytes.Clone(s.ECHSecret)
	clone.ECHConfig = bytes.Clone(s.ECHConfig)
	return &clone
}

// WaitForSecrets waits for the required key material without polling. The stop
// channel is closed when the connection is abandoned.
func (kl *KeyLogStore) WaitForSecrets(clientRandom []byte, ready func(*TLSSecrets) bool, stop <-chan struct{}, timeout time.Duration) (*TLSSecrets, error) {
	key := hex.EncodeToString(clientRandom)
	kl.mu.Lock()
	kl.pinLocked(key)
	kl.mu.Unlock()
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
