// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package types

import (
	"errors"
	"time"
)

// DecryptOptions controls output and connection resource boundaries.
type DecryptOptions struct {
	// RawChunks emits authenticated TLS bytes or QUIC STREAM chunks instead of
	// parsed application messages. Chunk boundaries are not message boundaries.
	RawChunks bool
	// HTTPEvents emits incremental HTTP headers, body, SSE, trailers and terminal events.
	HTTPEvents bool
	// MaxDecodedBodyBytes enables incremental gzip expansion with this per-message
	// output limit. Zero preserves the content-coded representation.
	MaxDecodedBodyBytes int64
	// OnDiagnostic receives payload-free connection diagnostics. Calls may be
	// concurrent; the callback must return promptly and must not call the engine.
	OnDiagnostic func(Diagnostic)
	// KeyWaitTimeout bounds handshake/key acquisition in wall-clock time.
	// Non-positive values use 30 seconds.
	KeyWaitTimeout time.Duration
	// IdleTimeout reclaims connections without input packets in wall-clock time.
	// Non-positive values use five minutes; capture timestamps do not drive it.
	IdleTimeout time.Duration
	// MaxConnections bounds concurrent decryptors, including closing generations.
	// Non-positive values use 1024.
	MaxConnections int
}

// Validate rejects conflicting output modes before consuming any input.
func (o DecryptOptions) Validate() error {
	if o.RawChunks && o.HTTPEvents {
		return errors.New("RawChunks and HTTPEvents are mutually exclusive")
	}
	if o.MaxDecodedBodyBytes < 0 || o.MaxDecodedBodyBytes > 0 && !o.HTTPEvents {
		return errors.New("MaxDecodedBodyBytes requires HTTPEvents and a nonnegative limit")
	}
	return nil
}

func (o DecryptOptions) SecretWaitTimeout() time.Duration {
	if o.KeyWaitTimeout > 0 {
		return o.KeyWaitTimeout
	}
	return 30 * time.Second
}

func (o DecryptOptions) ConnectionIdleTimeout() time.Duration {
	if o.IdleTimeout > 0 {
		return o.IdleTimeout
	}
	return 5 * time.Minute
}

func (o DecryptOptions) ConnectionLimit() int {
	if o.MaxConnections > 0 {
		return o.MaxConnections
	}
	return 1024
}

// Diagnostic identifies the stage and reason for incomplete or failed output.
// It deliberately excludes secrets, application bytes and parser error text.
type Diagnostic struct {
	ConnectionID string
	Transport    string
	Stage        string
	Code         string
}

// Report delivers a diagnostic when the caller supplied an observer.
func (o DecryptOptions) Report(connection ConnectionKey, stage, code string) {
	if o.OnDiagnostic != nil {
		o.OnDiagnostic(Diagnostic{
			ConnectionID: connection.String(), Transport: connection.Proto,
			Stage: stage, Code: code,
		})
	}
}
