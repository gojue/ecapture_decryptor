// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package types

// DecryptOptions controls application output without changing packet decryption.
type DecryptOptions struct {
	// RawChunks emits authenticated TLS bytes or QUIC STREAM chunks instead of
	// parsed application messages. Chunk boundaries are not message boundaries.
	RawChunks bool
	// OnDiagnostic receives payload-free connection diagnostics. Calls may be
	// concurrent; the callback must return promptly and must not call the engine.
	OnDiagnostic func(Diagnostic)
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
