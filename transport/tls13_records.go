// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/gojue/ecapture_decryptor/crypto"
)

const (
	tls13Probe = iota // Application-only keys; unavailable handshake records may precede them.
	tls13Handshake
	tls13Application
	tls13Early
)

var errTLS13Handshake = errors.New("invalid TLS 1.3 handshake phase")

// Each state is owned by its direction's process lock. Early acceptance/output
// has a separate lock; no direction ever acquires the opposite direction lock.
type tls13Direction struct {
	phase         int
	handshake     crypto.HandshakeAssembler
	early         *crypto.RecordDecryptor
	waiting       bool
	finished      bool
	ee            bool
	skipped       int
	generation    uint64
	authenticated bool
}

type tlsEarlyChunk struct {
	data  []byte
	early bool
}

func (td *TLSDecryptor) wakeTLS13() {
	select {
	case td.tls13Wake <- struct{}{}:
	default:
	}
}

func (td *TLSDecryptor) tlsEarlyStatus() string {
	td.earlyMu.Lock()
	defer td.earlyMu.Unlock()
	return td.earlyStatus
}

func (td *TLSDecryptor) queueTLS13Client(data []byte, early bool) error {
	td.earlyMu.Lock()
	defer td.earlyMu.Unlock()
	if td.earlyOffered && td.earlyStatus == "" {
		if len(data) > tlsPendingResponseLimit-td.earlyBytes || len(td.earlyPending) >= tlsPendingResponseCount {
			return crypto.ErrHandshakeResourceLimit
		}
		td.earlyPending = append(td.earlyPending, tlsEarlyChunk{bytes.Clone(data), early})
		td.earlyBytes += len(data)
		return nil
	}
	status := ""
	if early {
		status = td.earlyStatus
	}
	td.queueRequestEarly(data, status)
	return nil
}

func (td *TLSDecryptor) resolveTLSEarly(status string) error {
	td.earlyMu.Lock()
	defer td.earlyMu.Unlock()
	if td.earlyStatus != "" {
		return nil
	}
	if status == "accepted" && td.earlyHandshakeWithoutEnd {
		return errTLS13Handshake
	}
	td.earlyStatus = status
	if td.earlyOffered {
		td.options.Report(td.ConnectionInfo, "handshake", "early_data_"+status)
	}
	for _, chunk := range td.earlyPending {
		earlyStatus := ""
		if chunk.early {
			earlyStatus = status
		}
		// Unknown early bytes might be a prefix of a later application message.
		// Only raw output can preserve that uncertain boundary safely.
		if status != "unknown" || td.options.RawChunks {
			td.queueRequestEarly(chunk.data, earlyStatus)
		}
	}
	td.earlyPending = nil
	td.earlyBytes = 0
	td.wakeTLS13()
	return nil
}

func (td *TLSDecryptor) tls13Fail(stage, code string, err error) {
	td.recordFailure(stage, code, err)
	td.abortInput()
}

// refreshTLS13Keys is called under one direction lock. Missing early/handshake
// keys leave ciphertext in the existing bounded StreamBuffer until key updates
// wake the worker, or finalization reports the unavailable boundary.
func (td *TLSDecryptor) refreshTLS13Keys(client bool) error {
	secrets := td.keyLog.GetSecrets(td.clientRandom)
	if secrets == nil {
		return nil
	}
	i := 1
	secret := secrets.ServerHandshakeTrafficSecret
	target := &td.serverHandshakeDecryptor
	if client {
		i, secret, target = 0, secrets.ClientHandshakeTrafficSecret, &td.clientHandshakeDecryptor
	}
	if *target == nil && len(secret) > 0 && !td.tls13[i].authenticated {
		next, err := crypto.NewRecordDecryptor(td.version, td.cipherSuite, secret)
		if err != nil {
			return err
		}
		td.handshakeMu.Lock()
		*target = next
		td.handshakeMu.Unlock()
		if td.tls13[i].phase == tls13Probe && td.tls13[i].skipped == 0 {
			td.tls13[i].phase = tls13Handshake
		}
	}
	if client && td.earlyOffered && td.tls13[0].early == nil && len(secrets.ClientEarlyTrafficSecret) > 0 && td.tls13[0].phase == tls13Early {
		next, err := crypto.NewRecordDecryptor(td.version, td.cipherSuite, secrets.ClientEarlyTrafficSecret)
		if err != nil {
			return err
		}
		td.tls13[0].early = next
	}
	return nil
}

func (td *TLSDecryptor) processTLS13Records(client bool) {
	i := 1
	in, application := td.serverIn, td.serverDecryptor
	handshake := &td.serverHandshakeDecryptor
	probeErr := &td.serverProbeErr
	applicationSeen := &td.serverApplicationSeen
	if client {
		i, in, application = 0, td.clientIn, td.clientDecryptor
		handshake, probeErr, applicationSeen = &td.clientHandshakeDecryptor, &td.clientProbeErr, &td.clientApplicationSeen
	}
	s := &td.tls13[i]
	if err := td.refreshTLS13Keys(client); err != nil {
		td.tls13Fail("keys", "invalid_secret", err)
		return
	}
	for !td.aborted.Load() {
		s.waiting = false
		if s.phase == tls13Handshake && *handshake == nil || s.phase == tls13Early && s.early == nil && td.tlsEarlyStatus() != "rejected" {
			if !td.tls13Finalizing.Load() {
				s.waiting = true
				return
			}
			if s.phase == tls13Handshake {
				td.recordFailure("keys", "missing_secret", errors.New("TLS handshake traffic secret unavailable"))
				s.phase = tls13Probe
			}
		}
		record := in.TryReadRecord()
		if record == nil {
			return
		}
		if record[0] == 20 {
			if len(record) != 6 || record[5] != 1 || s.phase == tls13Application {
				td.tls13Fail("handshake", "invalid_handshake", errTLS13Handshake)
				return
			}
			continue
		}
		if record[0] != 23 {
			td.tls13Fail("handshake", "invalid_handshake", errTLS13Handshake)
			return
		}
		phase := s.phase
		decryptor := application
		if phase == tls13Handshake {
			decryptor = *handshake
		} else if phase == tls13Early {
			decryptor = s.early
		}
		var plaintext []byte
		var typ byte
		err := errors.New("TLS early traffic secret unavailable")
		if decryptor != nil {
			plaintext, typ, err = decryptor.Decrypt(record)
		}
		if phase == tls13Early && err != nil && *handshake != nil {
			// Rejected 0-RTT has no EndOfEarlyData. Authenticate the first
			// handshake record without advancing either failed key candidate.
			plaintext, typ, err = (*handshake).Decrypt(record)
			if err == nil {
				td.earlyMu.Lock()
				td.earlyHandshakeWithoutEnd = true
				accepted := td.earlyStatus == "accepted"
				td.earlyMu.Unlock()
				if accepted {
					td.tls13Fail("handshake", "invalid_handshake", errTLS13Handshake)
					return
				}
				s.phase, phase = tls13Handshake, tls13Handshake
			}
		}
		if phase == tls13Early && err != nil && *handshake == nil && td.tls13Finalizing.Load() {
			plaintext, typ, err = application.Decrypt(record)
			if err == nil {
				s.phase, phase = tls13Application, tls13Application
			}
		}
		if err != nil {
			canSkip := phase == tls13Probe && !s.authenticated || phase == tls13Early && s.early == nil && (td.tlsEarlyStatus() == "rejected" || td.tls13Finalizing.Load())
			if canSkip {
				s.skipped += len(record)
				*probeErr = err
				if s.skipped > tlsPendingResponseLimit {
					td.tls13Fail("input", "resource_limit", crypto.ErrHandshakeResourceLimit)
					return
				}
				if phase == tls13Early {
					td.recordFailure("keys", "missing_early_secret", errors.New("TLS early records could not be authenticated"))
				}
				continue
			}
			td.tls13Fail("decrypt", "authentication_failed", err)
			return
		}
		if phase == tls13Probe {
			s.phase, phase = tls13Application, tls13Application
		}
		if td.echOuterCandidate {
			td.handshakeMu.Lock()
			report := !td.echOuterReported
			td.echOuterReported = true
			td.handshakeMu.Unlock()
			if report {
				td.options.Report(td.ConnectionInfo, "handshake", "ech_not_accepted_or_grease")
			}
		}
		if phase == tls13Application {
			s.authenticated = true
		}
		if typ == 22 {
			if err := td.handleTLS13Handshake(s, plaintext, client, phase); err != nil {
				code := "invalid_handshake"
				if errors.Is(err, crypto.ErrHandshakeResourceLimit) {
					code = "resource_limit"
				}
				td.tls13Fail("handshake", code, err)
				return
			}
			continue
		}
		if s.handshake.Pending() || typ == 23 && phase == tls13Handshake {
			td.tls13Fail("handshake", "invalid_handshake", errTLS13Handshake)
			return
		}
		if typ == 21 {
			if len(plaintext) != 2 {
				td.tls13Fail("handshake", "invalid_handshake", errTLS13Handshake)
				return
			}
			if plaintext[1] == 0 && !client {
				td.serverEnded.Store(true) // Authenticated close_notify ends close-delimited HTTP.
			} else if plaintext[1] != 0 && plaintext[1] != 90 {
				td.options.Report(td.ConnectionInfo, "handshake", "tls_alert")
			}
		}
		if typ != 23 {
			continue
		}
		if phase == tls13Application {
			*applicationSeen = true
		}
		if len(plaintext) > 0 {
			if client {
				if err := td.queueTLS13Client(plaintext, phase == tls13Early); err != nil {
					td.tls13Fail("input", "resource_limit", err)
					return
				}
			} else {
				td.queueResponse(plaintext)
			}
		}
	}
}

func (td *TLSDecryptor) handleTLS13Handshake(s *tls13Direction, data []byte, client bool, phase int) error {
	messages, err := s.handshake.Feed(data)
	if err != nil {
		return err
	}
	for i, message := range messages {
		typ, body := message[0], message[4:]
		boundary := i == len(messages)-1 && !s.handshake.Pending()
		switch typ {
		case 5: // EndOfEarlyData is protected with the early traffic key.
			if !client || phase != tls13Early || len(body) != 0 || !boundary {
				return errTLS13Handshake
			}
			s.phase = tls13Handshake
		case 8: // Only authenticated EncryptedExtensions can confirm 0-RTT.
			if client || phase != tls13Handshake || s.ee || len(body) < 2 || int(binary.BigEndian.Uint16(body)) != len(body)-2 {
				return errTLS13Handshake
			}
			accepted := false
			for ext := body[2:]; len(ext) > 0; {
				if len(ext) < 4 {
					return errTLS13Handshake
				}
				n := int(binary.BigEndian.Uint16(ext[2:]))
				if n > len(ext)-4 {
					return errTLS13Handshake
				}
				if binary.BigEndian.Uint16(ext) == 42 {
					if accepted || n != 0 || !td.earlyOffered {
						return errTLS13Handshake
					}
					accepted = true
				}
				ext = ext[4+n:]
			}
			s.ee = true
			status := "rejected"
			if accepted {
				status = "accepted"
			}
			if err := td.resolveTLSEarly(status); err != nil {
				return err
			}
		case 20: // Finished ends the handshake epoch only after its full body.
			config, _ := crypto.GetCipherSuite(td.cipherSuite)
			if phase == tls13Early || len(body) != config.HashFunc().Size() || !boundary {
				return errTLS13Handshake
			}
			s.finished, s.phase = true, tls13Application
		case 24:
			if phase != tls13Application || len(body) != 1 || body[0] > 1 || !boundary {
				return errTLS13Handshake
			}
			decryptor := td.serverDecryptor
			if client {
				decryptor = td.clientDecryptor
			}
			if err := decryptor.UpdateTrafficSecret(); err != nil {
				return err
			}
			s.generation++
			code := "key_update"
			if body[0] == 1 {
				code = "key_update_requested"
			}
			td.options.Report(td.ConnectionInfo, "decrypt", code)
		default:
			if phase == tls13Early {
				return errTLS13Handshake
			}
		}
	}
	return nil
}

func (td *TLSDecryptor) tls13Waiting() bool {
	td.clientProcessMu.Lock()
	waiting := td.tls13[0].waiting
	td.clientProcessMu.Unlock()
	td.serverProcessMu.Lock()
	waiting = waiting || td.tls13[1].waiting
	td.serverProcessMu.Unlock()
	return waiting || td.earlyOffered && td.tlsEarlyStatus() == ""
}

func (td *TLSDecryptor) finishTLS13() {
	if td.version != 0x0304 {
		return
	}
	td.handshakeMu.RLock()
	unknownECH := td.echOuterCandidate && !td.echOuterReported
	td.handshakeMu.RUnlock()
	if unknownECH {
		td.options.Report(td.ConnectionInfo, "handshake", "ech_unknown")
	}
	if td.earlyOffered && td.tlsEarlyStatus() == "" {
		_ = td.resolveTLSEarly("unknown")
		td.recordFailure("handshake", "early_data_unknown", errors.New("TLS early data acceptance is unknown"))
	}
	td.clientProcessMu.Lock()
	pending := td.tls13[0].handshake.Pending()
	td.clientProcessMu.Unlock()
	td.serverProcessMu.Lock()
	pending = pending || td.tls13[1].handshake.Pending()
	td.serverProcessMu.Unlock()
	if pending {
		td.recordFailure("handshake", "truncated_handshake", io.ErrUnexpectedEOF)
	}
}

// waitTLSRecords joins FIN independently of key availability. A late keylog
// update wakes both directions without another packet, and an unresolved early
// boundary shares the original handshake/key deadline rather than extending it.
func (td *TLSDecryptor) waitTLSRecords(deadline time.Time) {
	clientClosed, serverClosed := td.clientIn.Closed, td.serverIn.Closed
	updates := td.keyLog.Updates()
	var timeout <-chan time.Time
	timer := time.NewTimer(max(0, time.Until(deadline)))
	defer timer.Stop()
	for {
		td.processClientRecords()
		td.processServerRecords()
		waiting := td.tls13Waiting()
		if waiting && td.earlyOffered {
			timeout = timer.C
		} else {
			timeout = nil
		}
		if clientClosed == nil && serverClosed == nil && !waiting || td.aborted.Load() {
			return
		}
		select {
		case <-updates:
			updates = td.keyLog.Updates()
		case <-td.tls13Wake:
		case <-clientClosed:
			clientClosed = nil
		case <-serverClosed:
			serverClosed = nil
		case <-td.closeSignal:
			td.tls13Finalizing.Store(true)
			td.processClientRecords()
			td.processServerRecords()
			return
		case <-timeout:
			td.recordFailure("keys", "key_wait_timeout", context.DeadlineExceeded)
			td.tls13Finalizing.Store(true)
			td.processClientRecords()
			td.processServerRecords()
			td.stopInput()
			return
		}
	}
}
