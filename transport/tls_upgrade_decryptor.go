// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package transport

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/gojue/ecapture_decryptor/types"
)

// tlsUpgradeDecryptor coordinates one physical connection and at most one
// tunnel. Only TLSDecryptor authenticates records; the gate consumes framing.
type tlsUpgradeDecryptor struct {
	mu                    sync.Mutex
	base, outer, inner    *TLSDecryptor
	gate                  *tlsUpgrade
	options               types.DecryptOptions
	at                    time.Time
	closed, outerFinished bool
	sidesClosed           [2]bool
	reset                 bool
	err                   error
	deadlineErr           error
	ready, inputDone      chan struct{}
	innerDone             chan error
	inputOnce             sync.Once
	negotiated            chan struct{}
	negotiatedOnce        sync.Once
}

func newTLSUpgradeDecryptor(base *TLSDecryptor, options types.DecryptOptions) *tlsUpgradeDecryptor {
	u := &tlsUpgradeDecryptor{base: base, options: options, ready: make(chan struct{}), inputDone: make(chan struct{}), negotiated: make(chan struct{})}
	name := options.TLSUpgrade
	if name == "https-connect" {
		name = "connect"
		u.outer = base
		outerOptions := options
		outerOptions.TLSUpgrade = ""
		outerOptions.ApplicationProtocol = ""
		outerOptions.RawChunks = true
		outerOptions.HTTPEvents = false
		outerOptions.MaxDecodedBodyBytes = 0
		base.SetOptions(outerOptions)
		base.rawMetadata = map[string]any{"tls_depth": 1, "parent_tls_depth": 0, "upgrade_protocol": options.TLSUpgrade}
		base.plaintextSink = u.feedPlaintext
	}
	u.gate, u.err = newTLSUpgrade(name)
	return u
}

func (u *tlsUpgradeDecryptor) finishNegotiation() {
	u.negotiatedOnce.Do(func() { close(u.negotiated) })
}

func (u *tlsUpgradeDecryptor) SetPacketTime(at time.Time) {
	u.mu.Lock()
	u.at = at
	u.mu.Unlock()
	if u.outer != nil {
		u.outer.SetPacketTime(at)
	}
}

func (u *tlsUpgradeDecryptor) feed(data []byte, client bool) error {
	u.mu.Lock()
	closed, at := u.closed, u.at
	u.mu.Unlock()
	if closed {
		return io.ErrClosedPipe
	}
	if u.outer != nil {
		if client {
			return u.outer.FeedClient(data)
		}
		return u.outer.FeedServer(data)
	}
	return u.feedPlaintext(data, client, at)
}

func (u *tlsUpgradeDecryptor) feedPlaintext(data []byte, client bool, at time.Time) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed && u.outer == nil {
		return io.ErrClosedPipe
	}
	if u.err != nil {
		return u.err
	}
	chunks, err := u.gate.Feed(data, client)
	if err != nil {
		for _, chunk := range chunks {
			if !chunk.tls {
				u.emitNegotiation(chunk, at)
			}
		}
		u.err = err
		code := "parse_failed"
		if errors.Is(err, errTLSUpgradeLimit) {
			code = "resource_limit"
		}
		u.options.Report(u.base.ConnectionInfo, "protocol", code)
		u.inputOnce.Do(func() { close(u.inputDone) })
		return err
	}
	if u.gate.Finished() && !u.gate.Upgraded() {
		u.finishNegotiation() // A refusal is plaintext, not a TLS failure.
	}
	for _, chunk := range chunks {
		if !chunk.tls {
			u.emitNegotiation(chunk, at)
			continue
		}
		if u.inner == nil {
			u.startInner()
		}
		u.inner.SetPacketTime(at)
		if chunk.client {
			err = u.inner.FeedClient(chunk.data)
		} else {
			err = u.inner.FeedServer(chunk.data)
		}
		if err != nil {
			// The authenticated outer stream remains usable even when its
			// inner TLS layer has terminated or lacks usable keys.
			if u.outer == nil {
				u.err = err
				return err
			}
		}
	}
	if u.gate.Upgraded() && u.inner == nil {
		u.startInner()
	}
	if u.outer == nil && u.inner != nil {
		if u.sidesClosed[0] {
			_ = u.inner.CloseClient()
		}
		if u.sidesClosed[1] {
			_ = u.inner.CloseServer()
		}
	}
	return nil
}

func (u *tlsUpgradeDecryptor) emitNegotiation(chunk tlsUpgradeChunk, at time.Time) {
	direction, depth := "response", 0
	if chunk.client {
		direction = "request"
	}
	if u.outer != nil {
		depth = 1
	}
	p := types.NewDecryptedPacket("tcp", "starttls", direction, chunk.data, at, u.base.ConnectionInfo)
	p.WithMetadata("kind", "negotiation_chunk").WithMetadata("upgrade_protocol", u.options.TLSUpgrade).WithMetadata("tls_depth", depth)
	if depth > 0 {
		p.WithMetadata("parent_tls_depth", depth-1)
	}
	u.base.packetChan <- p
}

// Called under mu. The one bounded relay decorates all existing parser outputs
// without introducing a second application parser or changing packet identity.
func (u *tlsUpgradeDecryptor) startInner() {
	packets := make(chan *types.DecryptedPacket)
	relayDone := make(chan struct{})
	depth := 1
	if u.outer != nil {
		depth = 2
	}
	inner := NewTLSDecryptor(u.base.ConnectionInfo, u.base.keyLog, u.base.clientOut, u.base.serverOut, u.base.logger, packets)
	options := u.options
	options.TLSUpgrade = ""
	inner.SetOptions(options)
	inner.handshakeReady = u.finishNegotiation
	if u.reset {
		inner.ObserveTCPReset()
	}
	u.inner = inner
	u.innerDone = make(chan error, 1)
	go func() {
		defer close(relayDone)
		for p := range packets {
			p.WithMetadata("upgrade_protocol", u.options.TLSUpgrade).WithMetadata("tls_depth", depth).WithMetadata("parent_tls_depth", depth-1)
			u.base.packetChan <- p
		}
	}()
	go func() {
		err := inner.Decrypt()
		close(packets)
		<-relayDone
		u.innerDone <- err
	}()
	close(u.ready)
}

func (u *tlsUpgradeDecryptor) closeSide(client bool) error {
	i := 1
	if client {
		i = 0
	}
	u.mu.Lock()
	u.sidesClosed[i] = true
	if u.sidesClosed[0] && u.sidesClosed[1] {
		u.inputOnce.Do(func() { close(u.inputDone) })
	}
	child := u.inner
	u.mu.Unlock()
	if u.outer != nil {
		child = u.outer
	}
	if child != nil {
		if client {
			return child.CloseClient()
		}
		return child.CloseServer()
	}
	return nil
}

// Close stops physical input. An HTTPS outer layer may still decrypt buffered
// records, so its child is stopped only after that final drain has completed.
func (u *tlsUpgradeDecryptor) Close() error {
	u.mu.Lock()
	u.closed = true
	u.inputOnce.Do(func() { close(u.inputDone) })
	inner, stopInner := u.inner, u.outer == nil || u.outerFinished
	u.mu.Unlock()
	if u.outer != nil {
		u.outer.stopInput()
	}
	if stopInner && inner != nil {
		inner.stopInput()
	}
	return nil
}

func (u *tlsUpgradeDecryptor) observeReset() {
	u.mu.Lock()
	u.reset = true
	inner := u.inner
	u.mu.Unlock()
	if u.outer != nil {
		u.outer.ObserveTCPReset()
	}
	if inner != nil {
		inner.ObserveTCPReset()
	}
}

func (u *tlsUpgradeDecryptor) Decrypt() error {
	defer u.Close()
	workerDone := make(chan struct{})
	timer := time.NewTimer(u.options.SecretWaitTimeout())
	timerDone := make(chan struct{})
	go func() {
		defer close(timerDone)
		select {
		case <-u.negotiated:
		case <-workerDone:
		case <-timer.C:
			select {
			case <-u.negotiated:
				return
			default:
			}
			u.mu.Lock()
			u.deadlineErr = context.DeadlineExceeded
			inner := u.inner
			innerOnly := u.outer != nil && inner != nil
			if u.err == nil && !innerOnly {
				u.err = context.DeadlineExceeded
			}
			u.mu.Unlock()
			u.options.Report(u.base.ConnectionInfo, "keys", "key_wait_timeout")
			if !innerOnly {
				_ = u.Close()
			}
			if inner != nil {
				inner.abortInput()
			}
		}
	}()
	defer func() { timer.Stop(); close(workerDone); <-timerDone }()

	var outerErr error
	if u.outer != nil {
		outerErr = u.outer.Decrypt()
	} else {
		select {
		case <-u.ready:
		case <-u.inputDone:
		}
	}
	u.mu.Lock()
	u.outerFinished = true
	inner, done, closed := u.inner, u.innerDone, u.closed
	u.mu.Unlock()
	if inner != nil && u.outer != nil {
		_ = inner.CloseClient()
		_ = inner.CloseServer()
		if closed {
			inner.stopInput()
		}
	}
	var innerErr error
	if inner != nil {
		innerErr = <-done
		if innerErr != nil && u.outer != nil {
			inner.handshakeMu.RLock()
			ready := inner.handshakeComplete
			inner.handshakeMu.RUnlock()
			if !ready {
				u.options.Report(u.base.ConnectionInfo, "tunnel", "inner_tls_unavailable")
			}
		}
	}
	u.mu.Lock()
	var gateErr error
	if u.gate != nil {
		gateErr = u.gate.Close()
	}
	err := errors.Join(outerErr, gateErr, innerErr, u.err, u.deadlineErr)
	u.mu.Unlock()
	if gateErr != nil {
		u.options.Report(u.base.ConnectionInfo, "protocol", "parse_failed")
	}
	return err
}
