// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package transport

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gojue/ecapture_decryptor/types"
)

func TestTLSHandshakeAndKeyWaitShareDeadline(t *testing.T) {
	for _, phase := range []string{"client_hello", "partial_client_hello", "server_hello", "secrets", "default_timeout"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				timeout := 100 * time.Millisecond
				if phase == "default_timeout" {
					timeout = 0
				}
				diagnostics := make(chan types.Diagnostic, 8)
				options := types.DecryptOptions{RawChunks: true, KeyWaitTimeout: timeout, OnDiagnostic: func(d types.Diagnostic) {
					diagnostics <- d
				}}
				decryptor, packets := newTLSRawTest(options)
				if phase == "partial_client_hello" {
					if err := decryptor.FeedClient([]byte{0x16, 3, 3, 0, 40, 1, 0}); err != nil {
						t.Fatal(err)
					}
				} else if phase == "secrets" {
					prepareTLS13RawHandshake(t, decryptor, nil)
				}
				started := time.Now()
				done := make(chan error, 1)
				go func() { done <- decryptor.Decrypt() }()
				if phase == "server_hello" {
					// Consuming most of the deadline in ClientHello must not grant a
					// fresh timeout to the following ServerHello or secret wait.
					time.Sleep(75 * time.Millisecond)
					hello := append([]byte{0x16, 3, 3, 0, 38, 1, 0, 0, 34, 3, 3}, bytes.Repeat([]byte{0x44}, 32)...)
					if err := decryptor.FeedClient(hello); err != nil {
						t.Fatal(err)
					}
				}
				if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("waiting for %s returned %v, want deadline error", phase, err)
				}
				if elapsed := time.Since(started); elapsed != options.SecretWaitTimeout() {
					t.Fatalf("wait lasted %s, want total deadline %s", elapsed, options.SecretWaitTimeout())
				}
				close(diagnostics)
				found := false
				for diagnostic := range diagnostics {
					found = found || diagnostic.Code == "key_wait_timeout"
				}
				if !found || len(packets) != 0 {
					t.Fatal("timeout lacked a diagnostic or emitted plaintext/end markers")
				}
				assertTLSBuffersReleased(t, decryptor)
				if err := decryptor.Close(); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestTLSCloseCancelsMissingHandshake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		decryptor, packets := newTLSRawTest(types.DecryptOptions{RawChunks: true, KeyWaitTimeout: time.Hour})
		done := make(chan error, 1)
		go func() { done <- decryptor.Decrypt() }()
		synctest.Wait()
		_ = decryptor.Close()
		if err := <-done; err == nil || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("close while waiting for ClientHello returned %v", err)
		}
		if len(packets) != 0 {
			t.Fatal("closed handshake emitted raw end markers")
		}
		assertTLSBuffersReleased(t, decryptor)
	})
}

func TestTLSLateSecretsStopDeadlineAndDrainHTTP10(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		decryptor, packets := newTLSRawTest(types.DecryptOptions{KeyWaitTimeout: time.Second})
		prepareTLS13RawHandshake(t, decryptor, nil)
		secret := bytes.Repeat([]byte{0x11}, 32)
		request := []byte("GET / HTTP/1.0\r\nHost: example.test\r\n\r\n")
		response := []byte("HTTP/1.0 200 OK\r\n\r\nclose-delimited-body")
		if err := decryptor.FeedClient(tls13RawTestRecord(t, secret, 0, request, 0x17)); err != nil {
			t.Fatal(err)
		}
		if err := decryptor.FeedServer(tls13RawTestRecord(t, secret, 0, response, 0x17)); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- decryptor.Decrypt() }()
		synctest.Wait()
		time.Sleep(500 * time.Millisecond)
		random := hex.EncodeToString(bytes.Repeat([]byte{0x44}, 32))
		decryptor.keyLog.AddSecret("CLIENT_TRAFFIC_SECRET_0", random, secret)
		decryptor.keyLog.AddSecret("SERVER_TRAFFIC_SECRET_0", random, secret)
		synctest.Wait()
		if len(packets) != 1 {
			t.Fatal("late secrets lost the request or prematurely completed the response")
		}
		time.Sleep(2 * time.Second)
		if decryptor.isClosed.Load() {
			t.Fatal("handshake deadline remained armed after keys became available")
		}
		_ = decryptor.Close()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if len(packets) != 2 {
			t.Fatalf("got %d HTTP messages, want request and close-delimited response", len(packets))
		}
		if got := <-packets; !bytes.Equal(got.Data, request) {
			t.Fatal("request bytes changed")
		}
		if got := <-packets; !bytes.Equal(got.Data, response) {
			t.Fatal("final HTTP/1.0 response was not drained")
		}
		assertTLSBuffersReleased(t, decryptor)
	})
}

func TestTLSInputLimitTerminatesAndReleases(t *testing.T) {
	for _, direction := range []string{"client", "server"} {
		t.Run(direction, func(t *testing.T) {
			diagnostics := make(chan types.Diagnostic, 8)
			decryptor, packets := newTLSRawTest(types.DecryptOptions{RawChunks: true, OnDiagnostic: func(d types.Diagnostic) {
				diagnostics <- d
			}})
			prepareTLS13RawHandshake(t, decryptor, bytes.Repeat([]byte{0x11}, 32))
			feed := decryptor.FeedClient
			if direction == "server" {
				feed = decryptor.FeedServer
			}
			want := feed(make([]byte, 8<<20)) // The queued Hello already occupies space.
			if want == nil || !decryptor.isClosed.Load() {
				t.Fatal("input limit did not terminate the connection")
			}
			if err := decryptor.Decrypt(); !errors.Is(err, want) {
				t.Fatalf("Decrypt lost the input limit error: %v", err)
			}
			if len(packets) != 0 {
				t.Fatal("input limit failure emitted plaintext/end markers")
			}
			if len(diagnostics) != 1 || (<-diagnostics).Code != "resource_limit" {
				t.Fatal("input limit failure lacked its diagnostic")
			}
			assertTLSBuffersReleased(t, decryptor)
		})
	}
}

func TestTLSServerFirstQueueLimit(t *testing.T) {
	for _, mode := range []string{"library", "stdout"} {
		t.Run(mode, func(t *testing.T) {
			diagnostics := make(chan types.Diagnostic, 8)
			decryptor, packets := newTLSRawTest(types.DecryptOptions{OnDiagnostic: func(d types.Diagnostic) {
				diagnostics <- d
			}})
			if mode == "stdout" {
				decryptor.packetChan = nil
			}
			prepareTLS13RawHandshake(t, decryptor, bytes.Repeat([]byte{0x11}, 32))
			chunk := make([]byte, 1<<20)
			for range 8 {
				decryptor.queueResponse(chunk)
			}
			if mode == "library" && len(decryptor.responseQueue) != 0 {
				t.Fatal("library mode retained redundant stdout response data")
			}
			decryptor.queueResponse([]byte{1})
			if !decryptor.aborted.Load() {
				t.Fatal("server-first response queue exceeded its limit without terminating")
			}
			if err := decryptor.Decrypt(); err == nil || len(packets) != 0 {
				t.Fatalf("queue limit failure was not preserved: err=%v packets=%d", err, len(packets))
			}
			if len(diagnostics) != 1 || (<-diagnostics).Code != "resource_limit" {
				t.Fatal("queue limit failure lacked its diagnostic")
			}
			assertTLSBuffersReleased(t, decryptor)
		})
	}
}

func TestTLSServerFirstTinyChunkCountLimit(t *testing.T) {
	for _, mode := range []string{"library", "stdout"} {
		t.Run(mode, func(t *testing.T) {
			diagnostics := make(chan types.Diagnostic, 8)
			decryptor, packets := newTLSRawTest(types.DecryptOptions{OnDiagnostic: func(d types.Diagnostic) {
				diagnostics <- d
			}})
			if mode == "stdout" {
				decryptor.packetChan = nil
			}
			prepareTLS13RawHandshake(t, decryptor, bytes.Repeat([]byte{0x11}, 32))
			for range tlsPendingResponseCount {
				decryptor.queueResponse([]byte{1})
			}
			if decryptor.aborted.Load() || len(diagnostics) != 0 {
				t.Fatal("tiny chunks exhausted the quota before its object limit")
			}
			decryptor.queueResponse([]byte{1})
			if !decryptor.aborted.Load() || len(decryptor.pendingResponses) > tlsPendingResponseCount || len(decryptor.responseQueue) > tlsPendingResponseCount {
				t.Fatal("tiny chunk object overflow did not stop at its quota")
			}
			if err := decryptor.Decrypt(); err == nil || len(packets) != 0 {
				t.Fatalf("tiny chunk overflow did not preserve failure: err=%v packets=%d", err, len(packets))
			}
			if len(diagnostics) != 1 || (<-diagnostics).Code != "resource_limit" {
				t.Fatal("tiny chunk overflow lacked its resource diagnostic")
			}
			assertTLSBuffersReleased(t, decryptor)
		})
	}
}

func assertTLSBuffersReleased(t *testing.T, decryptor *TLSDecryptor) {
	t.Helper()
	if decryptor.clientIn.Len() != 0 || decryptor.serverIn.Len() != 0 || decryptor.parser != nil ||
		decryptor.sniffBuffer != nil || decryptor.pendingResponses != nil || decryptor.pendingResponseBytes != 0 ||
		decryptor.requestQueue != nil || decryptor.responseQueue != nil || decryptor.responseQueueBytes != 0 {
		t.Fatal("finished TLS decryptor retained buffered input or output")
	}
}
