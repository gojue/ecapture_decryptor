// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package transport

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gojue/ecapture_decryptor/types"
)

func newTLSUpgradeTest(options types.DecryptOptions, capacity int) (*TLSDecryptorWrapper, chan *types.DecryptedPacket) {
	base, _ := newTLSRawTest(types.DecryptOptions{})
	packets := make(chan *types.DecryptedPacket, capacity)
	wrapper := NewTLSDecryptorLibrary(base.ConnectionInfo, base.keyLog, base.clientOut, base.serverOut, base.logger, packets).(*TLSDecryptorWrapper)
	wrapper.SetOptions(options)
	return wrapper, packets
}

func tlsUpgradeTestHellos(random byte) (client, server []byte) {
	c := append([]byte{3, 3}, bytes.Repeat([]byte{random}, 32)...)
	c = append(c, 0, 0, 2, 0x13, 1, 1, 0, 0, 7, 0, 43, 0, 3, 2, 3, 4)
	s := append([]byte{3, 3}, bytes.Repeat([]byte{0x55}, 32)...)
	s = append(s, 0, 0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4)
	client = append([]byte{0x16, 3, 3, 0, byte(4 + len(c)), 1, 0, 0, byte(len(c))}, c...)
	server = append([]byte{0x16, 3, 3, 0, byte(4 + len(s)), 2, 0, 0, byte(len(s))}, s...)
	return client, server
}

func tlsUpgradeTestSecrets(w *TLSDecryptorWrapper, random byte, secret []byte) {
	id := hex.EncodeToString(bytes.Repeat([]byte{random}, 32))
	w.keyLog.AddSecret("CLIENT_TRAFFIC_SECRET_0", id, secret)
	w.keyLog.AddSecret("SERVER_TRAFFIC_SECRET_0", id, secret)
}

func TestTLSUpgradeEmptyCloseAndDeadline(t *testing.T) {
	for _, mode := range []string{"smtp", "imap", "pop3", "ldap", "postgres", "mysql", "connect", "https-connect"} {
		for _, timeout := range []bool{false, true} {
			t.Run(mode+map[bool]string{false: "/close", true: "/timeout"}[timeout], func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					w, packets := newTLSUpgradeTest(types.DecryptOptions{TLSUpgrade: mode, KeyWaitTimeout: time.Second}, 8)
					done := make(chan error, 1)
					go func() { done <- w.Decrypt() }()
					synctest.Wait()
					if timeout {
						time.Sleep(time.Second)
					} else {
						_ = w.Close()
						_ = w.Close()
					}
					err := <-done
					if timeout && !errors.Is(err, context.DeadlineExceeded) || !timeout && mode != "https-connect" && err != nil {
						t.Fatalf("unexpected terminal error: %v", err)
					}
					if len(packets) != 0 || w.upgrade.inner != nil {
						t.Fatal("empty negotiation created TLS output or a child")
					}
					_ = w.Close()
				})
			})
		}
	}
}

func TestTLSUpgradeRefusalKeepsPlaintextAndStopsDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w, packets := newTLSUpgradeTest(types.DecryptOptions{TLSUpgrade: "postgres", KeyWaitTimeout: time.Second}, 8)
		done := make(chan error, 1)
		go func() { done <- w.Decrypt() }()
		request := []byte{0, 0, 0, 8, 4, 210, 22, 47}
		if err := w.FeedClient(request); err != nil {
			t.Fatal(err)
		}
		if err := w.FeedServer([]byte("N")); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		time.Sleep(2 * time.Second)
		fakeTLS := []byte("\x16\x03\x03\x00\x10not-a-TLS-record")
		if err := w.FeedClient(fakeTLS); err != nil {
			t.Fatal(err)
		}
		_ = w.CloseClient()
		_ = w.CloseServer()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if len(packets) != 3 || w.upgrade.inner != nil {
			t.Fatal("refusal lost plaintext or started TLS")
		}
		for _, want := range [][]byte{request, []byte("N"), fakeTLS} {
			p := <-packets
			if p.Protocol != "starttls" || p.Metadata["tls_depth"] != 0 || !bytes.Equal(p.Data, want) {
				t.Fatalf("incorrect plaintext packet: %+v", p)
			}
		}
	})
}

func TestTLSUpgradeLateKeysAfterFINAndExactHandoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w, packets := newTLSUpgradeTest(types.DecryptOptions{TLSUpgrade: "postgres", RawChunks: true, KeyWaitTimeout: time.Second}, 16)
		done := make(chan error, 1)
		go func() { done <- w.Decrypt() }()
		client, server := tlsUpgradeTestHellos(0x44)
		secret := bytes.Repeat([]byte{0x11}, 32)
		request, response := []byte("client\x00"), []byte("server\xff")
		client = append(client, tls13RawTestRecord(t, secret, 0, request, 0x17)...)
		server = append(server, tls13RawTestRecord(t, secret, 0, response, 0x17)...)
		prelude := append([]byte{0, 0, 0, 8, 4, 210, 22, 47}, client...)
		for _, b := range prelude {
			if err := w.FeedClient([]byte{b}); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.FeedServer(append([]byte("S"), server...)); err != nil {
			t.Fatal(err)
		}
		_ = w.CloseClient()
		_ = w.CloseServer()
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("FIN canceled late-key wait: %v", err)
		default:
		}
		time.Sleep(500 * time.Millisecond)
		tlsUpgradeTestSecrets(w, 0x44, secret)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		var plaintext [2][]byte
		for len(packets) > 0 {
			p := <-packets
			if p.Protocol != "tls" {
				continue
			}
			i := 1
			if p.Direction == "request" {
				i = 0
			}
			if p.Metadata["tls_depth"] != 1 || p.Metadata["parent_tls_depth"] != 0 || p.ConnectionID() != w.GetAddr().String() || p.Metadata["offset"] != uint64(len(plaintext[i])) {
				t.Fatal("invalid layer metadata or offset", p.Metadata)
			}
			plaintext[i] = append(plaintext[i], p.Data...)
		}
		if !bytes.Equal(plaintext[0], request) || !bytes.Equal(plaintext[1], response) {
			t.Fatal("TLS handoff lost or duplicated bytes", plaintext)
		}
		assertTLSBuffersReleased(t, w.upgrade.inner)
	})
}

func TestTLSUpgradeOneDeadlineAcrossNegotiationAndTLS(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w, _ := newTLSUpgradeTest(types.DecryptOptions{TLSUpgrade: "postgres", RawChunks: true, KeyWaitTimeout: time.Second}, 16)
		done := make(chan error, 1)
		started := time.Now()
		go func() { done <- w.Decrypt() }()
		synctest.Wait()
		time.Sleep(750 * time.Millisecond)
		_ = w.FeedClient([]byte{0, 0, 0, 8, 4, 210, 22, 47})
		_ = w.FeedServer([]byte("S"))
		if err := <-done; !errors.Is(err, context.DeadlineExceeded) || time.Since(started) != time.Second {
			t.Fatalf("upgrade restarted the deadline: %v, elapsed=%v", err, time.Since(started))
		}
		assertTLSBuffersReleased(t, w.upgrade.inner)
	})
}

func TestTLSUpgradeNegotiationBackpressureAndTruncation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w, packets := newTLSUpgradeTest(types.DecryptOptions{TLSUpgrade: "postgres"}, 0)
		fed := make(chan error, 1)
		go func() { fed <- w.FeedClient([]byte{0, 0, 0, 8, 4, 210, 22, 47}) }()
		synctest.Wait()
		select {
		case <-fed:
			t.Fatal("slow consumer did not apply backpressure")
		default:
		}
		p := <-packets
		if p.Metadata["kind"] != "negotiation_chunk" || len(p.Data) != 8 {
			t.Fatal(p)
		}
		if err := <-fed; err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		if err := w.Decrypt(); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("missing upgrade response returned %v", err)
		}
	})
}

func TestTLSUpgradeHTTPSNestedLateSecretsAndEOFDrain(t *testing.T) {
	for _, mode := range []string{"late_inner", "close_before_drain", "missing_inner"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				diagnostics := make(chan types.Diagnostic, 16)
				w, packets := newTLSUpgradeTest(types.DecryptOptions{TLSUpgrade: "https-connect", RawChunks: true, KeyWaitTimeout: time.Second, OnDiagnostic: func(d types.Diagnostic) { diagnostics <- d }}, 32)
				outerSecret, innerSecret := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)
				outerClient, outerServer := tlsUpgradeTestHellos(0x44)
				innerClient, innerServer := tlsUpgradeTestHellos(0x66)
				request, response := []byte("request\x00"), []byte("response\xff")
				connect := []byte("CONNECT origin.example:443 HTTP/1.1\r\nHost: origin.example:443\r\n\r\n")
				accepted := []byte("HTTP/1.1 200 Connection Established\r\n\r\n")
				clientWire := append(innerClient, tls13RawTestRecord(t, innerSecret, 0, request, 0x17)...)
				serverWire := append(innerServer, tls13RawTestRecord(t, innerSecret, 0, response[:1], 0x17)...)
				serverTail := tls13RawTestRecord(t, innerSecret, 1, response[1:], 0x17)
				outerClient = append(outerClient, tls13RawTestRecord(t, outerSecret, 0, connect, 0x17)...)
				outerClient = append(outerClient, tls13RawTestRecord(t, outerSecret, 1, clientWire, 0x17)...)
				outerServer = append(outerServer, tls13RawTestRecord(t, outerSecret, 0, append(bytes.Clone(accepted), serverWire...), 0x17)...)
				outerServer = append(outerServer, tls13RawTestRecord(t, outerSecret, 1, serverTail, 0x17)...)
				done := make(chan error, 1)
				go func() { done <- w.Decrypt() }()
				if err := w.FeedClient(outerClient); err != nil {
					t.Fatal(err)
				}
				if err := w.FeedServer(outerServer); err != nil {
					t.Fatal(err)
				}
				_ = w.CloseClient()
				_ = w.CloseServer()
				synctest.Wait()
				if mode == "close_before_drain" {
					tlsUpgradeTestSecrets(w, 0x66, innerSecret)
				}
				tlsUpgradeTestSecrets(w, 0x44, outerSecret)
				if mode == "close_before_drain" {
					_ = w.Close()
				} else {
					synctest.Wait()
					select {
					case err := <-done:
						t.Fatalf("outer FIN canceled inner secret wait: %v", err)
					default:
					}
					if mode == "late_inner" {
						time.Sleep(500 * time.Millisecond)
						tlsUpgradeTestSecrets(w, 0x66, innerSecret)
					} else {
						_ = w.Close()
					}
				}
				err := <-done
				if (err != nil) != (mode == "missing_inner") {
					t.Fatalf("nested termination: %v", err)
				}
				var outerData, innerData [2][]byte
				for len(packets) > 0 {
					p := <-packets
					if p.Protocol != "tls" {
						continue
					}
					i := 1
					if p.Direction == "request" {
						i = 0
					}
					depth := p.Metadata["tls_depth"].(int)
					if p.ConnectionID() != w.GetAddr().String() || p.Metadata["parent_tls_depth"] != depth-1 {
						t.Fatal("nested identity changed", p.Metadata)
					}
					if depth == 1 {
						outerData[i] = append(outerData[i], p.Data...)
					} else {
						innerData[i] = append(innerData[i], p.Data...)
					}
				}
				if !bytes.Equal(outerData[0], append(bytes.Clone(connect), clientWire...)) || !bytes.Equal(outerData[1], append(append(bytes.Clone(accepted), serverWire...), serverTail...)) {
					t.Fatal("outer authenticated bytes changed or vanished")
				}
				if mode == "missing_inner" {
					if len(innerData[0])+len(innerData[1]) != 0 {
						t.Fatal("missing keys emitted inner plaintext")
					}
					found := false
					for len(diagnostics) > 0 {
						d := <-diagnostics
						found = found || d.Stage == "tunnel" && d.Code == "inner_tls_unavailable"
					}
					if !found {
						t.Fatal("missing inner boundary diagnostic")
					}
				} else if !bytes.Equal(innerData[0], request) || !bytes.Equal(innerData[1], response) {
					t.Fatal("inner handoff lost authenticated application bytes")
				}
				assertTLSBuffersReleased(t, w.upgrade.inner)
				assertTLSBuffersReleased(t, w.upgrade.outer)
			})
		})
	}
}

func TestTLSUpgradeInnerDeadlinePreservesLaterOuterBytes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w, packets := newTLSUpgradeTest(types.DecryptOptions{TLSUpgrade: "https-connect", RawChunks: true, KeyWaitTimeout: time.Second}, 32)
		outerSecret, innerSecret := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)
		outerClient, outerServer := tlsUpgradeTestHellos(0x44)
		innerClient, innerServer := tlsUpgradeTestHellos(0x66)
		tlsUpgradeTestSecrets(w, 0x44, outerSecret)
		_ = w.FeedClient(outerClient)
		_ = w.FeedServer(outerServer)
		done := make(chan error, 1)
		go func() { done <- w.Decrypt() }()
		synctest.Wait()
		request := append([]byte("CONNECT origin.example:443 HTTP/1.1\r\nHost: origin.example:443\r\n\r\n"), innerClient...)
		response := append([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"), innerServer...)
		_ = w.FeedClient(tls13RawTestRecord(t, outerSecret, 0, request, 0x17))
		_ = w.FeedServer(tls13RawTestRecord(t, outerSecret, 0, response, 0x17))
		synctest.Wait()
		time.Sleep(time.Second)
		synctest.Wait()
		if w.upgrade.outer.isClosed.Load() || !w.upgrade.inner.isClosed.Load() {
			t.Fatal("inner timeout must close only the inner layer")
		}
		late := tls13RawTestRecord(t, innerSecret, 0, []byte("after-inner-timeout"), 0x17)
		if err := w.FeedServer(tls13RawTestRecord(t, outerSecret, 1, late, 0x17)); err != nil {
			t.Fatal("inner timeout rejected subsequent outer data", err)
		}
		_ = w.CloseClient()
		_ = w.CloseServer()
		if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("inner deadline disappeared: %v", err)
		}
		var got []byte
		for len(packets) > 0 {
			p := <-packets
			if p.Metadata["tls_depth"] == 2 {
				t.Fatal("missing inner keys emitted plaintext")
			}
			if p.Protocol == "tls" && p.Direction == "response" {
				got = append(got, p.Data...)
			}
		}
		if !bytes.Equal(got, append(response, late...)) {
			t.Fatal("outer bytes after inner deadline were lost")
		}
	})
}

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

func TestTLSWebSocketSplitUpgradeAndMalformedFrame(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			diagnostic := make(chan types.Diagnostic, 8)
			td, packets := newTLSRawTest(types.DecryptOptions{OnDiagnostic: func(d types.Diagnostic) { diagnostic <- d }})
			secret := bytes.Repeat([]byte{0x11}, 32)
			prepareTLS13RawHandshake(t, td, secret)
			done := make(chan error, 1)
			go func() { done <- td.Decrypt() }()
			request := []byte("GET /chat HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
			for i, part := range [][]byte{request[:4], request[4:35], request[35:]} {
				if err := td.FeedClient(tls13RawTestRecord(t, secret, uint64(i), part, 0x17)); err != nil {
					t.Fatal(err)
				}
			}
			response := []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
			response = append(response, 0x81, 2, 'o', 'k')
			if malformed {
				response[len(response)-4] = 0x83
			}
			for i, part := range [][]byte{response[:20], response[20:]} {
				if err := td.FeedServer(tls13RawTestRecord(t, secret, uint64(i), part, 0x17)); err != nil {
					t.Fatal(err)
				}
			}
			_ = td.Close()
			err := <-done
			if (err != nil) != malformed {
				t.Fatalf("malformed %v: %v", malformed, err)
			}
			expected := 3
			if malformed {
				expected = 2
			}
			if len(packets) != expected {
				t.Fatalf("got %d packets", len(packets))
			}
			for len(packets) > 0 {
				if packet := <-packets; packet.Protocol != "websocket" {
					t.Fatal(packet.Protocol)
				}
			}
			if malformed {
				found := false
				for len(diagnostic) > 0 {
					d := <-diagnostic
					found = found || d.Stage == "protocol" && d.Code == "parse_failed"
				}
				if !found {
					t.Fatal("missing payload-free parser diagnostic")
				}
			}
			assertTLSBuffersReleased(t, td)
		})
	}
}

func TestExplicitTLSProtocolSelectionFragments(t *testing.T) {
	for _, tc := range []struct {
		name           string
		client, server []byte
		protocol       string
		responseFirst  bool
	}{
		{"mqtt", []byte{0x10, 13, 0, 4, 'M', 'Q', 'T', 'T', 4, 2, 0, 0, 0, 1, 'c'}, []byte{0x20, 2, 0, 0}, "mqtt", false},
		{"redis", []byte("*1\r\n$4\r\nPING\r\n"), []byte("+PONG\r\n"), "redis", false},
		{"redis", []byte("*1\r\n$4\r\nPING\r\n"), []byte("+PONG\r\n"), "redis", true},
		{"dot", []byte{0, 17, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1}, []byte{0, 17, 0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1}, "dns", false},
	} {
		name := tc.name
		if tc.responseFirst {
			name += "/response-first"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				td, out := newTLSRawTest(types.DecryptOptions{ApplicationProtocol: tc.name})
				secret := bytes.Repeat([]byte{0x11}, 32)
				prepareTLS13RawHandshake(t, td, secret)
				done := make(chan error, 1)
				go func() { done <- td.Decrypt() }()
				synctest.Wait()
				for i, v := range tc.client {
					if i == 1 && tc.responseFirst {
						if err := td.FeedServer(tls13RawTestRecord(t, secret, 0, tc.server, 0x17)); err != nil {
							t.Fatal(err)
						}
					}
					if err := td.FeedClient(tls13RawTestRecord(t, secret, uint64(i), []byte{v}, 0x17)); err != nil {
						t.Fatal(err)
					}
				}
				if !tc.responseFirst {
					if err := td.FeedServer(tls13RawTestRecord(t, secret, 0, tc.server, 0x17)); err != nil {
						t.Fatal(err)
					}
				}
				_ = td.Close()
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				if len(out) != 2 {
					t.Fatalf("got %d messages", len(out))
				}
				for len(out) > 0 {
					p := <-out
					if p.Protocol != tc.protocol {
						t.Fatal(p.Protocol)
					}
					if tc.protocol == "redis" && (p.Metadata["request_id"] != uint64(1) || p.Metadata["command"] != "PING") {
						t.Fatal("unpaired Redis exchange", p.Metadata)
					}
				}
				assertTLSBuffersReleased(t, td)
			})
		})
	}
}
