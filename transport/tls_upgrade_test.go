// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

type upgradeTestStep struct {
	client bool
	data   []byte
}

func upgradeTestBER(tag byte, value []byte) []byte {
	return append([]byte{tag, byte(len(value))}, value...)
}

func upgradeTestLDAP(response bool, code byte) []byte {
	op := byte(0x77)
	body := upgradeTestBER(0x80, []byte("1.3.6.1.4.1.1466.20037"))
	if response {
		op = 0x78
		body = []byte{0x0a, 1, code, 4, 0, 4, 0}
	}
	return upgradeTestBER(0x30, append([]byte{2, 1, 1}, upgradeTestBER(op, body)...))
}

func upgradeTestMySQL(ssl bool) []byte {
	body := append([]byte{10}, []byte("8.0-test\x00")...)
	body = append(body, 1, 0, 0, 0)
	body = append(body, []byte("12345678\x00")...)
	caps := uint16(0x8200)
	if ssl {
		caps |= 0x800
	}
	body = binary.LittleEndian.AppendUint16(body, caps)
	body = append(body, 45, 2, 0, 0, 0, 0)
	body = append(body, make([]byte, 10)...)
	return append([]byte{byte(len(body)), 0, 0, 0}, body...)
}

func upgradeTestTranscript(mode string, accepted bool) []upgradeTestStep {
	client := func(s string) upgradeTestStep { return upgradeTestStep{true, []byte(s)} }
	server := func(s string) upgradeTestStep { return upgradeTestStep{false, []byte(s)} }
	switch mode {
	case "smtp":
		result := "220 begin TLS\r\n"
		if !accepted {
			result = "454 unavailable\r\n"
		}
		return []upgradeTestStep{server("220-greeting\r\n220 ready\r\n"), client("EHLO example\r\n"), server("250-example\r\n250-STARTTLS\r\n250 OK\r\n"), client("STARTTLS\r\n"), server(result)}
	case "imap":
		result := "a2 OK begin TLS\r\n"
		if !accepted {
			result = "a2 NO unavailable\r\n"
		}
		return []upgradeTestStep{server("* OK greeting\r\n"), client("a1 CAPABILITY\r\n"), server("* CAPABILITY IMAP4rev1 STARTTLS\r\na1 OK done\r\n"), client("a2 STARTTLS\r\n"), server("* OK still plaintext\r\n" + result)}
	case "pop3":
		result := "+OK begin TLS\r\n"
		if !accepted {
			result = "-ERR unavailable\r\n"
		}
		return []upgradeTestStep{server("+OK greeting\r\n"), client("CAPA\r\n"), server("+OK capabilities\r\nSTLS\r\n+OK fake acceptance\r\n.\r\n"), client("STLS\r\n"), server(result)}
	case "ldap":
		code := byte(0)
		if !accepted {
			code = 52
		}
		return []upgradeTestStep{{true, upgradeTestLDAP(false, 0)}, {false, upgradeTestLDAP(true, code)}}
	case "postgres":
		result := "S"
		if !accepted {
			result = "N"
		}
		return []upgradeTestStep{{true, []byte{0, 0, 0, 8, 4, 210, 22, 47}}, server(result)}
	case "mysql":
		steps := []upgradeTestStep{{false, upgradeTestMySQL(accepted)}}
		if accepted {
			request := make([]byte, 36)
			request[0], request[3] = 32, 1
			binary.LittleEndian.PutUint32(request[4:], 0x8a00)
			request[12] = 45
			steps = append(steps, upgradeTestStep{true, request})
		}
		return steps
	default:
		result := "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 Tunnel\r\nContent-Length: ignored\r\nTransfer-Encoding: ignored\r\n\r\n"
		if !accepted {
			result = "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 99\r\n\r\n"
		}
		return []upgradeTestStep{client("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n"), server(result)}
	}
}

var upgradeTestModes = []string{"smtp", "imap", "pop3", "ldap", "postgres", "mysql", "connect"}

func collectUpgradeChunks(got *[2][2][]byte, chunks []tlsUpgradeChunk) {
	for _, chunk := range chunks {
		dir, encrypted := 1, 0
		if chunk.client {
			dir = 0
		}
		if chunk.tls {
			encrypted = 1
		}
		got[encrypted][dir] = append(got[encrypted][dir], chunk.data...)
	}
}

func TestTLSUpgradeFragmentationAndExactHandoff(t *testing.T) {
	for _, mode := range upgradeTestModes {
		for _, ordering := range []string{"one_byte", "coalesced", "server_first", "client_first"} {
			t.Run(mode+"/"+ordering, func(t *testing.T) {
				u, err := newTLSUpgrade(mode)
				if err != nil {
					t.Fatal(err)
				}
				steps := upgradeTestTranscript(mode, true)
				var want, got [2][2][]byte
				for _, step := range steps {
					dir := 1
					if step.client {
						dir = 0
					}
					want[0][dir] = append(want[0][dir], step.data...)
				}
				// Boundary detection must preserve arbitrary trailing bytes without
				// searching for or validating a TLS magic byte inside the tail.
				want[1] = [2][]byte{{0x80, 0, 0x16, 3, 3, '\r', '\n'}, {0x17, 3, 3, 0, 1, 0}}
				if ordering == "server_first" || ordering == "client_first" {
					c := append(bytes.Clone(want[0][0]), want[1][0]...)
					s := append(bytes.Clone(want[0][1]), want[1][1]...)
					steps = []upgradeTestStep{{false, s}, {true, c}}
					if ordering == "client_first" {
						steps[0], steps[1] = steps[1], steps[0]
					}
				} else {
					for side := 0; side < 2; side++ {
						for i := len(steps) - 1; i >= 0; i-- {
							if steps[i].client == (side == 0) {
								steps[i].data = append(bytes.Clone(steps[i].data), want[1][side]...)
								break
							}
						}
					}
				}
				for _, step := range steps {
					data := step.data
					for len(data) > 0 {
						n := len(data)
						if ordering == "one_byte" {
							n = 1
						}
						chunks, err := u.Feed(data[:n], step.client)
						if err != nil {
							t.Fatal(err)
						}
						collectUpgradeChunks(&got, chunks)
						data = data[n:]
					}
				}
				if !u.Upgraded() || !u.Finished() || u.Close() != nil {
					t.Fatalf("upgrade not completed: %+v", u)
				}
				for encrypted := range want {
					for dir := range want[encrypted] {
						if !bytes.Equal(got[encrypted][dir], want[encrypted][dir]) {
							t.Fatalf("TLS=%d direction=%d got %x want %x", encrypted, dir, got[encrypted][dir], want[encrypted][dir])
						}
					}
				}
				if _, err := u.Feed([]byte{1}, true); !errors.Is(err, io.ErrClosedPipe) {
					t.Fatal("feed after close", err)
				}
			})
		}
	}
}

func TestTLSUpgradeRefusalPermanentlyPreservesPlaintext(t *testing.T) {
	for _, mode := range upgradeTestModes {
		t.Run(mode, func(t *testing.T) {
			u, _ := newTLSUpgrade(mode)
			steps := upgradeTestTranscript(mode, false)
			fake := []byte("\x16\x03\x03\x00\x10not-a-TLS-record\r\nSTARTTLS\r\n")
			steps = append(steps, upgradeTestStep{true, fake}, upgradeTestStep{false, []byte("220 fake success\r\n+OK\r\na2 OK\r\nHTTP/1.1 200 OK\r\n\r\n")})
			var got, want [2][2][]byte
			for _, step := range steps {
				dir := 1
				if step.client {
					dir = 0
				}
				want[0][dir] = append(want[0][dir], step.data...)
				chunks, err := u.Feed(step.data, step.client)
				if err != nil {
					t.Fatal(err)
				}
				collectUpgradeChunks(&got, chunks)
			}
			if u.Upgraded() || !u.Finished() || u.Close() != nil {
				t.Fatal("refused upgrade was not retained as plaintext")
			}
			for i := range want[0] {
				if !bytes.Equal(got[0][i], want[0][i]) || len(got[1][i]) != 0 {
					t.Fatal("refusal lost plaintext or emitted fake TLS")
				}
			}
		})
	}
}

func TestTLSUpgradeUnsupportedPlaintextCannotTriggerLaterUpgrade(t *testing.T) {
	for _, tc := range []struct {
		mode, greeting string
		command        []byte
	}{
		{"smtp", "220 ready\r\n", []byte("MAIL FROM:<test@example.test>\r\nDATA\r\nSTARTTLS\r\n")},
		{"imap", "* OK ready\r\n", []byte("a1 LOGIN user {20}\r\na2 STARTTLS\r\n")},
		{"pop3", "+OK ready\r\n", []byte("USER test\r\nSTLS\r\n")},
		{"ldap", "", []byte{0x30, 5, 2, 1, 1, 0x60, 0}},
		{"postgres", "", []byte{0, 0, 0, 8, 4, 210, 22, 48}},
		{"connect", "", []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\nCONNECT example.test:443 HTTP/1.1\r\n\r\n")},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			u, _ := newTLSUpgrade(tc.mode)
			if _, err := u.Feed([]byte(tc.greeting), false); err != nil {
				t.Fatal(err)
			}
			if _, err := u.Feed(tc.command, true); err != nil {
				t.Fatal(err)
			}
			if !u.Finished() || u.Upgraded() {
				t.Fatal("unsupported command did not stop upgrade detection")
			}
			chunks, err := u.Feed([]byte("220 success\r\n\x16\x03\x03"), false)
			if err != nil || len(chunks) != 1 || chunks[0].tls {
				t.Fatal("message content was mistaken for upgrade")
			}
		})
	}
}

func TestTLSUpgradeMalformedAndTruncated(t *testing.T) {
	for _, tc := range []struct {
		name, mode string
		steps      []upgradeTestStep
	}{
		{"smtp_multiline_code", "smtp", []upgradeTestStep{{false, []byte("220-first\r\n250 mismatch\r\n")}}},
		{"smtp_bare_lf", "smtp", []upgradeTestStep{{false, []byte("220 ready\n")}}},
		{"imap_wrong_tag", "imap", []upgradeTestStep{{false, []byte("* OK ready\r\n")}, {true, []byte("a1 STARTTLS\r\n")}, {false, []byte("a2 OK ready\r\n")}}},
		{"ldap_indefinite", "ldap", []upgradeTestStep{{true, []byte{0x30, 0x80}}}},
		{"ldap_wrong_id", "ldap", []upgradeTestStep{{true, upgradeTestLDAP(false, 0)}, {false, []byte{0x30, 12, 2, 1, 2, 0x78, 7, 0xa, 1, 0, 4, 0, 4, 0}}}},
		{"postgres_wrong_reply", "postgres", []upgradeTestStep{{true, []byte{0, 0, 0, 8, 4, 210, 22, 47}}, {false, []byte("Y")}}},
		{"mysql_sequence", "mysql", []upgradeTestStep{{false, []byte{1, 0, 0, 1, 10}}}},
		{"connect_body", "connect", []upgradeTestStep{{true, []byte("CONNECT host:443 HTTP/1.1\r\nContent-Length: 10\r\n\r\n")}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, _ := newTLSUpgrade(tc.mode)
			var err error
			for _, step := range tc.steps {
				_, err = u.Feed(step.data, step.client)
			}
			if !errors.Is(err, errTLSUpgrade) || u.Upgraded() || u.Close() != err || len(u.buf[0])+len(u.buf[1]) != 0 {
				t.Fatalf("malformed negotiation state: err=%v upgraded=%v", err, u.Upgraded())
			}
		})
	}
	for _, mode := range upgradeTestModes {
		t.Run(mode+"/truncated", func(t *testing.T) {
			u, _ := newTLSUpgrade(mode)
			steps := upgradeTestTranscript(mode, true)
			for i, step := range steps {
				if i == len(steps)-1 {
					step.data = step.data[:len(step.data)-1]
				}
				if _, err := u.Feed(step.data, step.client); err != nil {
					t.Fatal(err)
				}
			}
			if err := u.Close(); !errors.Is(err, io.ErrUnexpectedEOF) || u.Upgraded() {
				t.Fatal("incomplete negotiation accepted", err)
			}
		})
	}
	for _, authority := range []string{"host:0", "host:65536", "host:+443", "user@host:443", "host/path:443", "host?query:443", "host#fragment:443", "[not-an-ip]:443"} {
		t.Run(authority, func(t *testing.T) {
			u, _ := newTLSUpgrade("connect")
			if _, err := u.Feed([]byte("CONNECT "+authority+" HTTP/1.1\r\n\r\n"), true); !errors.Is(err, errTLSUpgrade) {
				t.Fatal("invalid CONNECT authority accepted", err)
			}
		})
	}
}

func TestTLSUpgradeLimitsAndOwnedOutput(t *testing.T) {
	u, _ := newTLSUpgrade("smtp")
	_, _ = u.Feed([]byte("220 ready\r\n"), false)
	_, _ = u.Feed([]byte("STARTTLS\r\n"), true)
	if _, err := u.Feed(bytes.Repeat([]byte{'x'}, maxTLSUpgradeBuffer), true); err != nil {
		t.Fatal(err)
	}
	if _, err := u.Feed([]byte{1}, true); !errors.Is(err, errTLSUpgradeLimit) || len(u.buf[0]) != 0 {
		t.Fatal("candidate buffer limit", err)
	}
	u, _ = newTLSUpgrade("ldap")
	if _, err := u.Feed([]byte{0x30, 0x83, 1, 0, 0}, true); !errors.Is(err, errTLSUpgradeLimit) {
		t.Fatal("declared BER limit", err)
	}
	u, _ = newTLSUpgrade("smtp")
	_, _ = u.Feed([]byte("220 ready\r\n"), false)
	var err error
	for i := 0; i < 300 && err == nil; i++ {
		_, err = u.Feed([]byte("NOOP\r\n"), true)
		if err == nil {
			_, err = u.Feed([]byte("250 "+strings.Repeat("x", 4096)+"\r\n"), false)
		}
	}
	if !errors.Is(err, errTLSUpgradeLimit) {
		t.Fatal("aggregate prelude limit", err)
	}
	u, _ = newTLSUpgrade("postgres")
	_, _ = u.Feed([]byte{0, 0, 0, 8, 4, 210, 22, 47}, true)
	_, _ = u.Feed([]byte("S"), false)
	data := bytes.Repeat([]byte{'x'}, 2*maxTLSUpgradeBytes)
	chunks, err := u.Feed(data, true)
	if err != nil || len(chunks) != 1 || !chunks[0].tls || len(chunks[0].data) != len(data) {
		t.Fatal("post-upgrade TLS was charged to prelude budget", err)
	}
	data[0] = 0
	if chunks[0].data[0] != 'x' {
		t.Fatal("output aliases caller input")
	}
}

func FuzzTLSUpgradeFragments(f *testing.F) {
	for i, mode := range upgradeTestModes {
		var client, server []byte
		for _, step := range upgradeTestTranscript(mode, true) {
			if step.client {
				client = append(client, step.data...)
			} else {
				server = append(server, step.data...)
			}
		}
		f.Add(uint8(i), client, server, uint8(7))
	}
	f.Fuzz(func(t *testing.T, mode uint8, client, server []byte, size uint8) {
		if len(client)+len(server) > maxTLSUpgradeBytes {
			return
		}
		u, _ := newTLSUpgrade(upgradeTestModes[int(mode)%len(upgradeTestModes)])
		for len(client)+len(server) > 0 {
			for side := 0; side < 2; side++ {
				data := &client
				if side == 1 {
					data = &server
				}
				n := min(len(*data), int(size)+1)
				chunks, err := u.Feed((*data)[:n], side == 0)
				*data = (*data)[n:]
				for _, chunk := range chunks {
					if chunk.tls && !u.Upgraded() {
						t.Fatal("TLS output before successful boundary")
					}
				}
				if err != nil {
					_ = u.Close()
					return
				}
				if len(u.buf[0]) > maxTLSUpgradeBuffer || len(u.buf[1]) > maxTLSUpgradeBuffer || u.total > maxTLSUpgradeBytes {
					t.Fatal("unbounded negotiation")
				}
			}
		}
		_ = u.Close()
	})
}
