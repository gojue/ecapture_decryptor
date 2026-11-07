//go:build ignore

// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

// Run explicitly with Go 1.26. Independent crypto/tls peers create real TCP
// traffic; the observer only logs RFC 9850 ECH material, never rewrites packets.
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type keyWriter struct {
	mu sync.Mutex
	f  *os.File
}

func (w *keyWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.f.Write(b)
}

func vector(b []byte) []byte { return append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...) }

func echConfig(id byte) (*ecdh.PrivateKey, []byte, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	b := []byte{id, 0, 0x20}
	b = append(b, vector(key.PublicKey().Bytes())...)
	b = append(b, 0, 4, 0, 1, 0, 1) // HKDF-SHA256, AES-128-GCM.
	name := "public.example"
	b = append(b, 0, byte(len(name)))
	b = append(b, name...)
	b = append(b, 0, 0) // No config extensions.
	return key, append([]byte{0xfe, 0x0d}, vector(b)...), nil
}

// A generator-owned recipient private key and the actual transmitted enc are
// sufficient to independently reconstruct DHKEM's shared_secret (RFC 9180 4.1).
// This is not an HPKE exporter secret. No SDK or TLS implementation internals
// are imported, and standard TLS traffic secrets still come from KeyLogWriter.
func kemSecret(key *ecdh.PrivateKey, enc []byte) ([]byte, error) {
	public, err := ecdh.X25519().NewPublicKey(enc)
	if err != nil {
		return nil, err
	}
	dh, err := key.ECDH(public)
	if err != nil {
		return nil, err
	}
	suite := []byte{'K', 'E', 'M', 0, 0x20}
	input := append(append([]byte("HPKE-v1"), suite...), []byte("eae_prk")...)
	prk, err := hkdf.Extract(sha256.New, append(input, dh...), nil)
	if err != nil {
		return nil, err
	}
	info := append([]byte{0, 32}, []byte("HPKE-v1")...)
	info = append(info, suite...)
	info = append(info, []byte("shared_secret")...)
	info = append(info, enc...)
	info = append(info, key.PublicKey().Bytes()...)
	return hkdf.Expand(sha256.New, prk, string(info), 32)
}

type echObserver struct {
	net.Conn
	key                              *ecdh.PrivateKey
	config                           []byte
	keys                             io.Writer
	record, hello                    []byte
	logged                           bool
	clientHellos, hrrs, secondEncLen int
	serverRecord, serverHello        []byte
}

func (o *echObserver) Write(b []byte) (int, error) {
	n, err := o.Conn.Write(b)
	if err == nil {
		err = o.observe(b[:n])
	}
	return n, err
}

func (o *echObserver) Read(b []byte) (int, error) {
	n, err := o.Conn.Read(b)
	if n > 0 {
		o.serverRecord = append(o.serverRecord, b[:n]...)
		if len(o.serverRecord)+len(o.serverHello) > 65536 {
			return n, errors.New("fixture server handshake exceeds bound")
		}
		for len(o.serverRecord) >= 5 {
			size := 5 + int(binary.BigEndian.Uint16(o.serverRecord[3:5]))
			if len(o.serverRecord) < size {
				break
			}
			if o.serverRecord[0] == 22 {
				o.serverHello = append(o.serverHello, o.serverRecord[5:size]...)
			}
			o.serverRecord = o.serverRecord[size:]
			for len(o.serverHello) >= 4 {
				length := 4 + int(o.serverHello[1])<<16 + int(o.serverHello[2])<<8 + int(o.serverHello[3])
				if len(o.serverHello) < length {
					break
				}
				const retryRandom = "\xcf\x21\xad\x74\xe5\x9a\x61\x11\xbe\x1d\x8c\x02\x1e\x65\xb8\x91\xc2\xa2\x11\x16\x7a\xbb\x8c\x5e\x07\x9e\x09\xe2\xc8\xa8\x33\x9c"
				if o.serverHello[0] == 2 && length >= 38 && string(o.serverHello[6:38]) == retryRandom {
					o.hrrs++
				}
				o.serverHello = o.serverHello[length:]
			}
		}
	}
	return n, err
}

func (o *echObserver) observe(data []byte) error {
	o.record = append(o.record, data...)
	if len(o.record)+len(o.hello) > 65536 {
		return errors.New("fixture ClientHello exceeds bound")
	}
	for len(o.record) >= 5 {
		n := 5 + int(binary.BigEndian.Uint16(o.record[3:5]))
		if len(o.record) < n {
			return nil
		}
		if o.record[0] == 22 {
			o.hello = append(o.hello, o.record[5:n]...)
		}
		o.record = o.record[n:]
		if len(o.hello) < 4 {
			continue
		}
		size := 4 + int(o.hello[1])<<16 + int(o.hello[2])<<8 + int(o.hello[3])
		if len(o.hello) < size {
			continue
		}
		if o.hello[0] != 1 || size < 38 {
			return errors.New("fixture expected first ClientHello")
		}
		h := o.hello[4:size]
		outerRandom := bytes.Clone(h[2:34])
		pos := 34
		skip := func(width int) error {
			if pos+width > len(h) {
				return io.ErrUnexpectedEOF
			}
			n := int(h[pos])
			if width == 2 {
				n = int(binary.BigEndian.Uint16(h[pos:]))
			}
			pos += width + n
			if pos > len(h) {
				return io.ErrUnexpectedEOF
			}
			return nil
		}
		for _, width := range []int{1, 2, 1} {
			if err := skip(width); err != nil {
				return err
			}
		}
		if pos+2 > len(h) || pos+2+int(binary.BigEndian.Uint16(h[pos:])) != len(h) {
			return errors.New("invalid fixture extension vector")
		}
		pos += 2
		for pos+4 <= len(h) {
			kind, length := binary.BigEndian.Uint16(h[pos:]), int(binary.BigEndian.Uint16(h[pos+2:]))
			pos += 4
			if pos+length > len(h) {
				return io.ErrUnexpectedEOF
			}
			ext := h[pos : pos+length]
			pos += length
			if kind != 0xfe0d {
				continue
			}
			o.clientHellos++
			if o.logged {
				if len(ext) < 8 || o.clientHellos != 2 {
					return errors.New("unexpected retry ECH extension")
				}
				o.secondEncLen = int(binary.BigEndian.Uint16(ext[6:8]))
				o.record, o.hello = nil, nil
				return nil
			}
			if len(ext) < 40 || !bytes.Equal(ext[:5], []byte{0, 0, 1, 0, 1}) || ext[5] != o.config[4] || binary.BigEndian.Uint16(ext[6:]) != 32 {
				return errors.New("unexpected fixture ECH suite/config")
			}
			secret, err := kemSecret(o.key, ext[8:40])
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(o.keys, "ECH_SECRET %x %x\nECH_CONFIG %x %x\n", outerRandom, secret, outerRandom, o.config)
			o.logged = err == nil
			o.record, o.hello = nil, nil
			return err
		}
		return errors.New("missing fixture ECH extension")
	}
	return nil
}

func echHTTP(mode string) ([]byte, []byte) {
	request := []byte("GET /d10/" + mode + "/0 HTTP/1.1\r\nHost: fixture\r\n\r\n")
	body := "d10/" + mode + "/0\n"
	response := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
	return request, response
}

func exactRead(conn net.Conn, want []byte) error {
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return errors.New("fixture payload mismatch")
	}
	return nil
}

func runECH(cert tls.Certificate, keys *keyWriter, accepted, hrr bool) error {
	key, config, err := echConfig(7)
	if err != nil {
		return err
	}
	serverKey, serverConfig := key, config
	mode, port := "ech_accepted", 44460
	if !accepted {
		mode, port = "ech_rejected", 44461
		serverKey, serverConfig, err = echConfig(8)
		if err != nil {
			return err
		}
	}
	if hrr {
		mode, port = "ech_hrr_accepted", 44476
		if !accepted {
			mode, port = "ech_hrr_rejected", 44477
		}
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	defer listener.Close()
	server := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}, NextProtos: []string{"http/1.1"}, EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{Config: serverConfig, PrivateKey: serverKey.Bytes(), SendAsRetry: true}}}
	clientCurves := []tls.CurveID{tls.X25519}
	if hrr {
		server.CurvePreferences = []tls.CurveID{tls.CurveP256}
		clientCurves = append(clientCurves, tls.CurveP256)
	}
	request, response := echHTTP(mode)
	done := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
		conn := tls.Server(raw, server)
		defer conn.Close()
		err = conn.Handshake()
		if err == nil && conn.ConnectionState().ECHAccepted != accepted {
			err = errors.New("server ECH acceptance mismatch")
		}
		if !accepted {
			if err == nil {
				var b [1]byte
				n, readErr := conn.Read(b[:])
				if n != 0 || readErr == nil {
					err = errors.New("rejected ECH emitted application data")
				}
			}
			done <- err
			return
		}
		if err == nil {
			err = exactRead(conn, request)
		}
		if err == nil {
			_, err = conn.Write(response[:3])
		}
		if err == nil {
			_, err = conn.Write(response[3:])
		}
		done <- err
	}()
	raw, err := net.DialTimeout("tcp", listener.Addr().String(), 10*time.Second)
	if err != nil {
		return err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	observer := &echObserver{Conn: raw, key: key, config: config, keys: keys}
	client := tls.Client(observer, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: clientCurves, ServerName: "secret.example", InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}, KeyLogWriter: keys, EncryptedClientHelloConfigList: vector(config), EncryptedClientHelloRejectionVerify: func(tls.ConnectionState) error { return nil }})
	defer client.Close()
	err = client.Handshake()
	if accepted {
		if err != nil {
			return err
		}
		if !client.ConnectionState().ECHAccepted {
			return errors.New("client did not accept ECH")
		}
		if _, err = client.Write(request[:3]); err == nil {
			_, err = client.Write(request[3:])
		}
		if err == nil {
			err = exactRead(client, response)
		}
	} else {
		var rejection *tls.ECHRejectionError
		if !errors.As(err, &rejection) || len(rejection.RetryConfigList) == 0 {
			return fmt.Errorf("expected ECH rejection with retry configuration: %w", err)
		}
		err = nil
	}
	if err != nil {
		return err
	}
	if err := <-done; err != nil {
		return err
	}
	if !observer.logged {
		return errors.New("missing RFC 9850 ECH keylog records")
	}
	wantHellos, wantHRR := 1, 0
	if hrr {
		wantHellos, wantHRR = 2, 1
	}
	if observer.clientHellos != wantHellos || observer.hrrs != wantHRR {
		return fmt.Errorf("unexpected wire CH/HRR counts: %d/%d", observer.clientHellos, observer.hrrs)
	}
	if hrr && accepted && observer.secondEncLen != 0 {
		return errors.New("accepted retry must reuse HPKE context with empty enc")
	}
	state := client.ConnectionState()
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": mode, "port": port, "client_hellos": observer.clientHellos, "hrrs": observer.hrrs, "second_enc_length": observer.secondEncLen, "ech_accepted": accepted, "expected_rejection": !accepted, "cipher_suite": state.CipherSuite, "config_sha256": hex.EncodeToString(sha256Sum(config)), "application_messages": map[bool]int{true: 2, false: 0}[accepted]})
}

func sha256Sum(b []byte) []byte { sum := sha256.Sum256(b); return sum[:] }

func main() {
	certPath := flag.String("cert", "", "ephemeral test certificate")
	keyPath := flag.String("key", "", "ephemeral test certificate private key")
	keylogPath := flag.String("keylog", "", "fresh NSS/RFC 9850 keylog path")
	hrr := flag.Bool("hrr", false, "force HRR before accepting/rejecting ECH")
	mode := flag.String("mode", "all", "all, accepted or rejected")
	flag.Parse()
	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		panic(err)
	}
	f, err := os.OpenFile(*keylogPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	keys := &keyWriter{f: f}
	if *mode != "all" && *mode != "accepted" && *mode != "rejected" {
		panic("invalid fixture mode")
	}
	for _, accepted := range []bool{true, false} {
		if *mode == "accepted" && !accepted || *mode == "rejected" && accepted {
			continue
		}
		if err := runECH(cert, keys, accepted, *hrr); err != nil {
			panic(err)
		}
	}
}
