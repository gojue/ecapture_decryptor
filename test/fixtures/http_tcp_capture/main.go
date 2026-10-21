package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	portHTTP10 = "44434"
	portHTTP11 = "44435"
	portHTTP2  = "44436"
)

func certificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	privateDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER}),
	)
}

func listen(port string, cert tls.Certificate, nextProto string) (net.Listener, error) {
	return tls.Listen("tcp4", "127.0.0.1:"+port, &tls.Config{
		Certificates: []tls.Certificate{cert}, NextProtos: []string{nextProto},
	})
}

func serveHTTP10(cert tls.Certificate) error {
	listener, err := listen(portHTTP10, cert, "http/1.0")
	if err != nil {
		return err
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			req, err := http.ReadRequest(bufio.NewReader(conn))
			if err != nil {
				log.Printf("HTTP/1.0 read: %v", err)
				return
			}
			_ = req.Body.Close()
			if req.Proto != "HTTP/1.0" || req.URL.Path != "/legacy" {
				return
			}
			_, _ = io.WriteString(conn, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nlegacy-response")
		}()
	}
}

func serveHTTP11(cert tls.Certificate) error {
	listener, err := listen(portHTTP11, cert, "http/1.1")
	if err != nil {
		return err
	}
	defer listener.Close()
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		switch r.URL.Path {
		case "/keep-one":
			_, _ = io.WriteString(w, "keep-one-response")
		case "/chunked":
			body, _ := io.ReadAll(r.Body)
			if r.Method != "POST" || string(body) != "hello-chunked-world" {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, "chunked-")
			w.(http.Flusher).Flush()
			_, _ = io.WriteString(w, "response")
		default:
			http.NotFound(w, r)
		}
	})}
	return server.Serve(listener)
}

func serveHTTP2(cert tls.Certificate) error {
	listener, err := listen(portHTTP2, cert, "h2")
	if err != nil {
		return err
	}
	defer listener.Close()
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	go func() { <-arrived; <-arrived; close(release) }()
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Protocols: protocols, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		select {
		case <-release:
		case <-time.After(8 * time.Second):
			http.Error(w, "streams did not overlap", http.StatusGatewayTimeout)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintf(w, "multiplexed-response-%s", strings.TrimPrefix(r.URL.Path, "/"))
	})}
	return server.Serve(listener)
}

func serve() error {
	cert, err := certificate()
	if err != nil {
		return err
	}
	errors := make(chan error, 3)
	go func() { errors <- serveHTTP10(cert) }()
	go func() { errors <- serveHTTP11(cert) }()
	go func() { errors <- serveHTTP2(cert) }()
	log.Printf("TLS HTTP/1.0, HTTP/1.1 and HTTP/2 servers listening on 127.0.0.1:%s/%s/%s", portHTTP10, portHTTP11, portHTTP2)
	return <-errors
}

func keylogConfig() (*tls.Config, *os.File, error) {
	path := os.Getenv("SSLKEYLOGFILE")
	if path == "" {
		return nil, nil, fmt.Errorf("SSLKEYLOGFILE is required")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return nil, nil, err
	}
	return &tls.Config{InsecureSkipVerify: true, KeyLogWriter: file}, file, nil // Ephemeral loopback certificate.
}

func clientHTTP10(config *tls.Config) error {
	conn, err := tls.Dial("tcp4", "127.0.0.1:"+portHTTP10, config)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, "GET /legacy HTTP/1.0\r\nHost: localhost\r\n\r\n"); err != nil {
		return err
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		return err
	}
	if !strings.Contains(string(body), "HTTP/1.0 200 OK") || !strings.HasSuffix(string(body), "legacy-response") {
		return fmt.Errorf("unexpected HTTP/1.0 response: %q", body)
	}
	log.Printf("HTTP/1.0 close-delimited response: %d bytes", len(body))
	return nil
}

func clientHTTP11(config *tls.Config) error {
	conn, err := tls.Dial("tcp4", "127.0.0.1:"+portHTTP11, config)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	if _, err := io.WriteString(conn, "GET /keep-one HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		return err
	}
	first, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	if err != nil {
		return err
	}
	firstBody, err := io.ReadAll(first.Body)
	_ = first.Body.Close()
	if err != nil || first.StatusCode != 200 || string(firstBody) != "keep-one-response" {
		return fmt.Errorf("unexpected keep-alive response: %s %q %v", first.Status, firstBody, err)
	}
	request := "POST /chunked HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\ne\r\n-chunked-world\r\n0\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		return err
	}
	second, err := http.ReadResponse(reader, &http.Request{Method: "POST"})
	if err != nil {
		return err
	}
	secondBody, err := io.ReadAll(second.Body)
	_ = second.Body.Close()
	if err != nil || second.StatusCode != 201 || string(secondBody) != "chunked-response" || len(second.TransferEncoding) == 0 || second.TransferEncoding[0] != "chunked" {
		return fmt.Errorf("unexpected chunked response: %s %q encoding=%v err=%v", second.Status, secondBody, second.TransferEncoding, err)
	}
	log.Printf("HTTP/1.1 keep-alive and bidirectional chunked transfer on one TCP connection")
	return nil
}

func clientHTTP2(config *tls.Config) error {
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	transport := &http.Transport{TLSClientConfig: config, Protocols: protocols}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	var wg sync.WaitGroup
	errors := make(chan error, 2)
	for _, path := range []string{"/alpha", "/beta"} {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			req, err := http.NewRequestWithContext(context.Background(), "GET", "https://127.0.0.1:"+portHTTP2+path, nil)
			if err != nil {
				errors <- err
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				errors <- err
				return
			}
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr != nil || resp.ProtoMajor != 2 || resp.StatusCode != 200 || string(body) != "multiplexed-response-"+strings.TrimPrefix(path, "/") {
				errors <- fmt.Errorf("unexpected HTTP/2 response %s: protocol=%s status=%s body=%q err=%v", path, resp.Proto, resp.Status, body, readErr)
			}
		}(path)
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		return err
	}
	log.Printf("HTTP/2 two overlapping request streams completed")
	return nil
}

func client(mode string) error {
	config, file, err := keylogConfig()
	if err != nil {
		return err
	}
	defer file.Close()
	switch mode {
	case "http10":
		return clientHTTP10(config)
	case "http11":
		return clientHTTP11(config)
	case "http2":
		return clientHTTP2(config)
	default:
		return fmt.Errorf("unknown client mode %q", mode)
	}
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: http-tcp-traffic server | http10 | http11 | http2")
	}
	var err error
	if os.Args[1] == "server" {
		err = serve()
	} else {
		err = client(os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}
