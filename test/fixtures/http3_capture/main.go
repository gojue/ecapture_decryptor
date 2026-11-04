package main

import (
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
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
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

func quicConfig() *quic.Config {
	version := quic.Version1
	switch os.Getenv("QUIC_VERSION") {
	case "", "1":
	case "2":
		version = quic.Version2
	default:
		log.Fatal("QUIC_VERSION must be 1 or 2")
	}
	return &quic.Config{Versions: []quic.Version{version}, Tracer: qlog.DefaultConnectionTracer}
}

func serve(port string) error {
	cert, err := certificate()
	if err != nil {
		return err
	}
	conn, err := net.ListenPacket("udp4", "127.0.0.1:"+port)
	if err != nil {
		return err
	}
	defer conn.Close()
	server := &http3.Server{
		QUICConfig: quicConfig(),
		TLSConfig:  &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprintf(w, "%s %s %s", r.Method, r.URL.Path, body)
		}),
	}
	log.Printf("HTTP/3 server listening on %s", conn.LocalAddr())
	return server.Serve(conn)
}

func request(target string, external, updates bool) error {
	keylogPath := os.Getenv("SSLKEYLOGFILE")
	if keylogPath == "" {
		return fmt.Errorf("SSLKEYLOGFILE is required")
	}
	keylog, err := os.OpenFile(keylogPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer keylog.Close()
	tlsConfig := &tls.Config{NextProtos: []string{"h3"}, KeyLogWriter: keylog}
	if !external {
		tlsConfig.InsecureSkipVerify = true // Ephemeral self-signed loopback certificate.
		tlsConfig.ServerName = "localhost"
	}
	transport := &http3.Transport{TLSClientConfig: tlsConfig, QUICConfig: quicConfig()}
	defer transport.Close()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	baseURL := "https://127.0.0.1:" + target
	requests := []struct{ method, path, body string }{
		{"GET", "/one", ""},
		{"POST", "/upload", strings.Repeat("payload-", 300)},
	}
	if updates {
		requests = nil
		for i := 0; i < 12; i++ {
			requests = append(requests, struct{ method, path, body string }{"POST", fmt.Sprintf("/update/%d", i), strings.Repeat("payload-", 300)})
		}
	}
	if external {
		baseURL = strings.TrimSuffix(target, "/")
		requests = []struct{ method, path, body string }{
			{"GET", "/robots.txt", ""},
			{"GET", "/favicon.ico", ""},
		}
	}
	for _, item := range requests {
		req, err := http.NewRequestWithContext(context.Background(), item.method, baseURL+item.path, strings.NewReader(item.body))
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK || (!external && string(body) != item.method+" "+item.path+" "+item.body) {
			return fmt.Errorf("unexpected response: status=%d body=%q", resp.StatusCode, body)
		}
		log.Printf("HTTP/3 %s %s: %d, %d response bytes", item.method, item.path, resp.StatusCode, len(body))
	}
	return nil
}

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: http3-traffic server|client|client-updates PORT | client-url HTTPS_BASE_URL")
	}
	var err error
	switch os.Args[1] {
	case "server":
		err = serve(os.Args[2])
	case "client":
		err = request(os.Args[2], false, false)
	case "client-updates":
		err = request(os.Args[2], false, true)
	case "client-url":
		err = request(os.Args[2], true, false)
	default:
		log.Fatal("mode must be server, client, client-updates, or client-url")
	}
	if err != nil {
		log.Fatal(err)
	}
}
