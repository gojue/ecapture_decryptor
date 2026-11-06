package crypto

import (
	"bytes"
	"crypto/ecdh"
	stdhkdf "crypto/hkdf"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
)

func helloTestExtension(typ uint16, data []byte) []byte {
	return append([]byte{byte(typ >> 8), byte(typ), byte(len(data) >> 8), byte(len(data))}, data...)
}
func helloTestClient(random, session, extensions []byte) []byte {
	body := append([]byte{3, 3}, random...)
	body = append(body, byte(len(session)))
	body = append(body, session...)
	body = append(body, 0, 2, 0x13, 1, 1, 0, byte(len(extensions)>>8), byte(len(extensions)))
	return handshakeEncoding(1, append(body, extensions...))
}
func helloTestServer(random, extensions []byte) []byte {
	body := append([]byte{3, 3}, random...)
	body = append(body, 0, 0x13, 1, 0, byte(len(extensions)>>8), byte(len(extensions)))
	return handshakeEncoding(2, append(body, extensions...))
}
func helloTestRecord(typ byte, data []byte) []byte {
	return append([]byte{typ, 3, 3, byte(len(data) >> 8), byte(len(data))}, data...)
}
func TestHandshakeSplitHeaderAndCoalescedTail(t *testing.T) {
	ch := helloTestClient(bytes.Repeat([]byte{1}, 32), []byte{4, 5}, helloTestExtension(42, nil))
	tail := handshakeEncoding(11, []byte{9, 8})
	s := NewStreamBuffer()
	for _, v := range ch[:3] {
		if err := s.Write(helloTestRecord(22, []byte{v})); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Write(helloTestRecord(22, append(bytes.Clone(ch[3:]), tail...))); err != nil {
		t.Fatal(err)
	}
	application := helloTestRecord(23, []byte("preserved"))
	if err := s.Write(application); err != nil {
		t.Fatal(err)
	}
	s.Close()
	got, err := ReadClientHello(s)
	if err != nil || !got.EarlyData || !bytes.Equal(got.Message, ch) {
		t.Fatalf("ClientHello: %v", err)
	}
	following, err := readHandshakeMessage(s)
	if err != nil || !bytes.Equal(following, tail) {
		t.Fatalf("coalesced tail: %x %v", following, err)
	}
	record, err := s.ReadRecord()
	if err != nil || !bytes.Equal(record, application) {
		t.Fatalf("next record: %x %v", record, err)
	}
}
func TestHandshakeInvalidFraming(t *testing.T) {
	for name, wire := range map[string][]byte{
		"partial":         helloTestRecord(22, []byte{1, 0}),
		"ccs_fragment":    append(helloTestRecord(22, []byte{1}), helloTestRecord(20, []byte{1})...),
		"bad_ccs":         helloTestRecord(20, []byte{2}),
		"application":     helloTestRecord(23, []byte{1, 0, 0, 0}),
		"empty":           helloTestRecord(22, nil),
		"record_limit":    helloTestRecord(22, make([]byte, 16385)),
		"handshake_limit": helloTestRecord(22, []byte{1, 0x10, 0, 0}),
	} {
		t.Run(name, func(t *testing.T) {
			s := NewStreamBuffer()
			if err := s.Write(wire); err != nil {
				t.Fatal(err)
			}
			s.Close()
			if _, err := readHandshakeMessage(s); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
	s := NewStreamBuffer()
	if err := s.Write(append(helloTestRecord(20, []byte{1}), helloTestRecord(22, handshakeEncoding(0, nil))...)); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := readHandshakeMessage(s); err != nil {
		t.Fatal(err)
	}
}
func TestHandshakeAssemblerBoundaries(t *testing.T) {
	messages := [][]byte{handshakeEncoding(8, []byte{0, 0}), handshakeEncoding(5, nil), handshakeEncoding(24, []byte{1})}
	wire := bytes.Join(messages, nil)
	var a HandshakeAssembler
	var got [][]byte
	for _, b := range wire {
		next, err := a.Feed([]byte{b})
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, next...)
	}
	if a.Pending() || len(got) != len(messages) {
		t.Fatal("messages not framed")
	}
	for i := range got {
		if !bytes.Equal(got[i], messages[i]) {
			t.Fatal("message changed")
		}
	}
	next, err := a.Feed(wire)
	if err != nil || len(next) != 3 {
		t.Fatalf("coalesced: %v", err)
	}
	clear(wire)
	if !bytes.Equal(next[0], messages[0]) {
		t.Fatal("message aliases input")
	}
	if _, err := a.Feed([]byte{1, 0x10, 0, 0}); !errors.Is(err, ErrHandshakeResourceLimit) {
		t.Fatal(err)
	}
	if _, err := a.Feed(nil); !errors.Is(err, ErrHandshakeResourceLimit) {
		t.Fatal("nonsticky limit")
	}
	a.Reset()
	if a.Pending() {
		t.Fatal("reset retains pending")
	}
	if _, err := a.Feed(messages[0]); err != nil {
		t.Fatal(err)
	}
}
func TestHelloRetryResumptionAndExtensionBounds(t *testing.T) {
	ext := append(helloTestExtension(43, []byte{3, 4}), helloTestExtension(41, []byte{0, 0})...)
	sh := helloTestServer(bytes.Repeat([]byte{2}, 32), ext)
	if !ServerHelloResumed(sh) || IsHelloRetryRequest(sh) {
		t.Fatal("resumption not identified")
	}
	hrr := helloTestServer(helloRetryRandom, ext)
	if !IsHelloRetryRequest(hrr) || ServerHelloResumed(hrr) {
		t.Fatal("HRR misidentified")
	}
	if ServerHelloResumed(helloTestServer(bytes.Repeat([]byte{2}, 32), helloTestExtension(41, []byte{0, 0}))) {
		t.Fatal("TLS 1.2 called resumed by TLS 1.3 extension")
	}
	random := bytes.Repeat([]byte{1}, 32)
	for name, extensions := range map[string][]byte{"duplicate": append(helloTestExtension(42, nil), helloTestExtension(42, nil)...), "early_body": helloTestExtension(42, []byte{0}), "bad_ech": helloTestExtension(0xfe0d, []byte{1, 0}), "short_extension": {0, 42, 0}} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseClientHello(helloTestClient(random, nil, extensions)); err == nil {
				t.Fatal("invalid hello accepted")
			}
		})
	}
}

// The ciphertext producer is Go's independent RFC 9180 implementation. Only
// the KEM shared_secret is derived here to model RFC 9850's logged material.
func makeECHTest(t *testing.T) (*ClientHelloInfo, []byte, *TLSSecrets, []byte) {
	t.Helper()
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := hpke.DHKEM(ecdh.X25519()).NewPublicKey(sk.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	configBody := []byte{7, 0, 0x20, 0, 32}
	configBody = append(configBody, sk.PublicKey().Bytes()...)
	configBody = append(configBody, 0, 4, 0, 1, 0, 1, 0, 13)
	configBody = append(configBody, []byte("cover.example")...)
	configBody = append(configBody, 0, 0)
	config := append([]byte{0xfe, 0x0d, byte(len(configBody) >> 8), byte(len(configBody))}, configBody...)
	enc, sender, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.AES128GCM(), append([]byte("tls ech\x00"), config...))
	if err != nil {
		t.Fatal(err)
	}
	innerRandom := bytes.Repeat([]byte{0x21}, 32)
	outerRandom := bytes.Repeat([]byte{0x32}, 32)
	session := []byte{9, 8, 7}
	innerExt := append(helloTestExtension(0xfe0d, []byte{1}), helloTestExtension(43, []byte{2, 3, 4})...)
	encoded := append(helloTestClient(innerRandom, nil, innerExt)[4:], make([]byte, 17)...)
	inner := helloTestClient(innerRandom, session, innerExt)
	ech := []byte{0, 0, 1, 0, 1, 7, 0, 32}
	ech = append(ech, enc...)
	n := len(encoded) + 16
	ech = append(ech, byte(n>>8), byte(n))
	ech = append(ech, make([]byte, n)...)
	outerWire := helloTestClient(outerRandom, session, append(helloTestExtension(43, []byte{2, 3, 4}), helloTestExtension(0xfe0d, ech)...))
	ciphertext, err := sender.Seal(outerWire[4:], encoded)
	if err != nil {
		t.Fatal(err)
	}
	copy(outerWire[len(outerWire)-n:], ciphertext)
	outer, err := parseClientHello(outerWire)
	if err != nil {
		t.Fatal(err)
	}
	encPub, err := ecdh.X25519().NewPublicKey(enc)
	if err != nil {
		t.Fatal(err)
	}
	dh, err := sk.ECDH(encPub)
	if err != nil {
		t.Fatal(err)
	}
	kemSuite := []byte{'K', 'E', 'M', 0, 0x20}
	labeled := append([]byte("HPKE-v1"), kemSuite...)
	labeled = append(labeled, []byte("eae_prk")...)
	labeled = append(labeled, dh...)
	prk, err := stdhkdf.Extract(sha256.New, labeled, nil)
	if err != nil {
		t.Fatal(err)
	}
	info := append([]byte{0, 32}, []byte("HPKE-v1")...)
	info = append(info, kemSuite...)
	info = append(info, []byte("shared_secret")...)
	info = append(info, enc...)
	info = append(info, sk.PublicKey().Bytes()...)
	shared, err := stdhkdf.Expand(sha256.New, prk, string(info), 32)
	if err != nil {
		t.Fatal(err)
	}
	sh := helloTestServer(bytes.Repeat([]byte{0x43}, 32), helloTestExtension(43, []byte{3, 4}))
	clear(sh[30:38])
	transcript := sha256.Sum256(append(bytes.Clone(inner), sh...))
	acceptSecret, err := stdhkdf.Extract(sha256.New, innerRandom, nil)
	if err != nil {
		t.Fatal(err)
	}
	label := []byte("tls13 ech accept confirmation")
	acceptInfo := append([]byte{0, 8, byte(len(label))}, label...)
	acceptInfo = append(acceptInfo, 32)
	acceptInfo = append(acceptInfo, transcript[:]...)
	accept, err := stdhkdf.Expand(sha256.New, acceptSecret, string(acceptInfo), 8)
	if err != nil {
		t.Fatal(err)
	}
	copy(sh[30:38], accept)
	return outer, sh, &TLSSecrets{ECHSecret: shared, ECHConfig: config}, innerRandom
}
func TestECHAuthenticatedRandomAssociation(t *testing.T) {
	outer, sh, secrets, innerRandom := makeECHTest(t)
	inner, status, err := ResolveECHClientHello(outer, sh, secrets)
	if err != nil || status != "accepted" || !bytes.Equal(inner.Random, innerRandom) || !bytes.Equal(inner.sessionID, outer.sessionID) {
		t.Fatalf("accepted: %s %v", status, err)
	}
	rejected := bytes.Clone(sh)
	rejected[37] ^= 1
	selected, status, err := ResolveECHClientHello(outer, rejected, secrets)
	if err != nil || status != "rejected" || !bytes.Equal(selected.Random, outer.Random) {
		t.Fatalf("rejected: %s %v", status, err)
	}
	if _, _, err := ResolveECHClientHello(outer, sh, nil); !errors.Is(err, ErrECHSecretsUnavailable) {
		t.Fatal(err)
	}
	wrong := *secrets
	wrong.ECHSecret = bytes.Repeat([]byte{7}, 32)
	if _, _, err := ResolveECHClientHello(outer, sh, &wrong); !errors.Is(err, ErrECHAuthentication) {
		t.Fatal(err)
	}
	for _, index := range []int{6, len(outer.Message) - 1} {
		bad := *outer
		bad.Message = bytes.Clone(outer.Message)
		bad.Message[index] ^= 1
		if _, _, err := ResolveECHClientHello(&bad, sh, secrets); !errors.Is(err, ErrECHAuthentication) {
			t.Fatalf("altered authenticated byte: %v", err)
		}
	}
	bad := *outer
	bad.Message = nil
	if _, _, err := ResolveECHClientHello(&bad, sh, secrets); !errors.Is(err, ErrECHInvalid) {
		t.Fatal(err)
	}
	if _, _, err := ResolveECHClientHello(outer, helloTestServer(helloRetryRandom, helloTestExtension(43, []byte{3, 4})), secrets); !errors.Is(err, ErrECHUnsupported) {
		t.Fatal(err)
	}
	wrong = *secrets
	wrong.ECHConfig = bytes.Clone(secrets.ECHConfig)
	wrong.ECHConfig[4] ^= 1
	if _, _, err := ResolveECHClientHello(outer, sh, &wrong); !errors.Is(err, ErrECHInvalid) {
		t.Fatal(err)
	}
}
func TestECHOuterExtensionReconstruction(t *testing.T) {
	outerExt := append(helloTestExtension(10, []byte{0, 2, 0, 29}), helloTestExtension(43, []byte{2, 3, 4})...)
	outer, err := parseClientHello(helloTestClient(bytes.Repeat([]byte{1}, 32), []byte{4}, outerExt))
	if err != nil {
		t.Fatal(err)
	}
	for name, refs := range map[string][]byte{"valid": {4, 0, 10, 0, 43}, "reverse": {4, 0, 43, 0, 10}, "duplicate": {4, 0, 10, 0, 10}, "missing": {2, 0, 99}, "ech": {2, 0xfe, 0x0d}, "self": {2, 0xfd, 0}} {
		t.Run(name, func(t *testing.T) {
			ext := append(helloTestExtension(0xfe0d, []byte{1}), helloTestExtension(0xfd00, refs)...)
			encoded := helloTestClient(bytes.Repeat([]byte{2}, 32), nil, ext)[4:]
			inner, err := decodeECHInner(outer, encoded)
			if name == "valid" {
				if err != nil || len(inner.extensions) != 3 || inner.extensions[1].typ != 10 || inner.extensions[2].typ != 43 {
					t.Fatalf("reconstruct: %v", err)
				}
			} else if !errors.Is(err, ErrECHInvalid) {
				t.Fatalf("invalid refs: %v", err)
			}
		})
	}
	encoded := helloTestClient(bytes.Repeat([]byte{2}, 32), nil, helloTestExtension(0xfe0d, []byte{1}))[4:]
	if _, err := decodeECHInner(outer, append(encoded, 1)); !errors.Is(err, ErrECHInvalid) {
		t.Fatal("nonzero padding accepted")
	}
}
func FuzzHelloParsing(f *testing.F) {
	f.Add(helloTestClient(bytes.Repeat([]byte{1}, 32), nil, nil))
	f.Add(helloTestServer(helloRetryRandom, helloTestExtension(43, []byte{3, 4})))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxHandshakeMessage {
			return
		}
		_, _ = parseClientHello(data)
		_, _, _, _ = serverHello(data)
		_ = IsHelloRetryRequest(data)
		_ = ServerHelloResumed(data)
		var a HandshakeAssembler
		_, _ = a.Feed(data)
	})
}
