package crypto

import (
	"bytes"
	"crypto/ecdh"
	stdhkdf "crypto/hkdf"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
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
	first, _, _, final, secrets, random := makeECHFlight(t, false)
	return first, final, secrets, random
}

func makeECHFlight(t *testing.T, retry bool, change ...string) (*ClientHelloInfo, *ClientHelloInfo, []byte, []byte, *TLSSecrets, []byte) {
	t.Helper()
	hasChange := func(want string) bool {
		for _, item := range change {
			if item == want {
				return true
			}
		}
		return false
	}
	suite, newHash := byte(1), sha256.New
	if len(change) > 0 {
		if change[0] == "aes256" {
			suite, newHash = 2, sha512.New384
		}
		if change[0] == "chacha" {
			suite = 3
		}
	}
	clientHello := func(random, session, extensions []byte) []byte {
		message := helloTestClient(random, session, extensions)
		message[42+len(session)] = suite
		return message
	}
	serverHello := func(random, extensions []byte) []byte {
		message := helloTestServer(random, extensions)
		message[40] = suite
		return message
	}
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
	baseInnerExt := append(helloTestExtension(0xfe0d, []byte{1}), helloTestExtension(43, []byte{2, 3, 4})...)
	innerExt := bytes.Clone(baseInnerExt)
	outerExt := helloTestExtension(43, []byte{2, 3, 4})
	if hasChange("early") || hasChange("early_without_outer") {
		innerExt = append(innerExt, helloTestExtension(42, nil)...)
	}
	if hasChange("early") || hasChange("outer_early") {
		outerExt = append(outerExt, helloTestExtension(42, nil)...)
	}
	encoded := append(clientHello(innerRandom, nil, innerExt)[4:], make([]byte, 17)...)
	inner := clientHello(innerRandom, session, innerExt)
	ech := []byte{0, 0, 1, 0, 1, 7, 0, 32}
	ech = append(ech, enc...)
	n := len(encoded) + 16
	ech = append(ech, byte(n>>8), byte(n))
	ech = append(ech, make([]byte, n)...)
	outerWire := clientHello(outerRandom, session, append(bytes.Clone(outerExt), helloTestExtension(0xfe0d, ech)...))
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
	acceptSecret, err := stdhkdf.Extract(newHash, innerRandom, nil)
	if err != nil {
		t.Fatal(err)
	}
	confirm := func(label string, transcript []byte) []byte {
		t.Helper()
		h := newHash()
		h.Write(transcript)
		digest := h.Sum(nil)
		label = "tls13 " + label
		acceptInfo := append([]byte{0, 8, byte(len(label))}, label...)
		acceptInfo = append(acceptInfo, byte(len(digest)))
		acceptInfo = append(acceptInfo, digest...)
		accept, err := stdhkdf.Expand(newHash, acceptSecret, string(acceptInfo), 8)
		if err != nil {
			t.Fatal(err)
		}
		return accept
	}
	var second *ClientHelloInfo
	var hrr []byte
	transcript := bytes.Clone(inner)
	if retry {
		h := newHash()
		h.Write(inner)
		transcript = append([]byte{254, 0, 0, byte(h.Size())}, h.Sum(nil)...)
		ext := append(helloTestExtension(43, []byte{3, 4}), helloTestExtension(51, []byte{0, 23})...)
		ext = append(ext, helloTestExtension(0xfe0d, make([]byte, 8))...)
		hrr = serverHello(helloRetryRandom, ext)
		accept := confirm("hrr ech accept confirmation", append(bytes.Clone(transcript), hrr...))
		copy(hrr[len(hrr)-8:], accept)
		innerExt2 := append(bytes.Clone(baseInnerExt), helloTestExtension(44, []byte{0, 2, 0xaa, 0xbb})...)
		random2, session2 := bytes.Clone(innerRandom), bytes.Clone(session)
		for _, item := range change {
			switch item {
			case "inner_random":
				random2[0] ^= 1
			case "inner_session":
				session2[0] ^= 1
			case "inner_early":
				innerExt2 = append(innerExt2, helloTestExtension(42, nil)...)
			}
		}
		inner2 := clientHello(random2, session2, innerExt2)
		encoded2 := append(clientHello(random2, nil, innerExt2)[4:], make([]byte, 11)...)
		n := len(encoded2) + 16
		ech2 := []byte{0, 0, 1, 0, 1, 7, 0, 0, byte(n >> 8), byte(n)}
		ech2 = append(ech2, make([]byte, n)...)
		wire2 := clientHello(outerRandom, session2, append(bytes.Clone(outerExt), helloTestExtension(0xfe0d, ech2)...))
		ciphertext, err := sender.Seal(wire2[4:], encoded2)
		if err != nil {
			t.Fatal(err)
		}
		copy(wire2[len(wire2)-n:], ciphertext)
		second, err = parseClientHello(wire2)
		if err != nil {
			t.Fatal(err)
		}
		transcript = append(transcript, hrr...)
		transcript = append(transcript, inner2...)
	}
	sh := serverHello(bytes.Repeat([]byte{0x43}, 32), helloTestExtension(43, []byte{3, 4}))
	clear(sh[30:38])
	accept := confirm("ech accept confirmation", append(transcript, sh...))
	copy(sh[30:38], accept)
	return outer, second, hrr, sh, &TLSSecrets{ECHSecret: shared, ECHConfig: config}, innerRandom
}

func TestECHEarlyRandomAndRetry(t *testing.T) {
	for _, suite := range []string{"aes128", "aes256", "chacha"} {
		t.Run(suite, func(t *testing.T) {
			first, second, retry, final, secrets, random := makeECHFlight(t, true, suite, "early")
			inner1, inner2, status, err := ResolveECHClientHelloRetry(first, second, retry, final, secrets)
			if err != nil || status != "accepted" || !first.EarlyData || !second.EarlyData || !inner1.EarlyData || inner2.EarlyData {
				t.Fatalf("accepted ECH outer/inner early states: %s %v", status, err)
			}
			got, err := ECHClientEarlyRandom(first, secrets)
			if err != nil || !bytes.Equal(got, random) || bytes.Equal(got, first.Random) {
				t.Fatalf("authenticated early index: %x %v", got, err)
			}
			got[0] ^= 1
			again, err := ECHClientEarlyRandom(first, secrets)
			if err != nil || !bytes.Equal(again, random) {
				t.Fatal("early index aliases caller state", err)
			}
			// A rejecting server selects Outer for the handshake, while the
			// already-sent early records keep their authenticated Inner index.
			var extensions []byte
			for _, ext := range first.extensions {
				if ext.typ != 42 {
					extensions = append(extensions, helloTestExtension(ext.typ, ext.data)...)
				}
			}
			wire := helloTestClient(first.Random, first.sessionID, extensions)
			wire[42+len(first.sessionID)] = first.Message[42+len(first.sessionID)]
			outer2, err := parseClientHello(wire)
			if err != nil {
				t.Fatal(err)
			}
			rejected := bytes.Clone(retry)
			rejected[len(rejected)-1] ^= 1
			a, b, status, err := ResolveECHClientHelloRetry(first, outer2, rejected, final, secrets)
			if err != nil || status != "rejected" || !bytes.Equal(a.Random, first.Random) || !bytes.Equal(b.Random, first.Random) {
				t.Fatalf("rejected app identity: %s %v", status, err)
			}
			for _, material := range []*TLSSecrets{nil, secrets} {
				if _, _, _, err := ResolveECHClientHelloRetry(first, first, rejected, final, material); !errors.Is(err, ErrECHInvalid) {
					t.Fatal("rejected/GREASE CH2 kept early_data", err)
				}
			}
		})
	}
	first, _, _, _, secrets, _ := makeECHFlight(t, false, "early")
	for name, material := range map[string]*TLSSecrets{"missing": nil, "wrong": {ECHSecret: bytes.Repeat([]byte{1}, 32), ECHConfig: secrets.ECHConfig}, "missing_config": {ECHSecret: secrets.ECHSecret}} {
		t.Run(name, func(t *testing.T) {
			if random, err := ECHClientEarlyRandom(first, material); err == nil || random != nil {
				t.Fatal("unauthenticated early identity", err)
			}
		})
	}
	for _, index := range []int{6, len(first.Message) - 1} {
		bad := *first
		bad.Message = bytes.Clone(first.Message)
		bad.Message[index] ^= 1
		if _, err := ECHClientEarlyRandom(&bad, secrets); !errors.Is(err, ErrECHAuthentication) {
			t.Fatal("changed wire supplied early identity", err)
		}
	}
	for _, change := range []string{"no_early", "outer_early"} {
		first, _, _, _, secrets, _ := makeECHFlight(t, false, change)
		if random, err := ECHClientEarlyRandom(first, secrets); err != nil || random != nil {
			t.Fatal("inner without early data supplied an early identity", err)
		}
	}
	first, _, _, _, secrets, _ = makeECHFlight(t, false, "early_without_outer")
	if _, err := ECHClientEarlyRandom(first, secrets); !errors.Is(err, ErrECHInvalid) {
		t.Fatal("CH1 outer must copy the inner early offer", err)
	}
	first, second, retry, final, secrets, _ := makeECHFlight(t, true, "early", "inner_early")
	if _, _, _, err := ResolveECHClientHelloRetry(first, second, retry, final, secrets); !errors.Is(err, ErrECHInvalid) {
		t.Fatal("authenticated CH2 inner kept early_data", err)
	}
}

func TestECHHelloRetryTranscriptAndHPKESequence(t *testing.T) {
	first, second, retry, final, secrets, random := makeECHFlight(t, true)
	inner1, inner2, status, err := ResolveECHClientHelloRetry(first, second, retry, final, secrets)
	if err != nil || status != "accepted" || !bytes.Equal(inner1.Random, random) || !bytes.Equal(inner2.Random, random) || bytes.Equal(inner1.Message, inner2.Message) {
		t.Fatalf("accepted retry: status=%s err=%v", status, err)
	}
	for _, suite := range []string{"aes256", "chacha"} {
		t.Run(suite, func(t *testing.T) {
			first, second, retry, final, keys, random := makeECHFlight(t, true, suite)
			_, inner, status, err := ResolveECHClientHelloRetry(first, second, retry, final, keys)
			if err != nil || status != "accepted" || !bytes.Equal(inner.Random, random) {
				t.Fatal("TLS suite transcript", status, err)
			}
		})
	}
	for _, change := range []string{"hrr_confirmation", "final_confirmation", "payload", "outer_aad", "enc", "config", "secret", "missing", "repeat_hrr"} {
		t.Run(change, func(t *testing.T) {
			a, b, h, s, keys := *first, *second, bytes.Clone(retry), bytes.Clone(final), *secrets
			b.Message = bytes.Clone(second.Message)
			switch change {
			case "hrr_confirmation":
				h[len(h)-1] ^= 1
			case "final_confirmation":
				s[37] ^= 1
			case "payload":
				b.Message[len(b.Message)-1] ^= 1
			case "outer_aad":
				b.Message[6] ^= 1
			case "enc":
				for _, e := range second.extensions {
					if e.typ == 0xfe0d {
						b.Message[e.start+7] = 32
					}
				}
			case "config":
				for _, e := range second.extensions {
					if e.typ == 0xfe0d {
						b.Message[e.start+5] ^= 1
					}
				}
			case "secret":
				keys.ECHSecret = bytes.Repeat([]byte{3}, 32)
			case "missing":
				keys.ECHSecret = nil
			case "repeat_hrr":
				s = bytes.Clone(h)
			}
			if _, _, _, err := ResolveECHClientHelloRetry(&a, &b, h, s, &keys); err == nil {
				t.Fatal("altered retry accepted")
			}
		})
	}
	// Rejection/GREASE copies the first ECH extension instead of sealing CH2.
	rejected := helloTestServer(helloRetryRandom, helloTestExtension(43, []byte{3, 4}))
	for _, material := range []*TLSSecrets{nil, secrets} {
		a, b, status, err := ResolveECHClientHelloRetry(first, first, rejected, final, material)
		want := "rejected"
		if material == nil {
			want = "unknown"
		}
		if err != nil || status != want || !bytes.Equal(a.Random, first.Random) || !bytes.Equal(b.Random, first.Random) {
			t.Fatalf("outer retry: status=%s err=%v", status, err)
		}
	}
	for _, change := range []string{"inner_random", "inner_session", "inner_early"} {
		t.Run(change, func(t *testing.T) {
			first, second, retry, final, keys, _ := makeECHFlight(t, true, change)
			if _, _, _, err := ResolveECHClientHelloRetry(first, second, retry, final, keys); !errors.Is(err, ErrECHInvalid) {
				t.Fatal("authenticated CH2 changed forbidden state", err)
			}
		})
	}
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
	f.Add(append(helloTestRecord(23, []byte{0}), helloTestRecord(22, helloTestClient(bytes.Repeat([]byte{1}, 32), nil, nil))...))
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
		s := NewStreamBuffer()
		_ = s.Write(data)
		_ = s.Close()
		_, _ = ReadClientHelloRetry(s, func([]byte) error { return nil })
	})
}

func TestClientHelloFingerprints(t *testing.T) {
	// JA4's published example, with a real extension body for each parsed field.
	suites := []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	ids := []uint16{0x001b, 0, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 5, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015}
	bodies := map[uint16][]byte{0: {0, 6, 0, 0, 3, 'a', '.', 'b'}, 16: {0, 3, 2, 'h', '2'}, 13: {0, 16, 4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1}, 43: {4, 3, 4, 3, 3}, 11: {1, 0}, 10: {0, 6, 0, 29, 0, 23, 0, 24}}
	makeHello := func(ciphers, exts []uint16) []byte {
		body := append([]byte{3, 3}, make([]byte, 32)...)
		body = append(body, 0, byte(len(ciphers)*2>>8), byte(len(ciphers)*2))
		for _, v := range ciphers {
			body = append(body, byte(v>>8), byte(v))
		}
		body = append(body, 1, 0)
		var extensions []byte
		for _, id := range exts {
			extensions = append(extensions, helloTestExtension(id, bodies[id])...)
		}
		body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
		return handshakeEncoding(1, append(body, extensions...))
	}
	hello := makeHello(suites, ids)
	m := ClientHelloMetadata(hello, "t")
	if m["ja4"] != "t13d1516h2_8daaf6152771_e5627efa2ab1" || m["server_name"] != "a.b" || m["alpn"] != "" {
		t.Fatalf("wrong fingerprint/offer semantics: %v", m)
	}
	grease := ClientHelloMetadata(makeHello(append([]uint16{0x0a0a}, suites...), append([]uint16{0x2a2a}, ids...)), "t")
	if grease["ja3"] != m["ja3"] || grease["ja4"] != m["ja4"] {
		t.Fatal("GREASE affected fingerprint")
	}
	reversed := append([]uint16(nil), ids...)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	other := ClientHelloMetadata(makeHello(suites, reversed), "t")
	if other["ja4"] != m["ja4"] || other["ja3"] == m["ja3"] {
		t.Fatal("JA3/JA4 extension ordering semantics wrong")
	}
	quic := ClientHelloMetadata(hello, "q")
	if quic["ja4"] != "q"+m["ja4"][1:] {
		t.Fatal("QUIC transport marker lost")
	}
	for n := 0; n < len(hello); n++ {
		if ClientHelloMetadata(hello[:n], "t") != nil {
			t.Fatalf("accepted truncated hello at %d", n)
		}
	}
	for _, test := range []struct {
		value []byte
		want  string
	}{{[]byte{0xab}, "ab"}, {[]byte{0x30, 0xab}, "3b"}, {[]byte{'h'}, "hh"}} {
		bodies[16] = append([]byte{0, byte(len(test.value) + 1), byte(len(test.value))}, test.value...)
		got := ClientHelloMetadata(makeHello(suites, ids), "t")["ja4"]
		if len(got) < 10 || got[8:10] != test.want {
			t.Fatalf("ALPN fingerprint tag %q", got)
		}
	}
}

func TestNegotiatedHandshakeMetadata(t *testing.T) {
	ext := append(helloTestExtension(43, []byte{3, 4}), helloTestExtension(51, []byte{0, 29, 0, 1, 1})...)
	server := helloTestServer(make([]byte, 32), ext)
	got := ServerHelloMetadata(server)
	if got["version"] != "TLS 1.3" || got["cipher_suite"] != "TLS_AES_128_GCM_SHA256" || got["key_exchange_group"] != "X25519" || got["alpn"] != "" {
		t.Fatalf("bad negotiated metadata: %v", got)
	}
	ee := helloTestExtension(16, []byte{0, 3, 2, 'h', '2'})
	ee = handshakeEncoding(8, append([]byte{0, byte(len(ee))}, ee...))
	if EncryptedExtensionsMetadata(ee)["alpn"] != "h2" {
		t.Fatal("authenticated ALPN missing")
	}
	for n := 0; n < len(server); n++ {
		if ServerHelloMetadata(server[:n]) != nil {
			t.Fatalf("accepted partial server hello %d", n)
		}
	}
	for n := 0; n < len(ee); n++ {
		if EncryptedExtensionsMetadata(ee[:n]) != nil {
			t.Fatalf("accepted partial EE %d", n)
		}
	}
}
