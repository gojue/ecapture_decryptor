package transport

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/gojue/ecapture_decryptor/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

// RFC 9001 Appendix A.1 publishes independent key, IV, and header-protection
// vectors for both directions of a QUIC v1 connection.
func TestQUICInitialKeyDerivationRFC9001(t *testing.T) {
	q := &QUICDecryptor{logger: log.New(io.Discard, "", 0), version: 1}
	q.deriveInitialKeys(mustDecodeHex(t, "8394c8f03e515708"))
	for _, test := range []struct {
		name, key, iv, hp string
		actual            *QUICKeys
	}{
		{"client", "1f369613dd76d5467730efcbe3b1a22d", "fa044b2f42a3fd3b46fb255c", "9f50449e04a0e810283a1e9933adedd2", q.clientInitialKeys},
		{"server", "cf3a5331653c364c88f0f379b6067e37", "0ac1493ca1905853b0bba03e", "c206b8d9b9f0f37644430b490eeaa314", q.serverInitialKeys},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.actual == nil || test.actual.aead == nil {
				t.Fatal("Initial AEAD was not derived")
			}
			if !bytes.Equal(test.actual.key, mustDecodeHex(t, test.key)) ||
				!bytes.Equal(test.actual.iv, mustDecodeHex(t, test.iv)) ||
				!bytes.Equal(test.actual.hp, mustDecodeHex(t, test.hp)) {
				t.Fatalf("wrong %s Initial keys: key=%x iv=%x hp=%x", test.name, test.actual.key, test.actual.iv, test.actual.hp)
			}
		})
	}
}

func TestUDPAdapterClassifiesQUICInitial(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload []byte
		initial bool
	}{
		{"v1_initial", []byte{0xc0, 0, 0, 0, 1}, true},
		{"v1_greased_fixed_bit", []byte{0x80, 0, 0, 0, 1}, true},
		{"v1_handshake", []byte{0xe0, 0, 0, 0, 1}, false},
		{"v1_zero_rtt", []byte{0xd0, 0, 0, 0, 1}, false},
		{"v2_initial", []byte{0xd0, 0x6b, 0x33, 0x43, 0xcf}, true},
		{"v2_retry", []byte{0xc0, 0x6b, 0x33, 0x43, 0xcf}, false},
		{"version_negotiation", []byte{0xc0, 0, 0, 0, 0}, false},
		{"short_header", []byte{0x40, 0, 0, 0, 1}, false},
		{"truncated", []byte{0xc0, 0, 0, 0}, false},
		{"other_udp", []byte("hello"), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			adapter := NewUDPAdapter(&layers.UDP{BaseLayer: layers.BaseLayer{Payload: test.payload}})
			if got := adapter.IsSYN(); got != test.initial {
				t.Fatalf("QUIC Initial detection = %t, want %t", got, test.initial)
			}
			if adapter.Protocol() != "udp" || !bytes.Equal(adapter.GetPayload(), test.payload) {
				t.Fatal("UDP adapter did not preserve its protocol or datagram payload")
			}
		})
	}
}

func TestSplitQUICDatagramIgnoresZeroTailAfterInitial(t *testing.T) {
	initial := append([]byte{0xc0, 0, 0, 0, 1, 0, 0, 0, 17}, make([]byte, 17)...)
	padded := append(bytes.Clone(initial), make([]byte, 1106)...)
	packets, err := splitQUICDatagram(padded)
	if err != nil || len(packets) != 1 || !bytes.Equal(packets[0].data, initial) {
		t.Fatalf("split padded Initial: packets=%d err=%v", len(packets), err)
	}
	coalesced := append(bytes.Clone(initial), 0x40, 1, 2, 3)
	packets, err = splitQUICDatagram(coalesced)
	if err != nil || len(packets) != 2 || packets[1].packetType != QUICPacketType1RTT {
		t.Fatalf("split Initial plus 1-RTT: packets=%d err=%v", len(packets), err)
	}
}

func TestQUICBufferPreservesDatagramBoundariesAndCopiesInput(t *testing.T) {
	buffer := NewQUICBuffer()
	first := []byte{1, 2, 3}
	if err := buffer.Write(first); err != nil {
		t.Fatal(err)
	}
	first[0] = 9
	if err := buffer.Write([]byte{4, 5}); err != nil {
		t.Fatal(err)
	}
	if got := buffer.TryRead(); !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatalf("first UDP datagram = %v", got)
	}
	if got := buffer.TryRead(); !bytes.Equal(got, []byte{4, 5}) {
		t.Fatalf("second UDP datagram = %v", got)
	}
	if got := buffer.TryRead(); got != nil {
		t.Fatalf("unexpected extra UDP datagram: %v", got)
	}
	buffer.Close()
	if err := buffer.Write([]byte{6}); err != io.ErrClosedPipe {
		t.Fatalf("write after close = %v, want ErrClosedPipe", err)
	}
}

func TestDecryptRFC9001ServerInitial(t *testing.T) {
	q := &QUICDecryptor{logger: log.New(io.Discard, "", 0), version: quicVersion1}
	q.deriveInitialKeys(mustDecodeHex(t, "8394c8f03e515708"))
	protected := mustDecodeHex(t, "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a"+
		"5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3"+
		"dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84"+
		"022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4"+
		"2158407dd074ee")
	packets, err := splitQUICDatagram(protected)
	if err != nil || len(packets) != 1 || packets[0].packetType != QUICPacketTypeInitial {
		t.Fatalf("parse server Initial: packets=%d err=%v", len(packets), err)
	}
	plaintext, pn, _, err := decryptQUICPacket(packets[0], q.serverInitialKeys, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	want := mustDecodeHex(t, "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739"+
		"88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94"+
		"0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00"+
		"020304")
	if pn != 1 || !bytes.Equal(plaintext, want) {
		t.Fatalf("server Initial: packet number=%d plaintext=%x, want=%x", pn, plaintext, want)
	}
}

func TestDecryptRFC9001ChaChaShortHeader(t *testing.T) {
	secret := mustDecodeHex(t, "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")
	keys, err := deriveQUICKeys(secret, quicVersion1, quicChaCha20)
	if err != nil {
		t.Fatal(err)
	}
	packet := quicPacket{data: mustDecodeHex(t, "4cfe4189655e5cd55c41f69080575d7999c25a5bfb")}
	plaintext, pn, _, err := decryptQUICPacket(packet, keys, 0, 654360563, true)
	if err != nil {
		t.Fatal(err)
	}
	if pn != 654360564 || !bytes.Equal(plaintext, []byte{1}) {
		t.Fatalf("ChaCha20 short header: packet number=%d plaintext=%x", pn, plaintext)
	}
}

// Fixed expectations generated with Python hashlib/hmac (HKDF-Expand-Label),
// independent of expandQUICLabel. Input secret is bytes 0..31 (SHA256) or
// 0..47 (SHA384); the original HP key must survive both updates.
func TestQUICKeyUpdateVectors(t *testing.T) {
	for _, tc := range []struct {
		version                 uint32
		suite                   quicCipherSuite
		secret, key, iv, second string
	}{
		{quicVersion1, quicAES128, "6a4ca349a77d8643fc3d19b944d2c3de71cfc6727dff1962e00a30a6c5f4a7cd", "52a8ea4d44bd6ee8f7f34df728be5dea", "8c1635ecd2b745d8467158ed", "035c2e10c0849c79e2ae34b09716245b8903e0a7562aa6e60fd9cc9b571c67e4"},
		{quicVersion1, quicAES256, "d21f524277390ba96b86484d9c687f850f1e4d1f997033bba06051129179a762a94067d065f3f715e83d65a7bf8c79b9", "1a8ec1b9043b8a548f7780a26fd9f9cfb8f3eccf5fe64cd5879769c455e84e8c", "d710ad4869fa86124824cbb1", "b59dc4ced911d493647f41512cc4dd23f2c923690d97a00c65a6fceb5223efb25c9ef800978182d78ffa35232acad18b"},
		{quicVersion1, quicChaCha20, "6a4ca349a77d8643fc3d19b944d2c3de71cfc6727dff1962e00a30a6c5f4a7cd", "947f35d4ef48247c335c01c6f8d263de7eebfe5974e9f177809ee48c8b043441", "8c1635ecd2b745d8467158ed", "035c2e10c0849c79e2ae34b09716245b8903e0a7562aa6e60fd9cc9b571c67e4"},
		{quicVersion2, quicAES128, "48d47d0f9ab5b339758d7e26751d9425e1d81b7d4c216f71894f383fc9b246e9", "83bfe0192ac31e4af7c6e308a823b01e", "c6fb1bc3643c144d60c802fb", "7d9a3a5ac9d735cdd6fc4a00d01418a8a4e10b09ba19dcc1ba1c5c5696bcf123"},
		{quicVersion2, quicAES256, "5d745f2979be4db8e0cee23c76e261c7dd642f4181be807cef5b222c3d249eea8aef3941a4bb072775e4cf0bf1eae44c", "16b58be08573ad797179d693ae9c7d7f5bbad821cd12c50dd441d02796b2ef07", "321af7498ce594b7874ae725", "311147512f1b9b713c924a66d60c3f7378f28fbf89550b56a97dd95cd6564117ee31caaa47575ac555c5b103c601431c"},
		{quicVersion2, quicChaCha20, "48d47d0f9ab5b339758d7e26751d9425e1d81b7d4c216f71894f383fc9b246e9", "5c3ac3846dd4ffc9149724ef2f429c15c0f4fa540403083612c5292b65ec1739", "c6fb1bc3643c144d60c802fb", "7d9a3a5ac9d735cdd6fc4a00d01418a8a4e10b09ba19dcc1ba1c5c5696bcf123"},
	} {
		t.Run(fmt.Sprintf("%x/%d", tc.version, tc.suite), func(t *testing.T) {
			size := 32
			if tc.suite == quicAES256 {
				size = 48
			}
			secret := make([]byte, size)
			for i := range secret {
				secret[i] = byte(i)
			}
			initial, err := deriveQUICKeys(secret, tc.version, tc.suite)
			if err != nil {
				t.Fatal(err)
			}
			next, err := initial.nextKeys()
			if err != nil {
				t.Fatal(err)
			}
			second, err := next.nextKeys()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(next.secret, mustDecodeHex(t, tc.secret)) || !bytes.Equal(next.key, mustDecodeHex(t, tc.key)) || !bytes.Equal(next.iv, mustDecodeHex(t, tc.iv)) || !bytes.Equal(second.secret, mustDecodeHex(t, tc.second)) || !bytes.Equal(initial.hp, next.hp) || !bytes.Equal(initial.hp, second.hp) {
				t.Fatal("key update differs from independent HKDF vector or changed header protection")
			}
		})
	}
}

// This helper only seals state-machine inputs. Derivation is checked separately
// against fixed independent vectors above and real quic-go captures at SDK level.
func quicKeyPhasePacket(t *testing.T, key *QUICKeys, pn uint64, phase byte, frame []byte) quicPacket {
	t.Helper()
	header := []byte{0x40 | phase<<2, byte(pn)} // One-byte PN exercises wrap at 255.
	nonce := bytes.Clone(key.iv)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	data := append(header, key.aead.Seal(nil, nonce, frame, header)...)
	mask, err := key.headerMask(data[5:21])
	if err != nil {
		t.Fatal(err)
	}
	data[0] ^= mask[0] & 0x1f
	data[1] ^= mask[1]
	return quicPacket{data: data, packetType: QUICPacketType1RTT}
}

func TestQUICKeyUpdateState(t *testing.T) {
	for _, version := range []uint32{quicVersion1, quicVersion2} {
		for _, suite := range []quicCipherSuite{quicAES128, quicAES256, quicChaCha20} {
			t.Run(fmt.Sprintf("%x/%d", version, suite), func(t *testing.T) {
				// Independent connections and directions use different secrets. Interleave
				// their inputs so advancing one cannot advance or select another's keys.
				var flows [2]*QUICDecryptor
				var outputs [2]chan *types.DecryptedPacket
				var keys [2][2][3]*QUICKeys
				var diagnostics []types.Diagnostic
				for conn := range flows {
					flows[conn], outputs[conn] = newQUICOutputTest(t, types.DecryptOptions{RawChunks: true, OnDiagnostic: func(d types.Diagnostic) { diagnostics = append(diagnostics, d) }})
					q := flows[conn]
					q.version = version
					q.flow.clientRandom = bytes.Repeat([]byte{byte(conn + 1)}, 32)
					size := 32
					if suite == quicAES256 {
						size = 48
					}
					for dir := 0; dir < 2; dir++ {
						secret := bytes.Repeat([]byte{byte(10*conn + dir + 1)}, size)
						label := "CLIENT_TRAFFIC_SECRET_0"
						if dir == 1 {
							label = "SERVER_TRAFFIC_SECRET_0"
						}
						q.keyLog.AddSecret(label, hex.EncodeToString(q.flow.clientRandom), secret)
						var err error
						keys[conn][dir][0], err = deriveQUICKeys(secret, version, suite)
						if err != nil {
							t.Fatal(err)
						}
						for generation := 1; generation < 3; generation++ {
							keys[conn][dir][generation], err = keys[conn][dir][generation-1].nextKeys()
							if err != nil {
								t.Fatal(err)
							}
						}
					}
				}
				frame := func(id, offset byte, fin bool) []byte {
					typ := byte(0x0e)
					if fin {
						typ++
					}
					return []byte{typ, id, offset, 3, 'a', 'b', 'c'}
				}
				for _, step := range []struct {
					generation int
					pn         uint64
					id, offset byte
					fin        bool
				}{
					{0, 250, 0, 0, false}, {1, 260, 4, 0, true}, {0, 251, 0, 3, true},
					{1, 258, 8, 0, true}, {1, 260, 4, 0, true}, {0, 250, 0, 0, false},
					{2, 280, 12, 0, true}, {1, 262, 16, 0, true},
				} {
					for conn, q := range flows {
						for dir := 0; dir < 2; dir++ {
							packet := quicKeyPhasePacket(t, keys[conn][dir][step.generation], step.pn, byte(step.generation&1), frame(step.id, step.offset, step.fin))
							if deferred, err := q.processQUICPacket(packet, dir == 0, time.Time{}); err != nil || deferred {
								t.Fatalf("conn=%d dir=%d generation=%d pn=%d: %v deferred=%t", conn, dir, step.generation, step.pn, err, deferred)
							}
						}
					}
				}
				if len(diagnostics) != 0 {
					t.Fatalf("valid input diagnostics: %+v", diagnostics)
				}
				for conn, q := range flows {
					if len(outputs[conn]) != 12 {
						t.Fatalf("connection %d emitted %d chunks, want 12 without duplicates", conn, len(outputs[conn]))
					}
					for len(outputs[conn]) > 0 {
						packet := <-outputs[conn]
						if !bytes.Equal(packet.Data, []byte("abc")) {
							t.Fatalf("wrong authenticated bytes: %x", packet.Data)
						}
					}
					for dir := 0; dir < 2; dir++ {
						state := q.flow.keyPhase[dir]
						if state.generation != 2 || state.previous == nil || !bytes.Equal(state.previous.secret, keys[conn][dir][1].secret) || q.flow.largest[dir][quicLevelApplication] != 280 {
							t.Fatal("wrong committed generation or packet number")
						}
						good := quicKeyPhasePacket(t, keys[conn][dir][2], 281, 0, frame(20, 0, true))
						tampered := quicPacket{data: bytes.Clone(good.data)}
						tampered.data[0] ^= 4
						corrupt := quicPacket{data: bytes.Clone(good.data)}
						corrupt.data[len(corrupt.data)-1] ^= 1
						for _, bad := range []quicPacket{
							tampered, corrupt,
							quicKeyPhasePacket(t, keys[1-conn][dir][2], 281, 0, frame(20, 0, true)), // Wrong secret.
							quicKeyPhasePacket(t, keys[conn][dir][0], 252, 0, frame(20, 0, true)),   // Evicted generation.
							quicKeyPhasePacket(t, keys[conn][dir][1], 282, 1, frame(20, 0, true)),   // Old key above current PN.
							quicKeyPhasePacket(t, keys[conn][dir][2], 261, 0, frame(20, 0, true)),   // Current key below observed old PN.
							quicKeyPhasePacket(t, keys[conn][dir][2], 281, 1, frame(20, 0, true)),   // Authenticated wrong phase.
						} {
							before := q.flow.keyPhase[dir]
							before.next = [2]*QUICKeys{} // Speculative candidates may be cached, never committed.
							if deferred, err := q.processQUICPacket(bad, dir == 0, time.Time{}); err == nil || deferred {
								t.Fatal("invalid packet accepted or deferred")
							}
							after := q.flow.keyPhase[dir]
							after.next = [2]*QUICKeys{}
							if !reflect.DeepEqual(before, after) || q.flow.largest[dir][quicLevelApplication] != 280 || len(outputs[conn]) != 0 {
								t.Fatal("failed authentication advanced state or emitted bytes")
							}
						}
						if deferred, err := q.processQUICPacket(good, dir == 0, time.Time{}); err != nil || deferred {
							t.Fatalf("valid packet after failures: %v", err)
						}
						<-outputs[conn]
					}
					_ = q.Close()
					if err := q.Decrypt(); err != nil {
						t.Fatal(err)
					}
					assertQUICReleased(t, q)
					if !reflect.DeepEqual(q.flow.keyPhase, [2]quicKeyPhaseState{}) {
						t.Fatal("closed connection retained key generations")
					}
				}
				if len(diagnostics) != 28 {
					t.Fatalf("failure diagnostics=%d, want 28", len(diagnostics))
				}
				for _, d := range diagnostics {
					if d.Stage != "decrypt" || d.Code != "authentication_failed" {
						t.Fatalf("unsafe or incorrect diagnostic: %+v", d)
					}
				}
			})
		}
	}
}

func TestQUICKeyUpdateDoesNotSkipGenerations(t *testing.T) {
	q, output := newQUICOutputTest(t, types.DecryptOptions{RawChunks: true})
	q.version = quicVersion2
	initial, err := deriveQUICKeys(make([]byte, 32), q.version, quicAES128)
	if err != nil {
		t.Fatal(err)
	}
	first, err := initial.nextKeys()
	if err != nil {
		t.Fatal(err)
	}
	second, err := first.nextKeys()
	if err != nil {
		t.Fatal(err)
	}
	q.flow.keys[0][quicLevelApplication] = []*QUICKeys{initial}
	frame := []byte{0x0b, 0, 3, 'a', 'b', 'c'}
	future := quicKeyPhasePacket(t, second, 22, 0, frame)
	for i := 0; i < 2; i++ {
		cached := q.flow.keyPhase[0].next[0]
		if pending, err := q.processQUICPacket(future, true, time.Time{}); err == nil || pending {
			t.Fatal("skipped two generations")
		}
		if q.flow.haveLargest[0][quicLevelApplication] || q.flow.keyPhase[0].authenticated || len(output) != 0 {
			t.Fatal("unauthenticated packet changed committed state")
		}
		if i == 1 && q.flow.keyPhase[0].next[0] != cached {
			t.Fatal("rederived next keys on repeated failure")
		}
	}
	// The first observed application packet can be in generation one. A later
	// retry of generation two then authenticates without additional keylog data.
	for _, packet := range []quicPacket{quicKeyPhasePacket(t, first, 21, 1, frame), future} {
		if pending, err := q.processQUICPacket(packet, true, time.Time{}); err != nil || pending {
			t.Fatalf("cannot recover after missing generation: %v", err)
		}
	}
	if q.flow.keyPhase[0].generation != 2 || len(output) != 1 {
		t.Fatal("wrong generation or duplicate stream output")
	}
}

func TestQUICKeyUpdateSecretArrivesDuringRetry(t *testing.T) {
	q, output := newQUICOutputTest(t, types.DecryptOptions{RawChunks: true})
	q.version = quicVersion1
	q.flow.clientRandom = bytes.Repeat([]byte{0x44}, 32)
	random := hex.EncodeToString(q.flow.clientRandom)
	clientSecret, serverSecret := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	q.keyLog.AddSecret("CLIENT_TRAFFIC_SECRET_0", random, clientSecret)
	client, err := deriveQUICKeys(clientSecret, q.version, quicAES128)
	if err != nil {
		t.Fatal(err)
	}
	server, err := deriveQUICKeys(serverSecret, q.version, quicAES128)
	if err != nil {
		t.Fatal(err)
	}
	q.SetOptions(types.DecryptOptions{RawChunks: true, OnDiagnostic: func(d types.Diagnostic) {
		// This synchronous callback makes the mid-pass key arrival deterministic.
		if d.Code == "invalid_frame" {
			q.keyLog.AddSecret("SERVER_TRAFFIC_SECRET_0", random, serverSecret)
		}
	}})
	for generation := 0; generation < 3; generation++ {
		frame := []byte{0x0b, byte(4 * generation), 3, 'a', 'b', 'c'}
		q.flow.pending = append(q.flow.pending, quicDeferredPacket{packet: quicKeyPhasePacket(t, server, uint64(generation), byte(generation&1), frame)})
		if generation == 0 {
			// Authenticated but truncated STREAM frame, followed by padding-sized
			// ciphertext so that header protection has a complete sample.
			badFrame := []byte{0x0a, 0, 63}
			q.flow.pending = append(q.flow.pending, quicDeferredPacket{packet: quicKeyPhasePacket(t, client, 0, 0, badFrame), isClient: true})
		}
		server, err = server.nextKeys()
		if err != nil {
			t.Fatal(err)
		}
	}
	q.retryDeferredQUICPackets()
	if len(q.flow.pending) != 3 || q.flow.keyPhase[1].authenticated || len(output) != 0 {
		t.Fatal("newly available secret let later packets overtake the deferred prefix")
	}
	q.retryDeferredQUICPackets()
	if len(q.flow.pending) != 0 || q.flow.pendingBytes != 0 || q.flow.keyPhase[1].generation != 2 || len(output) != 3 {
		t.Fatal("ordered retry failed to decrypt all key generations")
	}
	if len(q.flow.errors) != 1 {
		t.Fatalf("errors=%v, want only the intentional malformed client frame", q.flow.errors)
	}
}

func TestQUICKeyUpdateCapturedGenerations(t *testing.T) {
	for _, tc := range []struct {
		version    int
		generation uint64
	}{{1, 8}, {2, 7}} {
		t.Run(fmt.Sprintf("v%d", tc.version), func(t *testing.T) {
			base := fmt.Sprintf("../test/testdata/http3_keyupdate_v%d", tc.version)
			capture, err := os.Open(base + ".pcapng")
			if err != nil {
				t.Fatal(err)
			}
			defer capture.Close()
			reader, err := pcapgo.NewNgReader(capture, pcapgo.DefaultNgReaderOptions)
			if err != nil {
				t.Fatal(err)
			}
			q, _ := newQUICOutputTest(t, types.DecryptOptions{RawChunks: true})
			q.packetChan = make(chan *types.DecryptedPacket, 512)
			keylog, err := os.ReadFile(base + ".keys")
			if err != nil {
				t.Fatal(err)
			}
			if err := q.keyLog.LoadFromReader(bytes.NewReader(keylog)); err != nil {
				t.Fatal(err)
			}
			for {
				data, info, err := reader.ReadPacketData()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				packet := gopacket.NewPacket(data, reader.LinkType(), gopacket.Default)
				udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
				if !ok {
					t.Fatal("fixture contains non-UDP packet")
				}
				q.processQUICDatagram(quicDatagram{data: udp.Payload, isClient: udp.DstPort == 44433, at: info.Timestamp})
			}
			if len(q.flow.errors) != 0 || len(q.flow.pending) != 0 {
				t.Fatalf("capture decryption failed: %v; pending=%d", q.flow.errors, len(q.flow.pending))
			}
			for dir, state := range q.flow.keyPhase {
				if state.generation != tc.generation {
					t.Fatalf("direction %d generation=%d, want %d actual updates", dir, state.generation, tc.generation)
				}
			}
			_ = q.Close()
			if err := q.Decrypt(); err != nil {
				t.Fatal(err)
			}
			assertQUICReleased(t, q)
		})
	}
}
