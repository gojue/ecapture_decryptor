package transport

import (
	"bytes"
	"encoding/hex"
	"io"
	"log"
	"testing"

	"github.com/google/gopacket/layers"
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
