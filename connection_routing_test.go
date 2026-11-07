package ecapture_decryptor

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gojue/ecapture_decryptor/crypto"
	"github.com/gojue/ecapture_decryptor/transport"
	"github.com/gojue/ecapture_decryptor/types"
	"github.com/google/gopacket/layers"
)

type routingDecryptor struct {
	addr                       types.ConnectionKey
	mu                         sync.Mutex
	client                     [][]byte
	server                     [][]byte
	closed                     chan struct{}
	closeMu                    sync.Once
	clientClosed, serverClosed bool
	resetObserved              bool
	finish                     <-chan struct{} // Optional completion gate, configured before Close.
}

func (d *routingDecryptor) Decrypt() error {
	<-d.closed
	if d.finish != nil {
		<-d.finish
	}
	return nil
}
func (d *routingDecryptor) SetPacketTime(time.Time) {}
func (d *routingDecryptor) CloseClient() error      { return d.closeDirection(true) }
func (d *routingDecryptor) CloseServer() error      { return d.closeDirection(false) }
func (d *routingDecryptor) ObserveTCPReset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.resetObserved = true
}
func (d *routingDecryptor) closeDirection(client bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if client {
		d.clientClosed = true
	} else {
		d.serverClosed = true
	}
	if d.clientClosed && d.serverClosed {
		return d.Close()
	}
	return nil
}
func (d *routingDecryptor) GetAddr() types.ConnectionKey { return d.addr }
func (d *routingDecryptor) Close() error {
	d.closeMu.Do(func() { close(d.closed) })
	return nil
}
func (d *routingDecryptor) FeedClient(payload []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.client = append(d.client, bytes.Clone(payload))
	return nil
}
func (d *routingDecryptor) FeedServer(payload []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.server = append(d.server, bytes.Clone(payload))
	return nil
}

func withRoutingDecryptor(t *testing.T, protocol string, run func(*DecryptorEngine, *[]*routingDecryptor)) {
	t.Helper()
	var created []*routingDecryptor
	decryptorRegistryMu.Lock()
	previous, existed := decryptorRegistry[protocol]
	decryptorRegistry[protocol] = func(key types.ConnectionKey, _ *DecryptorFactory) types.Decryptor {
		decryptor := &routingDecryptor{addr: key, closed: make(chan struct{})}
		created = append(created, decryptor)
		return decryptor
	}
	decryptorRegistryMu.Unlock()
	t.Cleanup(func() {
		decryptorRegistryMu.Lock()
		if existed {
			decryptorRegistry[protocol] = previous
		} else {
			delete(decryptorRegistry, protocol)
		}
		decryptorRegistryMu.Unlock()
	})
	logger := log.New(io.Discard, "", 0)
	engine := &DecryptorEngine{
		keyLog: crypto.NewKeyLogStore(), logger: logger,
		conntrack: make(map[string]types.Decryptor), tcpFlows: make(map[string]*tcpConnection),
	}
	engine.factory = NewDecryptorFactory(engine.keyLog, logger, nil)
	defer engine.waitForAllConnections()
	run(engine, &created)
}

func TestTCPPortTupleReuseStartsNewConnectionGeneration(t *testing.T) {
	withRoutingDecryptor(t, types.TransportProtocolTCP, func(engine *DecryptorEngine, created *[]*routingDecryptor) {
		clientIP := transport.NewIPv4Adapter(&layers.IPv4{SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2)})
		serverIP := transport.NewIPv4Adapter(&layers.IPv4{SrcIP: net.IPv4(192, 0, 2, 2), DstIP: net.IPv4(192, 0, 2, 1)})
		clientTCP := func(seq uint32, syn bool, payload string) *transport.TCPAdapter {
			return transport.NewTCPAdapter(&layers.TCP{SrcPort: 41004, DstPort: 443, Seq: seq, SYN: syn, BaseLayer: layers.BaseLayer{Payload: []byte(payload)}})
		}
		serverTCP := func(seq uint32, payload string) *transport.TCPAdapter {
			return transport.NewTCPAdapter(&layers.TCP{SrcPort: 443, DstPort: 41004, Seq: seq, ACK: true, BaseLayer: layers.BaseLayer{Payload: []byte(payload)}})
		}
		at := time.Unix(1, 0)
		engine.handlePacket(clientIP, clientTCP(100, true, ""), at)
		engine.handlePacket(clientIP, clientTCP(101, false, "first"), at)
		engine.handlePacket(serverIP, serverTCP(900, "reply"), at)
		engine.handlePacket(clientIP, clientTCP(500, true, ""), at)
		engine.handlePacket(clientIP, clientTCP(501, false, "second"), at)
		if len(*created) != 2 {
			t.Fatalf("got %d decryptors for reused TCP tuple, want 2", len(*created))
		}
		first, second := (*created)[0], (*created)[1]
		select {
		case <-first.closed:
		default:
			t.Fatal("old TCP generation remained open after a new SYN")
		}
		if first.addr.Generation == second.addr.Generation || second.addr.Generation == 0 {
			t.Fatalf("TCP tuple was not assigned a new generation: %d and %d", first.addr.Generation, second.addr.Generation)
		}
		if len(first.client) != 1 || string(first.client[0]) != "first" || len(first.server) != 1 || string(first.server[0]) != "reply" ||
			len(second.client) != 1 || string(second.client[0]) != "second" || len(second.server) != 0 {
			t.Fatalf("TCP payload crossed generations: first=%q/%q second=%q/%q", first.client, first.server, second.client, second.server)
		}
	})
}

func TestUDPQUICInitialAndReverseDatagramRouting(t *testing.T) {
	withRoutingDecryptor(t, types.TransportProtocolUDP, func(engine *DecryptorEngine, created *[]*routingDecryptor) {
		clientIP := transport.NewIPv4Adapter(&layers.IPv4{SrcIP: net.IPv4(192, 0, 2, 3), DstIP: net.IPv4(192, 0, 2, 4)})
		serverIP := transport.NewIPv4Adapter(&layers.IPv4{SrcIP: net.IPv4(192, 0, 2, 4), DstIP: net.IPv4(192, 0, 2, 3)})
		initial := []byte{0xc0, 0, 0, 0, 1, 0, 0}
		response := []byte{0x40, 1, 2, 3, 4}
		at := time.Unix(2, 0)
		engine.handlePacket(clientIP, transport.NewUDPAdapter(&layers.UDP{SrcPort: 41005, DstPort: 443, BaseLayer: layers.BaseLayer{Payload: initial}}), at)
		engine.handlePacket(serverIP, transport.NewUDPAdapter(&layers.UDP{SrcPort: 443, DstPort: 41005, BaseLayer: layers.BaseLayer{Payload: response}}), at)
		if len(*created) != 1 {
			t.Fatalf("got %d QUIC decryptors, want 1", len(*created))
		}
		decryptor := (*created)[0]
		if decryptor.addr.Proto != types.TransportProtocolUDP || len(decryptor.client) != 1 || !bytes.Equal(decryptor.client[0], initial) ||
			len(decryptor.server) != 1 || !bytes.Equal(decryptor.server[0], response) {
			t.Fatalf("UDP datagrams were not routed to the QUIC flow: client=%x server=%x", decryptor.client, decryptor.server)
		}
	})
}

func TestQUICCIDRoutingMigrationIsolationAndRetirement(t *testing.T) {
	withRoutingDecryptor(t, types.TransportProtocolUDP, func(e *DecryptorEngine, created *[]*routingDecryptor) {
		key := types.ConnectionKey{SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2), SrcPort: 41000, DstPort: 443, Proto: "udp"}
		initial := func(dcid, scid string) []byte {
			p := append([]byte{0xc0, 0, 0, 0, 1, byte(len(dcid))}, []byte(dcid)...)
			p = append(p, byte(len(scid)))
			return append(p, []byte(scid)...)
		}
		short := func(cid string) []byte {
			return append(append([]byte{0x40}, []byte(cid)...), bytes.Repeat([]byte{0xff}, 24)...)
		}
		e.handleQUICPacket(key, initial("dest-one", "client-one"), time.Time{})
		e.handleQUICPacket(key, initial("dest-two", "client-two"), time.Time{})
		if len(*created) != 2 {
			t.Fatalf("same tuple connections=%d", len(*created))
		}
		first, second := (*created)[0], (*created)[1]
		route := e.quic.routes[first.addr.String()]
		if _, err := e.quicCIDUpdate(route, []byte("rotated"), false, false); err != nil {
			t.Fatal(err)
		}
		migrated := key
		migrated.SrcPort++
		e.handleQUICPacket(migrated, short("rotated"), time.Time{})
		e.handleQUICPacket(migrated.Reverse(), short("client-one"), time.Time{})
		e.handleQUICPacket(key, short("dest-two"), time.Time{})
		if len(first.client) != 2 || len(first.server) != 1 || len(second.client) != 2 || len(second.server) != 0 {
			t.Fatal("migration lost identity or crossed connections")
		}
		if len(route.aliases) != 2 {
			t.Fatal("migration tuple was not recorded")
		}
		if _, err := e.quicCIDUpdate(route, []byte("rotated"), false, true); err != nil {
			t.Fatal(err)
		}
		e.handleQUICPacket(migrated, short("rotated"), time.Time{})
		if len(first.client) != 2 || len(route.aliases) != 1 || len(e.quic.pending) != 1 {
			t.Fatal("retired CID/tuple still routed")
		}
		// Colliding IDs must never use tuple proximity to choose a connection.
		other := e.quic.routes[second.addr.String()]
		if _, err := e.quicCIDUpdate(other, []byte("client-one"), true, false); err != nil {
			t.Fatal(err)
		}
		e.handleQUICPacket(key.Reverse(), short("client-one"), time.Time{})
		if len(first.server) != 1 || len(second.server) != 0 {
			t.Fatal("ambiguous CID routed")
		}
		for i := 0; i < 20; i++ {
			migrated.SrcPort++
			e.handleQUICPacket(migrated, short("dest-one"), time.Time{})
		}
		if len(route.aliases) > maxQUICTupleAliases {
			t.Fatal("unbounded tuple aliases")
		}
		e.expireIdleConnections(time.Now().Add(time.Hour), time.Second)
		if len(e.quic.routes) != 0 || len(e.quic.cids) != 0 {
			t.Fatal("idle cleanup leaked CID index")
		}
		e.expireQUICPending(time.Now(), true)
		if len(e.quic.pending) != 0 || e.quic.bytes != 0 {
			t.Fatal("pending routing leaked")
		}
	})
}

func TestQUICCIDPendingReleaseAndCapacity(t *testing.T) {
	withRoutingDecryptor(t, types.TransportProtocolUDP, func(e *DecryptorEngine, created *[]*routingDecryptor) {
		e.factory.options = types.DecryptOptions{MaxConnections: 1}
		key := types.ConnectionKey{SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2), SrcPort: 41000, DstPort: 443, Proto: "udp"}
		e.handleQUICPacket(key, []byte{0xc0, 0, 0, 0, 1, 1, 7, 1, 8}, time.Time{})
		first := (*created)[0]
		finish := make(chan struct{})
		first.finish = finish
		data := append([]byte{0x40, 9}, bytes.Repeat([]byte{0xff}, 20)...)
		e.handleQUICPacket(key, data, time.Unix(7, 0))
		if len(e.quic.pending) != 1 {
			t.Fatal("unknown CID guessed from tuple")
		}
		route := e.quic.routes[first.addr.String()]
		ready, err := e.quicCIDUpdate(route, []byte{9}, false, false)
		if err != nil || len(ready) != 1 || !ready[0].IsClient || !ready[0].Time.Equal(time.Unix(7, 0)) || !bytes.Equal(ready[0].Data, data) {
			t.Fatal("CID announcement did not release captured packet", err)
		}
		if len(e.quic.pending) != 0 || e.quic.bytes != 0 {
			t.Fatal("released packet retained")
		}
		e.expireIdleConnections(time.Now().Add(time.Hour), time.Second)
		e.handleQUICPacket(key, []byte{0xc0, 0, 0, 0, 1, 1, 10, 1, 11}, time.Time{})
		if len(*created) != 1 {
			t.Fatal("closing worker did not consume connection quota")
		}
		close(finish)
	})
}

func TestQUICZeroCIDDoesNotGuessMigrationOrAmbiguousTuple(t *testing.T) {
	withRoutingDecryptor(t, types.TransportProtocolUDP, func(e *DecryptorEngine, created *[]*routingDecryptor) {
		key := types.ConnectionKey{SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2), SrcPort: 41000, DstPort: 443, Proto: "udp"}
		e.handleQUICPacket(key, []byte{0xc0, 0, 0, 0, 1, 1, 7, 0}, time.Time{})
		first := (*created)[0]
		data := append([]byte{0x40}, bytes.Repeat([]byte{0xff}, 20)...)
		e.handleQUICPacket(key.Reverse(), data, time.Time{})
		migrated := key
		migrated.SrcPort++
		e.handleQUICPacket(migrated.Reverse(), data, time.Time{})
		if len(first.server) != 1 || len(e.quic.pending) != 1 {
			t.Fatal("zero CID migration guessed a connection")
		}
		// Another same-tuple connection makes the zero-CID direction ambiguous.
		// A distinct connection must authenticate with its own Initial DCID;
		// an unknown peer CID alone is not evidence of a new connection.
		initial, err := hex.DecodeString(quicZeroCIDInitialVectors[0].fresh)
		if err != nil {
			t.Fatal(err)
		}
		e.handleQUICPacket(key, initial, time.Time{})
		if len(*created) != 2 {
			t.Fatal("distinct Initial did not create a second route")
		}
		e.handleQUICPacket(key.Reverse(), data, time.Time{})
		if len(first.server) != 1 || len((*created)[1].server) != 0 {
			t.Fatal("zero CID ambiguous tuple guessed a connection")
		}
		e.handleQUICPacket(key.Reverse(), []byte{0xc0, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4}, time.Time{})
		if len(first.server) != 1 || len((*created)[1].server) != 0 {
			t.Fatal("zero CID ambiguous server Initial guessed a connection")
		}
		e.expireQUICPending(time.Now().Add(time.Minute), false)
		if len(e.quic.pending) != 0 {
			t.Fatal("unknown-CID waiting deadline not bounded")
		}
	})
}

// Protected Initials with SCID length zero, PN 1 and 24 PADDING bytes. The
// second packet uses DCID "rotated!" but retains the keys for "original", as
// required when a client adopts a server CID without Retry. These are packet
// protection vectors, not captures or complete handshakes.
var quicZeroCIDInitialVectors = []struct{ name, fresh, changed string }{
	{"v1", "c200000001086f726967696e616c000040299c3c8a8bc9c9efb108a2446dce3b5e2eaf7337f02499c94e5b35e11950babf2bce7c6536bf5725d3f9", "c20000000108726f746174656421000040299c3c8a8bc9c9efb108a2446dce3b5e2eaf7337f02499c94e5b4112cbf83757e640051e3e04f6f51bd0"},
	{"v2", "db6b3343cf086f726967696e616c0000402976901cf347a45fda20c6b4ea254dd0bb4e60493c643ec0a6df5ba9bdeb188d595029182d6d0afcdab9", "db6b3343cf08726f7461746564210000402976901cf347a45fda20c6b4ea254dd0bb4e60493c643ec0a6dfb3818559e38d92b54a1d3103ce4a34e4"},
}

func TestQUICZeroCIDInitialBeforePeerCIDPublication(t *testing.T) {
	for _, vector := range quicZeroCIDInitialVectors {
		for _, publishFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/publish_first=%t", vector.name, publishFirst), func(t *testing.T) {
				withRoutingDecryptor(t, types.TransportProtocolUDP, func(e *DecryptorEngine, created *[]*routingDecryptor) {
					fresh, err := hex.DecodeString(vector.fresh)
					if err != nil {
						t.Fatal(err)
					}
					changed, err := hex.DecodeString(vector.changed)
					if err != nil {
						t.Fatal(err)
					}
					key := types.ConnectionKey{SrcIP: net.IPv4(127, 0, 0, 1), DstIP: net.IPv4(127, 0, 0, 1), SrcPort: 41000, DstPort: 443, Proto: "udp"}
					e.handleQUICPacket(key, fresh, time.Time{})
					e.handleQUICPacket(key, fresh, time.Time{})
					first := (*created)[0]
					route := e.quic.routes[first.addr.String()]
					if publishFirst {
						if _, err := e.quicCIDUpdate(route, []byte("rotated!"), false, false); err != nil {
							t.Fatal(err)
						}
					}
					// No worker scheduling or sleeps: publish explicitly before or
					// after the reader has delivered both copies of the Initial.
					e.handleQUICPacket(key, changed, time.Unix(7, 0))
					e.handleQUICPacket(key, changed, time.Unix(8, 0))
					response := append([]byte{0x40}, bytes.Repeat([]byte{0xff}, 24)...)
					e.handleQUICPacket(key.Reverse(), response, time.Time{})
					if len(*created) != 1 || len(first.server) != 1 {
						t.Fatal("peer CID publication race created a second route or lost direction")
					}
					if len(first.client) != 4 || !bytes.Equal(first.client[2], changed) || !bytes.Equal(first.client[3], changed) {
						t.Fatal("authenticated Initial lost bytes or direction")
					}
					ready, err := e.quicCIDUpdate(route, []byte("rotated!"), false, false)
					if err != nil || len(ready) != 0 {
						t.Fatal("CID publication repeated an already delivered Initial")
					}
					if e.quic.bytes != 0 || len(e.quic.pending) != 0 {
						t.Fatal("pending Initial storage was not released")
					}
					// An unrecognized, damaged Initial must neither create a
					// second zero-CID route nor be selected by tuple alone.
					bad := bytes.Clone(changed)
					copy(bad[6:14], "unknown!")
					e.handleQUICPacket(key, bad, time.Time{})
					if len(*created) != 1 || len(first.client) != 4 || len(e.quic.pending) != 1 {
						t.Fatal("unauthenticated Initial bypassed bounded CID waiting")
					}
					e.expireQUICPending(time.Now().Add(time.Minute), false)
					if len(e.quic.pending) != 0 || e.quic.bytes != 0 || e.connectionError() == nil {
						t.Fatal("unknown Initial did not expire with an error")
					}
				})
			})
		}
	}
}

func TestQUICZeroCIDTupleIsolationAndCleanup(t *testing.T) {
	withRoutingDecryptor(t, types.TransportProtocolUDP, func(e *DecryptorEngine, created *[]*routingDecryptor) {
		// Header-only packets exercise the router with the existing fake worker.
		// Two zero-SCID tuples and an eight-byte SCID control carry distinct bytes.
		initial := func(dcid, scid string) []byte {
			p := append([]byte{0xc0, 0, 0, 0, 1, byte(len(dcid))}, dcid...)
			return append(append(p, byte(len(scid))), scid...)
		}
		keys := make([]types.ConnectionKey, 3)
		for i := range keys {
			keys[i] = types.ConnectionKey{SrcIP: net.IPv4(127, 0, 0, 1), DstIP: net.IPv4(127, 0, 0, 1), SrcPort: uint16(41000 + i), DstPort: 443, Proto: "udp"}
			scid := ""
			if i == 2 {
				scid = "client-8"
			}
			e.handleQUICPacket(keys[i], initial(fmt.Sprintf("dest-%03d", i), scid), time.Time{})
		}
		if len(*created) != 3 {
			t.Fatal("distinct original tuples did not create isolated connections")
		}
		for i, key := range keys {
			scid := ""
			if i == 2 {
				scid = "client-8"
				// The nonzero SCID can link a changed Initial before peer CID
				// publication, without relying on the original tuple fallback.
				e.handleQUICPacket(key, initial("unseen-8", scid), time.Time{})
			}
			p := initial("", fmt.Sprintf("peer-%03d", i))
			if i == 2 {
				p = initial(scid, fmt.Sprintf("peer-%03d", i))
			}
			e.handleQUICPacket(key.Reverse(), p, time.Time{})
			d := (*created)[i]
			if len(d.server) != 1 || !bytes.Equal(d.server[0], p) {
				t.Fatal("response bytes crossed tuple or direction")
			}
			want := 1
			if i == 2 {
				want = 2
			}
			if len(d.client) != want {
				t.Fatal("mixed CID control lost client Initial")
			}
		}
		e.expireIdleConnections(time.Now().Add(time.Hour), time.Second)
		e.connections.Wait()
		e.mu.Lock()
		clean := e.active == 0 && len(e.conntrack) == 0 && len(e.quic.routes) == 0 && len(e.quic.cids) == 0 && len(e.quic.pending) == 0 && e.quic.bytes == 0
		e.mu.Unlock()
		if !clean {
			t.Fatal("zero-CID idle cleanup retained routes or connection quota")
		}
		e.handleQUICPacket(keys[0], initial("dest-000", ""), time.Time{})
		if len(*created) != 4 || (*created)[3].addr.Generation == (*created)[0].addr.Generation {
			t.Fatal("reused tuple did not get a fresh generation after cleanup")
		}
	})
}

func TestLateProcessAttributionDoesNotSplitTCPOrCrossGenerations(t *testing.T) {
	withRoutingDecryptor(t, "tcp", func(e *DecryptorEngine, created *[]*routingDecryptor) {
		ip := transport.NewIPv6Adapter(&layers.IPv6{SrcIP: net.ParseIP("::1"), DstIP: net.ParseIP("::1")})
		tcp := func(seq uint32, syn bool) *transport.TCPAdapter {
			return transport.NewTCPAdapter(&layers.TCP{SrcPort: 45001, DstPort: 443, Seq: seq, SYN: syn})
		}
		e.handlePacket(ip, tcp(100, true), time.Now())
		first := (*created)[0].addr
		if pid, _ := first.Process.Identity("request"); pid != 0 {
			t.Fatal("invented first packet PID")
		}
		observation := &types.ConnectionProcess{}
		observation.Observe(101, "client", 1)
		e.handlePacket(ip, tcp(101, false), time.Now(), observation)
		server := &types.ConnectionProcess{}
		server.Observe(202, "server", 1)
		e.handlePacket(ip, transport.NewTCPAdapter(&layers.TCP{SrcPort: 443, DstPort: 45001, Seq: 900, ACK: true}), time.Now(), server)
		if len(*created) != 1 || first.String() != (*created)[0].addr.String() {
			t.Fatal("metadata changed route identity")
		}
		for dir, want := range map[string]int64{"request": 101, "response": 202} {
			p := types.NewDecryptedPacket("tcp", "tls", dir, nil, time.Now(), first)
			if p.PID != want {
				t.Fatalf("%s ownership=%d", dir, p.PID)
			}
		}
		e.handlePacket(ip, tcp(200, true), time.Now())
		if len(*created) != 2 {
			t.Fatal("new SYN did not create generation")
		}
		if pid, _ := (*created)[1].addr.Process.Identity("request"); pid != 0 {
			t.Fatal("process leaked across reuse")
		}
		conflict := &types.ConnectionProcess{}
		conflict.Observe(999, "other", 1)
		first.Process.Merge(conflict, false)
		if pid, _ := first.Process.Identity("request"); pid != 0 {
			t.Fatal("ambiguous shared endpoint attributed")
		}
		legacy := e.factory.Create(types.ConnectionKey{Proto: "tcp", Pid: 303, ProcessName: "explicit"})
		packet := types.NewDecryptedPacket("tcp", "tls", "request", nil, time.Now(), legacy.GetAddr())
		if packet.PID != 303 || packet.PName != "explicit" {
			t.Fatal("factory discarded explicit caller process metadata")
		}
	})
}
