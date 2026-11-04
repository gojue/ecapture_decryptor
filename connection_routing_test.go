package ecapture_decryptor

import (
	"bytes"
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
		e.handleQUICPacket(key, []byte{0xc0, 0, 0, 0, 1, 1, 9, 0}, time.Time{})
		if len(*created) != 2 {
			t.Fatal("distinct Initial did not create a second route")
		}
		e.handleQUICPacket(key.Reverse(), data, time.Time{})
		if len(first.server) != 1 || len((*created)[1].server) != 0 {
			t.Fatal("zero CID ambiguous tuple guessed a connection")
		}
		e.expireQUICPending(time.Now().Add(time.Minute), false)
		if len(e.quic.pending) != 0 {
			t.Fatal("unknown-CID waiting deadline not bounded")
		}
	})
}
