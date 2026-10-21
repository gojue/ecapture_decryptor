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
	addr    types.ConnectionKey
	mu      sync.Mutex
	client  [][]byte
	server  [][]byte
	closed  chan struct{}
	closeMu sync.Once
}

func (d *routingDecryptor) Decrypt() error               { <-d.closed; return nil }
func (d *routingDecryptor) SetPacketTime(time.Time)      {}
func (d *routingDecryptor) CloseClient() error           { return nil }
func (d *routingDecryptor) CloseServer() error           { return nil }
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
