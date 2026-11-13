package ecapture_decryptor

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gojue/ecapture_decryptor/crypto"
	"github.com/gojue/ecapture_decryptor/transport"
	"github.com/gojue/ecapture_decryptor/types"
	"github.com/google/gopacket/layers"
)

func lifecyclePacket(port uint16, syn, rst bool) *transport.TCPAdapter {
	return transport.NewTCPAdapter(&layers.TCP{SrcPort: layers.TCPPort(port), DstPort: 443, Seq: 100, SYN: syn, RST: rst})
}

func lifecycleIP() *transport.IPv4Adapter {
	return transport.NewIPv4Adapter(&layers.IPv4{SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2)})
}

func TestConnectionLimitReleasesCapacityAfterCompletion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		withRoutingDecryptor(t, types.TransportProtocolTCP, func(engine *DecryptorEngine, created *[]*routingDecryptor) {
			var diagnostics []types.Diagnostic
			engine.factory.options = types.DecryptOptions{MaxConnections: 1, OnDiagnostic: func(d types.Diagnostic) {
				diagnostics = append(diagnostics, d)
			}}
			engine.handlePacket(lifecycleIP(), lifecyclePacket(41000, true, false), time.Time{})
			finish := make(chan struct{})
			release := sync.OnceFunc(func() { close(finish) })
			defer release() // Unblock the helper's cleanup even if an assertion fails.
			(*created)[0].finish = finish
			engine.handlePacket(lifecycleIP(), lifecyclePacket(41001, true, false), time.Time{})
			if len(*created) != 1 || engine.active != 1 || len(diagnostics) != 1 || diagnostics[0].Code != "connection_limit" || engine.connectionError() == nil {
				t.Fatal("connection admission did not enforce and report its limit")
			}
			// Explicitly hold the worker after Close; synctest does not prevent
			// runnable goroutines from finishing before the next assertion.
			_ = (*created)[0].Close()
			synctest.Wait()
			engine.handlePacket(lifecycleIP(), lifecyclePacket(41001, true, false), time.Time{})
			if len(*created) != 1 || engine.active != 1 || len(diagnostics) != 1 {
				t.Fatal("closing connection released capacity early or repeated diagnostics")
			}
			release()
			synctest.Wait()
			if engine.active != 0 || len(engine.conntrack) != 0 || len(engine.tcpFlows) != 0 || len(engine.lastActivity) != 0 {
				t.Fatal("finished connection retained routing or admission state")
			}
			engine.handlePacket(lifecycleIP(), lifecyclePacket(41001, true, false), time.Time{})
			if len(*created) != 2 {
				t.Fatal("connection capacity was not reusable after completion")
			}
		})
	})
}

func TestIdleReaperKeepsActiveConnectionsAndReleasesIdleOnes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		withRoutingDecryptor(t, types.TransportProtocolTCP, func(engine *DecryptorEngine, created *[]*routingDecryptor) {
			var diagnostics []types.Diagnostic
			engine.factory.options = types.DecryptOptions{IdleTimeout: 2 * time.Second, OnDiagnostic: func(d types.Diagnostic) {
				diagnostics = append(diagnostics, d)
			}}
			stop := engine.startIdleReaper()
			defer stop()
			// Capture dates do not advance a wall-clock resource deadline.
			engine.handlePacket(lifecycleIP(), lifecyclePacket(41000, true, false), time.Unix(1, 0))
			engine.handlePacket(lifecycleIP(), lifecyclePacket(41001, true, false), time.Unix(1<<40, 0))
			time.Sleep(time.Second)
			engine.handlePacket(lifecycleIP(), lifecyclePacket(41001, false, false), time.Unix(1, 0))
			time.Sleep(time.Second)
			synctest.Wait()
			select {
			case <-(*created)[0].closed:
			default:
				t.Fatal("idle connection survived its wall-clock deadline")
			}
			select {
			case <-(*created)[1].closed:
				t.Fatal("recently active connection was reclaimed")
			default:
			}
			if engine.active != 1 || len(engine.conntrack) != 1 || len(engine.tcpFlows) != 1 || len(engine.lastActivity) != 1 ||
				len(diagnostics) != 1 || diagnostics[0].Code != "idle_timeout" || engine.connectionError() == nil {
				t.Fatal("idle cleanup lost active routing or failed to report retirement")
			}
		})
	})
}

func TestTCPResetClosesBothDirections(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options types.DecryptOptions
	}{
		{"default", types.DecryptOptions{}},
		{"http_events", types.DecryptOptions{HTTPEvents: true}},
		{"doh", types.DecryptOptions{ApplicationProtocol: "doh"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				withRoutingDecryptor(t, types.TransportProtocolTCP, func(engine *DecryptorEngine, created *[]*routingDecryptor) {
					engine.factory.options = tc.options
					engine.handlePacket(lifecycleIP(), lifecyclePacket(41000, true, false), time.Time{})
					engine.handlePacket(lifecycleIP(), lifecyclePacket(41000, false, true), time.Time{})
					synctest.Wait()
					if engine.active != 0 || len(engine.conntrack) != 0 {
						t.Fatal("TCP reset left one direction or its connection worker open")
					}
					if !(*created)[0].resetObserved {
						t.Fatal("TCP reset was not distinguished from normal EOF")
					}
				})
			})
		})
	}
}

type lockingCloseDecryptor struct {
	*routingDecryptor
	engine *DecryptorEngine
}

func (d *lockingCloseDecryptor) Close() error {
	// Re-enter the routing lock during Close to detect callers holding it.
	d.engine.mu.Lock()
	defer d.engine.mu.Unlock()
	return d.routingDecryptor.Close()
}

func TestCloseAllConnectionsDoesNotHoldRoutingLock(t *testing.T) {
	engine := &DecryptorEngine{conntrack: make(map[string]types.Decryptor)}
	connection := &lockingCloseDecryptor{routingDecryptor: &routingDecryptor{closed: make(chan struct{})}, engine: engine}
	engine.conntrack["test"] = connection
	done := make(chan struct{})
	go func() { engine.closeAllConnections(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close was called while holding the engine routing lock")
	}
}

type slowCloseDecryptor struct{ *routingDecryptor }

func (d *slowCloseDecryptor) Close() error {
	time.Sleep(3 * time.Second) // Model an output consumer draining buffered data.
	return d.routingDecryptor.Close()
}

func TestEOFDrainDoesNotTriggerIdleTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logger := log.New(io.Discard, "", 0)
		var diagnostics []types.Diagnostic
		engine := &DecryptorEngine{
			logger: logger, factory: NewDecryptorFactory(nil, logger, nil),
			conntrack: map[string]types.Decryptor{
				"test": &slowCloseDecryptor{&routingDecryptor{closed: make(chan struct{})}},
			},
			lastActivity: map[string]time.Time{"test": time.Now()},
		}
		engine.factory.options = types.DecryptOptions{IdleTimeout: 2 * time.Second, OnDiagnostic: func(d types.Diagnostic) {
			diagnostics = append(diagnostics, d)
		}}
		stop := engine.startIdleReaper()
		engine.waitForAllConnections()
		stop()
		if len(diagnostics) != 0 || engine.connectionError() != nil {
			t.Fatal("normal EOF drain was misreported as an idle timeout")
		}
	})
}

func TestDTLSRoutingLimitAndIdleLifecycle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		withRoutingDecryptor(t, types.TransportProtocolUDP, func(engine *DecryptorEngine, created *[]*routingDecryptor) {
			var diagnostics []types.Diagnostic
			engine.factory.options = types.DecryptOptions{UDPProtocol: "dtls", MaxConnections: 1, IdleTimeout: 2 * time.Second, OnDiagnostic: func(d types.Diagnostic) { diagnostics = append(diagnostics, d) }}
			packet := func(port uint16, reverse bool, payload string) *transport.UDPAdapter {
				src, dst := port, uint16(44463)
				if reverse {
					src, dst = dst, src
				}
				return transport.NewUDPAdapter(&layers.UDP{SrcPort: layers.UDPPort(src), DstPort: layers.UDPPort(dst), BaseLayer: layers.BaseLayer{Payload: []byte(payload)}})
			}
			reverseIP := transport.NewIPv4Adapter(&layers.IPv4{SrcIP: net.IPv4(192, 0, 2, 2), DstIP: net.IPv4(192, 0, 2, 1)})
			// Arbitrary bytes reach the explicitly selected DTLS worker, never the
			// QUIC header/CID router. Payload validation belongs to that worker.
			engine.handlePacket(lifecycleIP(), packet(41000, false, "first"), time.Unix(1, 0))
			engine.handlePacket(reverseIP, packet(41000, true, "reply"), time.Unix(1<<40, 0))
			engine.handlePacket(lifecycleIP(), packet(41001, false, "limited"), time.Time{})
			if len(*created) != 1 || engine.active != 1 || len((*created)[0].client) != 1 || len((*created)[0].server) != 1 || len(diagnostics) != 1 || diagnostics[0].Code != "connection_limit" || len(engine.tcpFlows) != 0 {
				t.Fatal("DTLS routing/admission failed")
			}
			finish := make(chan struct{})
			release := sync.OnceFunc(func() { close(finish) })
			defer release()
			(*created)[0].finish = finish
			time.Sleep(time.Second)
			engine.handlePacket(reverseIP, packet(41000, true, "active"), time.Unix(1, 0))
			time.Sleep(time.Second)
			engine.expireIdleConnections(time.Now(), 2*time.Second)
			select {
			case <-(*created)[0].closed:
				t.Fatal("active DTLS association retired")
			default:
			}
			time.Sleep(time.Second)
			engine.expireIdleConnections(time.Now(), 2*time.Second)
			synctest.Wait()
			if len(engine.conntrack) != 0 || len(engine.lastActivity) != 0 || engine.active != 1 || len(diagnostics) != 2 || diagnostics[1].Code != "idle_timeout" {
				t.Fatal("idle DTLS route or closing capacity leaked")
			}
			engine.handlePacket(lifecycleIP(), packet(41001, false, "still limited"), time.Time{})
			if len(*created) != 1 {
				t.Fatal("closing worker released admission early")
			}
			release()
			synctest.Wait()
			engine.handlePacket(lifecycleIP(), packet(41001, false, "reusable"), time.Time{})
			if len(*created) != 2 || engine.active != 1 || (*created)[0].addr.Generation == (*created)[1].addr.Generation {
				t.Fatal("DTLS capacity not reusable")
			}
		})
	})
}

func TestStreamingKeyReferencesReleasedByEngineLifecycle(t *testing.T) {
	for _, mode := range []string{"idle", "handshake_failure", "eof"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				store := crypto.NewStreamingKeyLogStore(time.Minute)
				logger := log.New(io.Discard, "", 0)
				packets := make(chan *types.DecryptedPacket, 16)
				engine := &DecryptorEngine{keyLog: store, logger: logger, conntrack: make(map[string]types.Decryptor), tcpFlows: make(map[string]*tcpConnection)}
				engine.factory = NewDecryptorFactory(store, logger, packets)
				engine.factory.options = types.DecryptOptions{RawChunks: true, IdleTimeout: time.Second, KeyWaitTimeout: time.Second}
				stop := engine.startIdleReaper()
				defer stop()
				defer engine.waitForAllConnections()
				random, secret := bytes.Repeat([]byte{0x42}, 32), bytes.Repeat([]byte{0x31}, 32)
				if _, err := store.Write([]byte(fmt.Sprintf("CLIENT_TRAFFIC_SECRET_0 %x %x\nSERVER_TRAFFIC_SECRET_0 %x %x\n", random, secret, random, secret))); err != nil {
					t.Fatal(err)
				}
				engine.handlePacket(lifecycleIP(), lifecyclePacket(41000, true, false), time.Time{})
				client, server := keyLogStreamHellos(random)
				payload := append(client, keyLogStreamRecord(t, secret, 0)...)
				tcp := lifecyclePacket(41000, false, false)
				tcp.Seq = 101
				tcp.Payload = payload
				engine.handlePacket(lifecycleIP(), tcp, time.Time{})
				if mode != "handshake_failure" {
					tcp = transport.NewTCPAdapter(&layers.TCP{SrcPort: 443, DstPort: 41000, Seq: 101, BaseLayer: layers.BaseLayer{Payload: server}})
					ip := transport.NewIPv4Adapter(&layers.IPv4{SrcIP: net.IPv4(192, 0, 2, 2), DstIP: net.IPv4(192, 0, 2, 1)})
					engine.handlePacket(ip, tcp, time.Time{})
				}
				synctest.Wait()
				if store.GetSecrets(random) == nil {
					t.Fatal("live connection lost its key")
				}
				if mode == "eof" {
					engine.waitForAllConnections()
				} else {
					time.Sleep(2 * time.Second)
					synctest.Wait()
				}
				if engine.active != 0 || len(engine.conntrack) != 0 || store.GetSecrets(random) != nil {
					t.Fatal("engine retirement retained routing, worker slot, or key")
				}
				if mode == "eof" && engine.connectionError() != nil {
					t.Fatal(engine.connectionError())
				}
				if mode != "eof" && !errors.Is(engine.connectionError(), ErrConnectionFailures) {
					t.Fatal("missing connection failure summary")
				}
			})
		})
	}
}

func TestCapturedProtocolWorkersReleaseStreamingKeyReferences(t *testing.T) {
	for _, tc := range []struct {
		name, capture string
		keys          []string
		options       types.DecryptOptions
	}{
		{"tls12", "d10_tls12_resume.pcapng", []string{"d10_openssl.keys"}, types.DecryptOptions{RawChunks: true}},
		{"quic", "http3_keyupdate_v1.pcapng", []string{"http3_keyupdate_v1.keys"}, types.DecryptOptions{RawChunks: true}},
		{"dtls", "d11_dtls_aes128.pcapng", []string{"d11_dtls.keys"}, types.DecryptOptions{UDPProtocol: "dtls"}},
		{"tls_upgrade", "d09_https_connect.pcapng", []string{"d09_upgrade.keys", "d09_inner.keys"}, types.DecryptOptions{TLSUpgrade: "https-connect", RawChunks: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := crypto.NewStreamingKeyLogStore(time.Minute)
			logger := log.New(io.Discard, "", 0)
			var keylog []byte
			var identities [][][]byte
			for _, path := range tc.keys {
				keys, err := os.ReadFile("test/testdata/" + path)
				if err != nil {
					t.Fatal(err)
				}
				keylog = append(keylog, keys...)
				var randoms [][]byte
				for _, line := range bytes.Split(keys, []byte{'\n'}) {
					f := bytes.Fields(line)
					if len(f) != 3 || string(f[0]) != "CLIENT_RANDOM" && string(f[0]) != "CLIENT_TRAFFIC_SECRET_0" {
						continue
					}
					random, err := hex.DecodeString(string(f[1]))
					if err == nil {
						randoms = append(randoms, random)
					}
				}
				if len(randoms) == 0 {
					t.Fatal("fixture has no supported key identities")
				}
				identities = append(identities, randoms)
			}
			capture, err := os.ReadFile("test/testdata/" + tc.capture)
			if err != nil {
				t.Fatal(err)
			}
			// Exercise normal EOF with a DSB after all captured packets. Only workers
			// that actually parsed the fixture can associate and retire these keys.
			input := append(capture, tlsFixtureDSB(t, keylog)...)
			blocks := &pcapngBlockReader{source: bytes.NewReader(input), onTLSSecrets: func(payload []byte) error { _, err := store.Write(payload); return err }}
			packets := make(chan *types.DecryptedPacket, 32)
			drained := make(chan int, 1)
			go func() {
				count := 0
				for p := range packets {
					if len(p.Data) > 0 {
						count++
					}
				}
				drained <- count
			}()
			engine := &DecryptorEngine{config: &DecryptorConfig{pcapReader: blocks, strictPcapng: true}, keyLog: store, logger: logger, conntrack: make(map[string]types.Decryptor), tcpFlows: make(map[string]*tcpConnection)}
			engine.factory = NewDecryptorFactory(store, logger, packets)
			engine.factory.options = tc.options
			err = engine.Run()
			close(packets)
			count := <-drained
			if err != nil || count == 0 {
				t.Fatalf("fixture failed: output=%d err=%v", count, err)
			}
			for i, randoms := range identities {
				removed := false
				for _, random := range randoms {
					removed = removed || store.GetSecrets(random) == nil
				}
				if !removed {
					t.Fatalf("worker retained every identity from %s", tc.keys[i])
				}
			}
			if engine.active != 0 || len(engine.conntrack) != 0 {
				t.Fatal("fixture worker remained active")
			}
		})
	}
}
