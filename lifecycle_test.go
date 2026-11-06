package ecapture_decryptor

import (
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

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
