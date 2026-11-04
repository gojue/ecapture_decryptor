package ecapture_decryptor

import (
	"errors"
	"time"

	"github.com/gojue/ecapture_decryptor/types"
)

// One reaper per engine also runs while its pcap reader is blocked. Close runs
// outside the routing lock: draining a connection must not lock out completion.
func (e *DecryptorEngine) startIdleReaper() func() {
	stop, done := make(chan struct{}), make(chan struct{})
	timeout := e.factory.options.ConnectionIdleTimeout()
	interval := timeout / 2
	if interval < time.Nanosecond {
		interval = time.Nanosecond
	}
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case now := <-ticker.C:
				e.expireIdleConnections(now, timeout)
			case <-stop:
				return
			}
		}
	}()
	return func() { close(stop); <-done }
}

func (e *DecryptorEngine) expireIdleConnections(now time.Time, timeout time.Duration) {
	var expired []types.Decryptor
	e.mu.Lock()
	if e.draining {
		e.mu.Unlock()
		return
	}
	for key, last := range e.lastActivity {
		if now.Sub(last) < timeout {
			continue
		}
		if connection := e.conntrack[key]; connection != nil {
			expired = append(expired, connection)
		}
		delete(e.conntrack, key)
		delete(e.tcpFlows, key)
		delete(e.lastActivity, key)
	}
	e.mu.Unlock()
	for _, connection := range expired {
		e.factory.options.Report(connection.GetAddr(), "input", "idle_timeout")
		e.recordConnectionError(errors.New("connection idle timeout"))
		_ = connection.Close()
	}
}
