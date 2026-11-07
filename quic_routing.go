// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package ecapture_decryptor

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/gojue/ecapture_decryptor/transport"
	"github.com/gojue/ecapture_decryptor/types"
)

const (
	maxQUICRoutePackets = 64 << 10
	maxQUICRouteBytes   = 32 << 20
	maxQUICTupleAliases = 8
)

type quicTuple struct{ forward, reverse string }
type quicRoute struct {
	key           string
	decryptor     types.Decryptor
	cids          [2]map[string]bool // IDs issued by client / server, including Initial routing IDs.
	zero          [2]bool
	aliases       []quicTuple
	initialSource string
	initialDCID   string
}
type quicBinding struct {
	route   *quicRoute
	reverse bool
}
type quicUnrouted struct {
	key        types.ConnectionKey
	data       []byte
	at, queued time.Time
	order      uint64
}
type quicRouter struct {
	routes  map[string]*quicRoute
	cids    map[string]map[quicBinding]bool
	pending []quicUnrouted
	bytes   int
	order   uint64
}

func (e *DecryptorEngine) quicRouteFailure(key types.ConnectionKey, code string) {
	e.factory.options.Report(key, "input", code)
	e.recordConnectionError(fmt.Errorf("QUIC routing: %s", code))
}

// e.mu protects all router state; no feeds, closes, or user callbacks run under it.
func (e *DecryptorEngine) addQUICCIDLocked(route *quicRoute, cid []byte, ownerClient, retire bool) error {
	dir := 1
	if ownerClient {
		dir = 0
	}
	id := string(cid)
	if id == "" {
		if !retire {
			route.zero[dir] = true
		}
		return nil
	}
	binding := quicBinding{route: route, reverse: ownerClient}
	if retire {
		delete(route.cids[dir], id)
		delete(e.quic.cids[id], binding)
		if len(e.quic.cids[id]) == 0 {
			delete(e.quic.cids, id)
		}
		// Non-original tuple aliases are only hints; discard them on CID retirement.
		if len(route.aliases) > 1 {
			route.aliases = route.aliases[:1]
		}
		return nil
	}
	if route.cids[dir][id] {
		return nil
	}
	// Sequence-numbered IDs plus the original and Retry routing IDs.
	if len(route.cids[dir]) >= 66 {
		return errors.New("QUIC routing CID limit exceeded")
	}
	route.cids[dir][id] = true
	if e.quic.cids[id] == nil {
		e.quic.cids[id] = make(map[quicBinding]bool)
	}
	e.quic.cids[id][binding] = true
	return nil
}

func (e *DecryptorEngine) removeQUICRouteLocked(key string) {
	if e.quic == nil {
		return
	}
	route := e.quic.routes[key]
	if route == nil {
		return
	}
	for dir, ids := range route.cids {
		for id := range ids {
			delete(e.quic.cids[id], quicBinding{route: route, reverse: dir == 0})
			if len(e.quic.cids[id]) == 0 {
				delete(e.quic.cids, id)
			}
		}
	}
	delete(e.quic.routes, key)
}

func (e *DecryptorEngine) matchQUICLocked(key types.ConnectionKey, data []byte, h transport.QUICHeaderInfo) (quicBinding, bool, bool) {
	matches := make(map[quicBinding]bool)
	add := func(id []byte) {
		for binding := range e.quic.cids[string(id)] {
			matches[binding] = true
		}
	}
	if h.Long {
		if len(h.DCID) > 0 {
			add(h.DCID)
		}
		if h.Type == transport.QUICPacketTypeInitial {
			// Distinct client SCIDs distinguish concurrent connections on one tuple.
			for binding := range matches {
				if !binding.reverse && !binding.route.cids[0][string(h.SCID)] && string(h.SCID) != binding.route.initialSource {
					delete(matches, binding)
				}
			}
			if len(matches) == 0 && len(h.SCID) > 0 {
				for binding := range e.quic.cids[string(h.SCID)] {
					binding.reverse = !binding.reverse
					matches[binding] = true
				}
			}
			if len(matches) == 0 && len(h.SCID) == 0 {
				// A zero SCID cannot link a client's later Initial to a CID in
				// an unread server flight. On its original tuple, authenticate
				// against the original Initial keys before selecting a route.
				for _, route := range e.quic.routes {
					if route.zero[0] && key.String() == route.aliases[0].forward &&
						transport.IsQUICClientInitial(data, []byte(route.initialDCID)) {
						matches[quicBinding{route: route}] = true
					}
				}
			}
		}
	} else {
		for size := 1; size <= 20 && size < len(data); size++ {
			add(data[1 : 1+size])
		}
	}
	if !h.Long || len(h.DCID) == 0 {
		// Zero-length CIDs cannot identify a migrated connection. Only a unique
		// original tuple and the direction with a zero CID are eligible.
		tuple := key.String()
		for _, route := range e.quic.routes {
			original := route.aliases[0]
			if route.zero[1] && tuple == original.forward && (!h.Long || h.Type != transport.QUICPacketTypeInitial || string(h.SCID) == route.initialSource) {
				matches[quicBinding{route: route}] = true
			}
			if route.zero[0] && tuple == original.reverse {
				matches[quicBinding{route: route, reverse: true}] = true
			}
		}
	}
	if len(matches) != 1 {
		return quicBinding{}, false, len(matches) > 1
	}
	for binding := range matches {
		return binding, true, false
	}
	return quicBinding{}, false, false
}

func (e *DecryptorEngine) noteQUICTupleLocked(binding quicBinding, key types.ConnectionKey) {
	key.Generation = 0
	if binding.reverse {
		key = key.Reverse()
	}
	alias := quicTuple{key.String(), key.Reverse().String()}
	for _, old := range binding.route.aliases {
		if old == alias {
			return
		}
	}
	// Keep the original tuple for zero-CID routing and a bounded recent history.
	if len(binding.route.aliases) == maxQUICTupleAliases {
		copy(binding.route.aliases[1:], binding.route.aliases[2:])
		binding.route.aliases = binding.route.aliases[:maxQUICTupleAliases-1]
	}
	binding.route.aliases = append(binding.route.aliases, alias)
}

func (e *DecryptorEngine) quicCIDUpdate(route *quicRoute, cid []byte, ownerClient, retire bool) ([]transport.QUICRoutedPacket, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.quic.routes[route.key] != route {
		return nil, nil
	} // Already retired/expired.
	if err := e.addQUICCIDLocked(route, cid, ownerClient, retire); err != nil {
		return nil, err
	}
	if retire {
		return nil, nil
	}
	var ready []transport.QUICRoutedPacket
	pending := e.quic.pending
	e.quic.pending = nil
	e.quic.bytes = 0
	for _, item := range pending {
		h, err := transport.InspectQUICHeader(item.data)
		if err == nil {
			binding, ok, _ := e.matchQUICLocked(item.key, item.data, h)
			if ok && binding.route == route {
				binding.route.decryptor.GetAddr().Process.Merge(item.key.Process, binding.reverse)
				e.noteQUICTupleLocked(binding, item.key)
				ready = append(ready, transport.QUICRoutedPacket{Data: item.data, IsClient: !binding.reverse, Time: item.at, Order: item.order})
				e.lastActivity[route.key] = time.Now()
				continue
			}
		}
		e.quic.pending = append(e.quic.pending, item)
		e.quic.bytes += len(item.data)
	}
	return ready, nil
}

func (e *DecryptorEngine) handleQUICPacket(key types.ConnectionKey, data []byte, at time.Time) {
	h, err := transport.InspectQUICHeader(data)
	if err != nil {
		e.quicRouteFailure(key, "invalid_packet")
		return
	}
	e.mu.Lock()
	if e.quic == nil {
		e.quic = &quicRouter{routes: make(map[string]*quicRoute), cids: make(map[string]map[quicBinding]bool)}
	}
	e.quic.order++
	order := e.quic.order
	binding, found, ambiguous := e.matchQUICLocked(key, data, h)
	if ambiguous {
		e.mu.Unlock()
		e.quicRouteFailure(key, "ambiguous_connection_id")
		return
	}
	newInitial := !found && h.Long && h.Type == transport.QUICPacketTypeInitial
	if newInitial && len(h.SCID) == 0 {
		for _, route := range e.quic.routes {
			if route.zero[0] && key.String() == route.aliases[0].forward {
				// A client Initial can already use a CID announced in a server
				// flight that the worker has not authenticated yet. An empty SCID
				// cannot link it back to that connection. Only create a new route
				// if its own DCID authenticates it; otherwise use the bounded
				// pending queue until the worker publishes the peer CID.
				newInitial = transport.IsQUICClientInitial(data, h.DCID)
				break
			}
		}
	}
	if newInitial {
		if e.active >= e.factory.options.ConnectionLimit() {
			e.mu.Unlock()
			if !e.limitReported {
				e.limitReported = true
				e.quicRouteFailure(key, "connection_limit")
			}
			return
		}
		e.nextGeneration++
		key.Generation = e.nextGeneration
		e.mu.Unlock()
		dec := e.factory.Create(key)
		if dec == nil {
			return
		}
		original := key
		original.Generation = 0
		route := &quicRoute{key: key.String(), decryptor: dec, initialSource: string(h.SCID), initialDCID: string(h.DCID), aliases: []quicTuple{{original.String(), original.Reverse().String()}}}
		route.cids = [2]map[string]bool{make(map[string]bool), make(map[string]bool)}
		e.mu.Lock()
		e.quic.routes[route.key] = route
		_ = e.addQUICCIDLocked(route, h.SCID, true, false)
		_ = e.addQUICCIDLocked(route, h.DCID, false, false)
		e.conntrack[route.key] = dec
		if e.lastActivity == nil {
			e.lastActivity = make(map[string]time.Time)
		}
		e.lastActivity[route.key] = time.Now()
		e.active++
		e.connections.Add(1)
		e.mu.Unlock()
		if q, ok := dec.(*transport.QUICDecryptor); ok {
			q.SetConnectionIDHandler(func(cid []byte, ownerClient, retire bool) ([]transport.QUICRoutedPacket, error) {
				return e.quicCIDUpdate(route, cid, ownerClient, retire)
			})
		}
		go func() {
			defer e.connections.Done()
			if err := dec.Decrypt(); err != nil {
				e.recordConnectionError(fmt.Errorf("decrypt QUIC connection %s: %w", dec.GetAddr(), err))
			}
			e.mu.Lock()
			e.removeQUICRouteLocked(route.key)
			delete(e.conntrack, route.key)
			delete(e.lastActivity, route.key)
			e.active--
			e.mu.Unlock()
		}()
		binding = quicBinding{route: route}
		found = true
		e.mu.Lock()
	}
	if !found {
		if len(e.quic.routes) == 0 {
			e.mu.Unlock()
			if e.missingStarts < 16 {
				e.missingStarts++
				e.factory.options.Report(key, "handshake", "missing_connection_start")
			}
			return
		}
		if len(e.quic.pending) >= maxQUICRoutePackets || len(data) > maxQUICRouteBytes-e.quic.bytes {
			e.mu.Unlock()
			e.quicRouteFailure(key, "resource_limit")
			return
		}
		e.quic.pending = append(e.quic.pending, quicUnrouted{key: key, data: bytes.Clone(data), at: at, queued: time.Now(), order: order})
		e.quic.bytes += len(data)
		e.mu.Unlock()
		return
	}
	e.lastActivity[binding.route.key] = time.Now()
	e.noteQUICTupleLocked(binding, key)
	e.mu.Unlock()
	dec := binding.route.decryptor
	dec.GetAddr().Process.Merge(key.Process, binding.reverse)
	if q, ok := dec.(*transport.QUICDecryptor); ok {
		err = q.FeedQUICPacket(transport.QUICRoutedPacket{Data: data, IsClient: !binding.reverse, Time: at, Order: order})
	} else {
		dec.SetPacketTime(at)
		if binding.reverse {
			err = dec.FeedServer(data)
		} else {
			err = dec.FeedClient(data)
		}
	}
	if err != nil {
		e.recordConnectionError(err)
		_ = dec.Close()
	}
}

func (e *DecryptorEngine) expireQUICPending(now time.Time, all bool) {
	e.mu.Lock()
	var expired bool
	if e.quic != nil {
		pending := e.quic.pending
		e.quic.pending = nil
		e.quic.bytes = 0
		for _, item := range pending {
			if all || now.Sub(item.queued) >= e.factory.options.SecretWaitTimeout() {
				expired = true
				continue
			}
			e.quic.pending = append(e.quic.pending, item)
			e.quic.bytes += len(item.data)
		}
	}
	e.mu.Unlock()
	if expired {
		e.quicRouteFailure(types.ConnectionKey{Proto: types.TransportProtocolUDP}, "unknown_connection_id")
	}
}
