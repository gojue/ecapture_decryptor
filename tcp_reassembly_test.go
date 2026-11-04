// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package ecapture_decryptor

import (
	"bytes"
	"testing"
)

func TestTCPDirectionPendingSegmentLimit(t *testing.T) {
	var direction tcpDirection
	direction.Start(1)
	// Keep the unrelated fragments beyond the small gap closed below, avoiding
	// quadratic draining of the entire quota in this boundary test.
	for i := range maxOutOfOrderSegments - 1 {
		direction.pending[1000+uint32(i)*2] = []byte{'x'}
	}
	direction.pendingBytes = maxOutOfOrderSegments - 1
	if ready, err := direction.Push(3, []byte("c")); err != nil || len(ready) != 0 {
		t.Fatalf("last available segment slot: ready=%q err=%v", ready, err)
	}
	if len(direction.pending) != maxOutOfOrderSegments || direction.pendingBytes != maxOutOfOrderSegments {
		t.Fatal("segment boundary did not preserve pending accounting")
	}
	if ready, err := direction.Push(4, []byte("d")); err == nil || len(ready) != 0 {
		t.Fatalf("new segment beyond limit: ready=%q err=%v", ready, err)
	}
	if len(direction.pending) != maxOutOfOrderSegments || direction.pendingBytes != maxOutOfOrderSegments {
		t.Fatal("rejected segment changed pending state")
	}
	if ready, err := direction.Push(3, []byte("cd")); err != nil || len(ready) != 0 {
		t.Fatalf("replacement at full segment quota: ready=%q err=%v", ready, err)
	}
	if _, err := direction.Push(3, []byte("c")); err != nil {
		t.Fatalf("shorter duplicate at full segment quota: %v", err)
	}
	if len(direction.pending) != maxOutOfOrderSegments || direction.pendingBytes != maxOutOfOrderSegments+1 {
		t.Fatal("replacement/duplicate changed the segment count or lost byte accounting")
	}
	ready, err := direction.Push(1, []byte("ab"))
	if err != nil || !bytes.Equal(bytes.Join(ready, nil), []byte("abcd")) {
		t.Fatalf("closing the gap: ready=%q err=%v", ready, err)
	}
	if len(direction.pending) != maxOutOfOrderSegments-1 || direction.pendingBytes != maxOutOfOrderSegments-1 {
		t.Fatal("draining the replacement did not release its slot and bytes")
	}
	if ready, err := direction.Push(7, []byte("g")); err != nil || len(ready) != 0 || len(direction.pending) != maxOutOfOrderSegments {
		t.Fatalf("reusing released capacity: ready=%q err=%v count=%d", ready, err, len(direction.pending))
	}
}
