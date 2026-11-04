// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package crypto

import (
	"bytes"
	"testing"
)

func TestStreamBufferClosePreservesDrainAndDiscardReleases(t *testing.T) {
	stream := NewStreamBuffer()
	record := []byte{0x17, 3, 3, 0, 3, 1, 2, 3}
	if err := stream.Write(record); err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()
	if got := stream.TryReadRecord(); !bytes.Equal(got, record) {
		t.Fatal("Close discarded the record before final draining")
	}
	stream.Discard()
	if stream.Len() != 0 || stream.buf.Cap() != 0 {
		t.Fatal("Discard retained input storage")
	}
}
