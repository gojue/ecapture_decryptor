// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package crypto

import (
	"bytes"
	"errors"
	"testing"
	"testing/synctest"
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

func TestStreamBufferWaitingReadDrainsConcurrentWriteAndClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for i := 0; i < 128; i++ {
			stream := NewStreamBuffer()
			record := []byte{22, 3, 3, 0, 3, 1, 2, 3}
			done := make(chan error, 1)
			go func() {
				got, err := stream.ReadRecord()
				if err == nil && !bytes.Equal(got, record) {
					err = errors.New("incorrect final record")
				}
				done <- err
			}()
			synctest.Wait()
			if err := stream.Write(record); err != nil {
				t.Fatal(err)
			}
			_ = stream.Close()
			if err := <-done; err != nil {
				t.Fatalf("iteration %d lost final record: %v", i, err)
			}
		}
	})
}
