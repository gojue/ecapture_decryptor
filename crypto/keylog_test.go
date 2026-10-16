package crypto

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestLoadFromReader(t *testing.T) {
	cr := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	secret := "aabbccddeeff00112233445566778899aabbcc"
	content := strings.Join([]string{
		"# this is a comment and should be ignored",
		"CLIENT_RANDOM " + cr + " " + secret,
		"CLIENT_TRAFFIC_SECRET_0 " + cr + " " + secret,
		"QUIC_CLIENT_TRAFFIC_SECRET_0 " + cr + " " + secret,
	}, "\n")

	kl, err := NewKeyLogStoreFromReader(strings.NewReader(content))
	if err != nil {
		t.Fatalf("NewKeyLogStoreFromReader error: %v", err)
	}

	crBytes, err := hex.DecodeString(cr)
	if err != nil {
		t.Fatalf("failed to decode client random: %v", err)
	}

	s := kl.GetSecrets(crBytes)
	if s == nil {
		t.Fatalf("expected secrets for client random, got nil")
	}

	if len(s.MasterSecret) == 0 {
		t.Errorf("expected MasterSecret to be set for CLIENT_RANDOM")
	}
	if len(s.ClientTrafficSecret) == 0 {
		t.Errorf("expected ClientTrafficSecret to be set for CLIENT_TRAFFIC_SECRET_0")
	}
}

func TestWriteStreaming(t *testing.T) {
	kl := NewKeyLogStore()

	cr := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	secret := "cafebabecafebabecafebabecafe"
	line := "CLIENT_HANDSHAKE_TRAFFIC_SECRET " + cr + " " + secret + "\n"

	// write first half
	half := len(line) / 2
	if _, err := kl.Write([]byte(line[:half])); err != nil {
		t.Fatalf("first write error: %v", err)
	}

	// should not be parsed yet
	crBytes, _ := hex.DecodeString(cr)
	if got := kl.GetSecrets(crBytes); got != nil {
		t.Fatalf("expected nil secrets before completing line, got: %+v", got)
	}

	// write the rest
	if _, err := kl.Write([]byte(line[half:])); err != nil {
		t.Fatalf("second write error: %v", err)
	}

	// now it should be parsed
	got := kl.GetSecrets(crBytes)
	if got == nil {
		t.Fatalf("expected secrets after complete line, got nil")
	}
	if len(got.ClientHandshakeTrafficSecret) == 0 {
		t.Errorf("expected ClientHandshakeTrafficSecret to be set after streaming write")
	}
}

func TestWaitForSecretsLateAndMissing(t *testing.T) {
	store := NewKeyLogStore()
	random := []byte{1, 2, 3, 4}
	ready := func(secrets *TLSSecrets) bool { return secrets != nil && len(secrets.MasterSecret) > 0 }
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := store.WaitForSecrets(random, ready, stop, time.Second)
		done <- err
	}()
	store.AddSecret("CLIENT_RANDOM", hex.EncodeToString(random), []byte{5, 6})
	if err := <-done; err != nil {
		t.Fatalf("late secret not observed: %v", err)
	}
	if _, err := store.WaitForSecrets([]byte{9}, ready, stop, time.Millisecond); err == nil {
		t.Fatal("missing secret did not time out")
	}
	close(stop)
	if _, err := store.WaitForSecrets([]byte{9}, ready, stop, time.Second); err == nil {
		t.Fatal("closed connection did not interrupt missing-secret wait")
	}
}
