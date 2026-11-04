package crypto

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestKeyLogUpdatesBroadcastAndResubscribe(t *testing.T) {
	store := NewKeyLogStore()
	first, second := store.Updates(), store.Updates()
	select {
	case <-first:
		t.Fatal("new subscription was already notified")
	default:
	}
	random := []byte{1, 2, 3, 4}
	store.AddSecret("CLIENT_TRAFFIC_SECRET_0", hex.EncodeToString(random), []byte{5, 6})
	for _, updates := range []<-chan struct{}{first, second} {
		select {
		case <-updates:
		default:
			t.Fatal("secret addition did not notify every subscriber")
		}
	}

	// Subscribe before reading. An addition between that read and the next wait
	// must close this generation instead of requiring a further secret update.
	next := store.Updates()
	secrets := store.GetSecrets(random)
	if secrets == nil || !bytes.Equal(secrets.ClientTrafficSecret, []byte{5, 6}) {
		t.Fatal("notified secret was not available")
	}
	select {
	case <-next:
		t.Fatal("resubscription reused a completed notification")
	default:
	}
	store.AddSecret("SERVER_TRAFFIC_SECRET_0", hex.EncodeToString(random), []byte{7, 8})
	select {
	case <-next:
	default:
		t.Fatal("secret added between read and wait was missed")
	}
	if got := store.GetSecrets(random); got == nil || !bytes.Equal(got.ServerTrafficSecret, []byte{7, 8}) {
		t.Fatal("second notification did not publish the server secret")
	}
}

func TestKeyLogUpdatesWaitForCompleteStreamingLine(t *testing.T) {
	store := NewKeyLogStore()
	updates := store.Updates()
	if _, err := store.Write([]byte("CLIENT_TRAFFIC_SECRET_0 01020304 0506")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-updates:
		t.Fatal("partial keylog line notified subscribers before a secret was available")
	default:
	}
	if _, err := store.Write([]byte("\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-updates:
	default:
		t.Fatal("completing a keylog line did not notify subscribers")
	}
	if got := store.GetSecrets([]byte{1, 2, 3, 4}); got == nil || !bytes.Equal(got.ClientTrafficSecret, []byte{5, 6}) {
		t.Fatal("streaming notification did not publish the complete secret")
	}
}

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
