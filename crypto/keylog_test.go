package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
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

func TestWaitForSecretsFinalUpdateAndEOF(t *testing.T) {
	// Exercise either select outcome when the last DSB and EOF become ready
	// after the initial snapshot. Neither outcome may lose the published key.
	for i := 0; i < 128; i++ {
		store := NewKeyLogStore()
		stop := make(chan struct{})
		first := true
		secrets, err := store.WaitForSecrets([]byte{1}, func(secrets *TLSSecrets) bool {
			if first {
				first = false
				store.AddSecret("CLIENT_RANDOM", "01", []byte{2})
				close(stop)
			}
			return secrets != nil && len(secrets.MasterSecret) != 0
		}, stop, time.Second)
		if err != nil || secrets == nil || !bytes.Equal(secrets.MasterSecret, []byte{2}) {
			t.Fatalf("final secret was lost at EOF: %v", err)
		}
	}
}

func TestKeyLogImportLineLimit(t *testing.T) {
	store := NewKeyLogStore()
	if n, err := store.Write(bytes.Repeat([]byte{'#'}, maxKeyLogLineBytes)); err != nil || n != maxKeyLogLineBytes {
		t.Fatalf("partial line at limit: n=%d err=%v", n, err)
	}
	if n, err := store.Write([]byte("x\n")); !errors.Is(err, ErrKeyLogResourceLimit) || n != 0 {
		t.Fatalf("oversized split line: n=%d err=%v", n, err)
	}
	if store.partial.Len() != 0 || store.partial.Cap() != 0 {
		t.Fatal("oversized partial line retained storage")
	}
	if _, err := store.Write([]byte("CLIENT_RANDOM 01 02\n")); err != nil || store.GetSecrets([]byte{1}) == nil {
		t.Fatalf("valid import after discarded partial line: %v", err)
	}
	for _, streaming := range []bool{false, true} {
		for _, ending := range []string{"", "\n", "\r\n"} {
			// The limit counts bytes before LF, including an optional CR.
			length := maxKeyLogLineBytes
			if ending == "\r\n" {
				length--
			}
			content := strings.Repeat("#", length) + ending
			if err := importTestKeyLog(NewKeyLogStore(), content, streaming); err != nil {
				t.Fatalf("streaming=%v: line at limit rejected: %v", streaming, err)
			}
			if err := importTestKeyLog(NewKeyLogStore(), "#"+content, streaming); !errors.Is(err, ErrKeyLogResourceLimit) {
				t.Fatalf("streaming=%v: oversized line error=%v", streaming, err)
			}
		}
	}
}

func TestKeyLogImportLargeBatchAndEntryLimit(t *testing.T) {
	var batch strings.Builder
	for i := 0; i < maxKeyLogEntries; i++ {
		fmt.Fprintf(&batch, "CLIENT_RANDOM %04x 01\n", i)
	}
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprintf("streaming=%v", streaming), func(t *testing.T) {
			store := NewKeyLogStore()
			if err := importTestKeyLog(store, batch.String(), streaming); err != nil {
				t.Fatal(err)
			}
			if len(store.secrets) != maxKeyLogEntries {
				t.Fatal("valid multi-line batch larger than the line limit was truncated")
			}
			if err := importTestKeyLog(store, "CLIENT_RANDOM 0000 0203\nSERVER_TRAFFIC_SECRET_0 0000 04\n", streaming); err != nil {
				t.Fatalf("existing entry update at limit: %v", err)
			}
			got := store.GetSecrets([]byte{0, 0})
			if !bytes.Equal(got.MasterSecret, []byte{2, 3}) || !bytes.Equal(got.ServerTrafficSecret, []byte{4}) ||
				len(store.secrets) != maxKeyLogEntries {
				t.Fatal("existing entry was not updated at the entry limit")
			}
			updates := store.Updates()
			if err := importTestKeyLog(store, "UNKNOWN_LABEL ffff 01\n", streaming); err != nil {
				t.Fatalf("unknown label allocated an entry: %v", err)
			}
			if err := importTestKeyLog(store, "CLIENT_RANDOM ffff 01\n", streaming); !errors.Is(err, ErrKeyLogResourceLimit) {
				t.Fatalf("new entry beyond limit: %v", err)
			}
			if store.GetSecrets([]byte{0xff, 0xff}) != nil || len(store.secrets) != maxKeyLogEntries {
				t.Fatal("failed import changed the store")
			}
			select {
			case <-updates:
				t.Fatal("ignored or rejected input notified secret subscribers")
			default:
			}
			if store.partial.Cap() != 0 {
				t.Fatal("failed import retained partial storage")
			}
			// Direct callers retain the original trusted-input compatibility path.
			store.AddSecret("CLIENT_RANDOM", "ffff", []byte{9})
			if got := store.GetSecrets([]byte{0xff, 0xff}); got == nil || !bytes.Equal(got.MasterSecret, []byte{9}) {
				t.Fatal("AddSecret silently discarded a valid key beyond the import limit")
			}
			store.AddSecret("UNKNOWN_LABEL", "eeee", []byte{1})
			if len(store.secrets) != maxKeyLogEntries+1 {
				t.Fatal("unknown AddSecret label created an empty entry")
			}
		})
	}
}

func TestKeyLogImportSecretBytesLimitAndReplacement(t *testing.T) {
	store := NewKeyLogStore()
	// Seed through the trusted API to reach the byte limit without a huge batch.
	store.AddSecret("CLIENT_TRAFFIC_SECRET_0", "01", make([]byte, maxKeyLogSecretBytes))
	for _, streaming := range []bool{false, true} {
		if err := importTestKeyLog(store, "CLIENT_RANDOM 02 01\n", streaming); !errors.Is(err, ErrKeyLogResourceLimit) {
			t.Fatalf("streaming=%v: secret byte limit error=%v", streaming, err)
		}
	}
	if len(store.secrets) != 1 || store.secretBytes != maxKeyLogSecretBytes {
		t.Fatal("rejected secret changed byte accounting or allocated an entry")
	}
	store.AddSecret("SERVER_TRAFFIC_SECRET_0", "01", []byte{2})
	if store.secretBytes != maxKeyLogSecretBytes+1 || len(store.secrets["01"].ServerTrafficSecret) != 1 {
		t.Fatal("trusted AddSecret failed beyond the byte limit")
	}
	if _, err := store.Write([]byte("SERVER_TRAFFIC_SECRET_0 01 03\n")); err != nil {
		t.Fatalf("non-growing replacement rejected after trusted addition: %v", err)
	}
	if err := store.LoadFromReader(strings.NewReader("QUIC_CLIENT_TRAFFIC_SECRET_0 01 04")); err != nil {
		t.Fatalf("shrinking replacement: %v", err)
	}
	got := store.GetSecrets([]byte{1})
	if store.secretBytes != 2 || !bytes.Equal(got.ClientTrafficSecret, []byte{4}) || !bytes.Equal(got.ServerTrafficSecret, []byte{3}) {
		t.Fatal("replacement did not charge only the difference in secret bytes")
	}
	if _, err := store.Write([]byte("CLIENT_RANDOM 02 05\n")); err != nil {
		t.Fatalf("freed secret capacity was not reusable: %v", err)
	}
}

func importTestKeyLog(store *KeyLogStore, content string, streaming bool) error {
	if streaming {
		_, err := store.Write([]byte(content))
		return err
	}
	return store.LoadFromReader(strings.NewReader(content))
}

func TestECHKeyLogExactAssociationAndCloning(t *testing.T) {
	store := NewKeyLogStore()
	outer := bytes.Repeat([]byte{0x32}, 32)
	inner := bytes.Repeat([]byte{0x21}, 32)
	outerHex := hex.EncodeToString(outer)
	updated := store.Updates()
	// Arrival order is independent of the TLS traffic-secret records.
	if _, err := store.Write([]byte("ECH_CONFIG " + strings.ToUpper(outerHex) + " 010203\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-updated:
	default:
		t.Fatal("ECH_CONFIG did not notify")
	}
	secret := bytes.Repeat([]byte{0x44}, 32)
	store.AddSecret("ECH_SECRET", outerHex, secret)
	store.AddSecret("CLIENT_TRAFFIC_SECRET_0", hex.EncodeToString(inner), []byte{9})
	secret[0] = 0
	got := store.GetSecrets(outer)
	if got == nil || got.ECHSecret[0] != 0x44 || !bytes.Equal(got.ECHConfig, []byte{1, 2, 3}) || len(got.ClientTrafficSecret) != 0 {
		t.Fatal("ECH labels not isolated on exact outer random")
	}
	got.ECHSecret[0] = 0
	got.ECHConfig[0] = 0
	again := store.GetSecrets(outer)
	if again.ECHSecret[0] != 0x44 || again.ECHConfig[0] != 1 {
		t.Fatal("ECH snapshot aliases store")
	}
	if got := store.GetSecrets(inner); got == nil || len(got.ECHConfig) != 0 || len(got.ECHSecret) != 0 || !bytes.Equal(got.ClientTrafficSecret, []byte{9}) {
		t.Fatal("inner and outer identities mixed")
	}
	before := store.secretBytes
	for _, bad := range []string{"00", "zz" + outerHex[2:], outerHex + "00"} {
		store.AddSecret("ECH_SECRET", bad, []byte{1})
	}
	if store.secretBytes != before || len(store.secrets) != 2 {
		t.Fatal("malformed ECH random allocated storage")
	}
	store.secretBytes = maxKeyLogSecretBytes
	_, err := store.Write([]byte("ECH_CONFIG " + outerHex + " 01020304\n"))
	if !errors.Is(err, ErrKeyLogResourceLimit) || len(store.GetSecrets(outer).ECHConfig) != 3 {
		t.Fatal("ECH import bypassed secret-byte budget")
	}
}

func TestStreamingKeyLogReferencesAndAccounting(t *testing.T) {
	store := NewStreamingKeyLogStore(time.Minute)
	first, second, undiscovered := store.NewConnectionScope(), store.NewConnectionScope(), store.NewConnectionScope()
	// References exist before a late DSB and repeated reads do not acquire more.
	for _, scope := range []*KeyLogStore{first, second} {
		scope.GetSecrets([]byte{1})
		scope.GetSecrets([]byte{1})
		scope.ResolveKeyReferences()
	}
	for _, line := range []string{"CLIENT_RANDOM 01 010203\n", "CLIENT_RANDOM 01 010203\n", "CLIENT_RANDOM 01 04\n", "SERVER_TRAFFIC_SECRET_0 01 0506\n"} {
		if _, err := store.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	if store.secretBytes != 3 || store.entries["01"].refs != 2 {
		t.Fatal("duplicate/update accounting changed reference count or bytes")
	}
	first.ReleaseKeyReferences()
	first.ReleaseKeyReferences()
	if store.GetSecrets([]byte{1}) == nil {
		t.Fatal("first release removed a shared key")
	}
	second.ReleaseKeyReferences()
	if store.GetSecrets([]byte{1}) == nil {
		t.Fatal("undiscovered connection lost an early DSB")
	}
	// A later worker can pin still-retained history atomically, but its
	// admission alone must not renew protection of already retired entries.
	later := store.NewConnectionScope()
	if later.GetSecrets([]byte{1}) == nil {
		t.Fatal("retained shared key could not be pinned")
	}
	undiscovered.ReleaseKeyReferences()
	if later.GetSecrets([]byte{1}) == nil {
		t.Fatal("explicit shared reference was reclaimed")
	}
	later.ResolveKeyReferences()
	later.ReleaseKeyReferences()
	if len(store.entries) != 0 || len(store.secrets) != 0 || store.secretBytes != 0 || len(store.pending) != 0 {
		t.Fatal("last worker retained keys or accounting")
	}
	// Missing keys have bounded references too; no secret needs to arrive to free them.
	missing := store.NewConnectionScope()
	missing.GetSecrets([]byte{2})
	missing.ResolveKeyReferences()
	missing.ReleaseKeyReferences()
	if len(store.entries) != 0 {
		t.Fatal("missing key reference survived failure")
	}
}

func TestStreamingKeyLogOrphanExpiryAndActiveProtection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := NewStreamingKeyLogStore(time.Second)
		if _, err := store.Write([]byte("CLIENT_RANDOM 01 0102\nCLIENT_RANDOM 02 0304\n")); err != nil {
			t.Fatal(err)
		}
		active := store.NewConnectionScope()
		active.GetSecrets([]byte{1})
		active.ResolveKeyReferences()
		pending := store.NewConnectionScope()
		time.Sleep(time.Second)
		store.ReapUnusedKeys()
		if store.GetSecrets([]byte{2}) == nil {
			t.Fatal("expired unassociated key lost before existing worker discovered identity")
		}
		pending.GetSecrets([]byte{2})
		pending.ResolveKeyReferences()
		time.Sleep(time.Hour)
		store.ReapUnusedKeys()
		if store.GetSecrets([]byte{1}) == nil || store.GetSecrets([]byte{2}) == nil {
			t.Fatal("active or waiting reference expired")
		}
		active.ReleaseKeyReferences()
		pending.ReleaseKeyReferences()
		if store.secretBytes != 0 {
			t.Fatal("completed workers retained secrets")
		}
		if _, err := store.Write([]byte("CLIENT_RANDOM 03 0506\n")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(750 * time.Millisecond)
		if _, err := store.Write([]byte("CLIENT_RANDOM 03 0506\nSERVER_TRAFFIC_SECRET_0 03 0708\n")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(250 * time.Millisecond)
		store.ReapUnusedKeys()
		if store.GetSecrets([]byte{3}) != nil || store.secretBytes != 0 {
			t.Fatal("duplicate or additional label extended orphan lifetime")
		}
		persistent := NewKeyLogStore()
		if _, err := persistent.Write([]byte("CLIENT_RANDOM 01 02\n")); err != nil {
			t.Fatal(err)
		}
		fileScope := persistent.NewConnectionScope()
		fileScope.GetSecrets([]byte{1})
		fileScope.ResolveKeyReferences()
		fileScope.ReleaseKeyReferences()
		time.Sleep(24 * time.Hour)
		persistent.ReapUnusedKeys()
		if persistent.GetSecrets([]byte{1}) == nil {
			t.Fatal("file pre-scan secret expired")
		}
	})
}

func TestKeyLogResourceLimitDetails(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		store := NewStreamingKeyLogStore(time.Minute)
		active := store.NewConnectionScope()
		active.GetSecrets(make([]byte, 32))
		active.ResolveKeyReferences()
		var batch strings.Builder
		for i := 0; i < maxKeyLogEntries; i++ {
			fmt.Fprintf(&batch, "CLIENT_RANDOM %064x %s\n", i, strings.Repeat("ab", 48))
		}
		// One Write is intentionally a multi-megabyte DSB, not an oversized line.
		if _, err := store.Write([]byte(batch.String())); err != nil {
			t.Fatal(err)
		}
		if store.secretBytes != 786432 {
			t.Fatalf("secret bytes=%d", store.secretBytes)
		}
		err := importTestKeyLog(store, fmt.Sprintf("CLIENT_RANDOM %064x %s\n", maxKeyLogEntries, strings.Repeat("cd", 48)), streaming)
		var detail *KeyLogResourceLimitError
		if !errors.Is(err, ErrKeyLogResourceLimit) || !errors.As(err, &detail) || detail.Resource != "entries" || detail.Current != maxKeyLogEntries || detail.Limit != maxKeyLogEntries || detail.Requested != 1 {
			t.Fatalf("incorrect safe entry limit: %v", err)
		}
		if strings.Contains(err.Error(), strings.Repeat("ab", 48)) || strings.Contains(err.Error(), fmt.Sprintf("%064x", maxKeyLogEntries)) {
			t.Fatal("error disclosed keylog content")
		}
		if store.GetSecrets(make([]byte, 32)) == nil {
			t.Fatal("pressure evicted the active connection's key")
		}
		active.ReleaseKeyReferences()
		if store.secretBytes != 786432-48 || len(store.secrets) != maxKeyLogEntries-1 {
			t.Fatal("release after capacity failure did not restore exact budget")
		}
		if err := importTestKeyLog(store, fmt.Sprintf("CLIENT_RANDOM %064x %s\n", maxKeyLogEntries, strings.Repeat("cd", 48)), streaming); err != nil {
			t.Fatalf("released capacity unusable: %v", err)
		}
	}
	for _, streaming := range []bool{false, true} {
		store := NewKeyLogStore()
		err := importTestKeyLog(store, strings.Repeat("PRIVATE", 600), streaming)
		var detail *KeyLogResourceLimitError
		if !errors.As(err, &detail) || detail.Resource != "line_bytes" || detail.Limit != 4096 || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatalf("line limit details: %v", err)
		}
		// Existing trusted API seeding only accelerates this byte-limit test.
		store.AddSecret("CLIENT_RANDOM", "01", make([]byte, maxKeyLogSecretBytes))
		err = importTestKeyLog(store, "SERVER_TRAFFIC_SECRET_0 01 abcd\n", streaming)
		if !errors.As(err, &detail) || detail.Resource != "secret_bytes" || detail.Current != maxKeyLogSecretBytes || detail.Requested != 2 {
			t.Fatalf("byte limit details: %v", err)
		}
	}
}

func TestStreamingKeyLogConcurrentImportReadAndRelease(t *testing.T) {
	store := NewStreamingKeyLogStore(time.Minute)
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 128; i++ {
				scope := store.NewConnectionScope()
				random := []byte{byte(worker)}
				scope.GetSecrets(random)
				scope.ResolveKeyReferences()
				line := []byte(fmt.Sprintf("CLIENT_RANDOM %x 01020304\n", random))
				if _, err := store.Write(line); err != nil {
					t.Error(err)
					return
				}
				snapshot := scope.GetSecrets(random)
				if snapshot == nil || len(snapshot.MasterSecret) != 4 {
					t.Error("pinned secret disappeared")
					return
				}
				snapshot.MasterSecret[0] = 99
				if scope.GetSecrets(random).MasterSecret[0] != 1 {
					t.Error("snapshot aliased cached secret")
					return
				}
				scope.ReleaseKeyReferences()
				store.ReapUnusedKeys()
			}
		}()
	}
	wg.Wait()
	if len(store.entries) != 0 || store.secretBytes != 0 || len(store.pending) != 0 {
		t.Fatal("concurrent workers leaked references")
	}
}

func TestStreamingKeyLogDiscoveryMetadataBounded(t *testing.T) {
	store := NewStreamingKeyLogStore(time.Minute)
	scope := store.NewConnectionScope()
	for i := 0; i < 100; i++ {
		scope.GetSecrets([]byte{byte(i)})
	}
	if scope.ResolveKeyReferences() {
		t.Fatal("overflowed identity set reported successful discovery")
	}
	if len(scope.scope.keys) != 8 || len(store.entries) != 8 || len(store.pending) != 1 {
		t.Fatal("unbounded negotiation identities or missing conservative barrier")
	}
	if _, err := store.Write([]byte("CLIENT_RANDOM ff 01\n")); err != nil {
		t.Fatal(err)
	}
	scope.ReleaseKeyReferences()
	if len(store.entries) != 1 || store.secretBytes != 1 || len(store.pending) != 0 {
		t.Fatal("bounded discovery cleanup damaged unrelated early DSB")
	}
}

func TestStreamingKeyLogPendingCohortsDoNotInheritRetiredHistory(t *testing.T) {
	store := NewStreamingKeyLogStore(time.Minute)
	older := store.NewConnectionScope()
	live := store.NewConnectionScope()
	live.GetSecrets([]byte{1})
	live.ResolveKeyReferences()
	if _, err := store.Write([]byte("CLIENT_RANDOM 01 010203\n")); err != nil {
		t.Fatal(err)
	}
	live.ReleaseKeyReferences()
	later := store.NewConnectionScope()
	if store.GetSecrets([]byte{1}) == nil {
		t.Fatal("earlier unresolved consumer lost the retained key")
	}
	older.ReleaseKeyReferences()
	if store.GetSecrets([]byte{1}) != nil || store.secretBytes != 0 || len(store.pending) != 1 {
		t.Fatal("later admission inherited historical protection")
	}
	// A fresh DSB, even for the same random, is available to the later worker.
	if _, err := store.Write([]byte("CLIENT_RANDOM 01 0405\n")); err != nil {
		t.Fatal(err)
	}
	if got := later.GetSecrets([]byte{1}); got == nil || !bytes.Equal(got.MasterSecret, []byte{4, 5}) {
		t.Fatal("fresh publication lost")
	}
	later.ResolveKeyReferences()
	later.ReleaseKeyReferences()
	if len(store.entries) != 0 || store.secretBytes != 0 {
		t.Fatal("new lifecycle did not release its keys")
	}
}

func TestStreamingKeyLogRepublishedHistoryProtectsNewConsumers(t *testing.T) {
	for _, republish := range []bool{false, true} {
		store := NewStreamingKeyLogStore(time.Minute)
		older, live := store.NewConnectionScope(), store.NewConnectionScope()
		live.GetSecrets([]byte{1})
		live.ResolveKeyReferences()
		if _, err := store.Write([]byte("CLIENT_RANDOM 01 0102\n")); err != nil {
			t.Fatal(err)
		}
		live.ReleaseKeyReferences()
		later := store.NewConnectionScope()
		if republish {
			// It is still physically retained for older. Reimport must give later
			// the same guarantee it would get if the entry had already been deleted.
			if _, err := store.Write([]byte("CLIENT_RANDOM 01 030405\n")); err != nil {
				t.Fatal(err)
			}
		} else {
			// The pre-retirement consumer may discover this shared identity late.
			if older.GetSecrets([]byte{1}) == nil {
				t.Fatal("pre-retirement reader lost the key")
			}
			older.ResolveKeyReferences()
		}
		older.ReleaseKeyReferences()
		if later.GetSecrets([]byte{1}) == nil {
			t.Fatal("fresh publication or overlapping live reference lost")
		}
		later.ResolveKeyReferences()
		later.ReleaseKeyReferences()
		if store.secretBytes != 0 || len(store.entries) != 0 {
			t.Fatal("republished/reference accounting leaked")
		}
	}
}

func TestStreamingKeyLogOrphanProtectionDoesNotExtendToLaterAdmissions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := NewStreamingKeyLogStore(time.Second)
		if _, err := store.Write([]byte("CLIENT_RANDOM 01 01\nCLIENT_RANDOM 02 02\n")); err != nil {
			t.Fatal(err)
		}
		older := store.NewConnectionScope()
		time.Sleep(time.Second)
		later := store.NewConnectionScope()
		// Reimport after the original window makes 02 available to new consumers.
		if _, err := store.Write([]byte("CLIENT_RANDOM 02 0203\n")); err != nil {
			t.Fatal(err)
		}
		older.ReleaseKeyReferences()
		if store.GetSecrets([]byte{1}) != nil || store.secretBytes != 2 {
			t.Fatal("later scope extended old orphan retention or broke new import")
		}
		if later.GetSecrets([]byte{2}) == nil {
			t.Fatal("republished orphan expired before later discovery")
		}
		later.ResolveKeyReferences()
		later.ReleaseKeyReferences()
		if len(store.entries) != 0 || store.secretBytes != 0 {
			t.Fatal("orphan publication leaked")
		}
	})
}

func TestStreamingKeyLogMissingReferenceDoesNotAccumulateMetadata(t *testing.T) {
	store := NewStreamingKeyLogStore(time.Minute)
	pending := store.NewConnectionScope()
	defer pending.ReleaseKeyReferences()
	for i := 0; i < 100; i++ {
		scope := store.NewConnectionScope()
		scope.GetSecrets([]byte{byte(i)})
		scope.ResolveKeyReferences()
		scope.ReleaseKeyReferences()
	}
	if len(store.entries) != 0 {
		t.Fatal("retired missing keys accumulated behind an unresolved worker")
	}
}
