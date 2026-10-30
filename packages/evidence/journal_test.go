package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAppendRetryRequiresDurableDirectory(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	j := Journal{Directory: t.TempDir(), Private: private}
	event := Event{ID: "event-durability", TenantID: "tenant-a", ActorID: "alice", Producer: "kernel", Action: "model.intent", Detail: json.RawMessage(`{"outcome":"reserved"}`)}
	syncErr := errors.New("injected directory sync failure")
	failSync := func(string) error { return syncErr }
	if proof, err := j.appendContext(context.Background(), event, nil, failSync); !errors.Is(err, syncErr) || proof != (Proof{}) {
		t.Fatal("failed initial sync returned an acknowledged proof", err)
	}
	entries, err := Verify(j.Directory, public, nil)
	if err != nil || len(entries) != 1 {
		t.Fatal("linked entry missing after injected sync failure", err)
	}
	if proof, err := j.appendContext(context.Background(), event, nil, failSync); !errors.Is(err, syncErr) || proof != (Proof{}) {
		t.Fatal("retry acknowledged an unsynced directory", err)
	}
	syncs := 0
	proof, err := j.appendContext(context.Background(), event, nil, func(path string) error {
		syncs++
		return syncJournalDirectory(path)
	})
	if err != nil || syncs != 1 || proof != entries[0].Proof {
		t.Fatal("retry did not sync and return the original proof", err)
	}
	entries, err = Verify(j.Directory, public, &proof)
	if err != nil || len(entries) != 1 {
		t.Fatal("retry duplicated or damaged the journal", err)
	}
}

func TestTamperDetectionAndRestore(t *testing.T) {
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	directory := t.TempDir()
	j := Journal{Directory: directory, Private: private}
	event := Event{ID: "event-one", TenantID: "tenant-a", ActorID: "alice", Action: "export.intent", Detail: json.RawMessage(`{"outcome":"reserved"}`)}
	proof, e := j.Append(event)
	if e != nil {
		t.Fatal(e)
	}
	again, e := j.Append(event)
	if e != nil || again != proof {
		t.Fatal("duplicate event was not idempotent")
	}
	if _, e := Verify(directory, public, &proof); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(directory, "000000000001.json")
	backup, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var entry Entry
	json.Unmarshal(backup, &entry)
	entry.Event.ActorID = "mallory"
	changed, _ := json.Marshal(entry)
	os.WriteFile(path, changed, 0600)
	if _, e := Verify(directory, public, &proof); e == nil {
		t.Fatal("event tampering accepted")
	}
	os.WriteFile(path, backup, 0600)
	if _, e := Verify(directory, public, &proof); e != nil {
		t.Fatal("backup restore integrity failed", e)
	}
	os.Remove(path)
	if _, e := Verify(directory, public, &proof); e == nil {
		t.Fatal("truncation passed the pinned checkpoint")
	}
}
