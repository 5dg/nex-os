package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

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
