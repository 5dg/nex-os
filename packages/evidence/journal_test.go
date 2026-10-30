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

func TestVerifyAnchoredExtension(t *testing.T) {
	limits := AnchoredVerificationLimits{MaxEntries: 10, MaxEntryBytes: 4096, MaxTotalBytes: 16384}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	j := Journal{Directory: t.TempDir(), Private: private}
	event := func(id string) Event {
		return Event{ID: id, TenantID: "tenant-a", ActorID: "alice", Producer: "kernel", Action: "model.intent", Detail: json.RawMessage(`{"outcome":"reserved"}`)}
	}
	first, err := j.Append(event("event-one"))
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := j.Append(event("event-two"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append(event("event-three")); err != nil {
		t.Fatal(err)
	}
	for _, pinned := range []Proof{first, anchor} {
		entries, err := VerifyAnchoredExtensionContext(context.Background(), j.Directory, public, pinned, limits)
		if err != nil || len(entries) != 3 {
			t.Fatalf("valid anchored extension rejected: %v", err)
		}
	}
	if _, err := Verify(j.Directory, public, &anchor); err == nil {
		t.Fatal("exact-tip verification unexpectedly accepted an older checkpoint")
	}
	wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, pinned := range []Proof{{}, {Sequence: anchor.Sequence, Head: anchor.Head, Signature: anchor.Signature, EventID: "other", Producer: anchor.Producer, Previous: anchor.Previous}} {
		if _, err := VerifyAnchoredExtensionContext(context.Background(), j.Directory, public, pinned, limits); err == nil {
			t.Fatal("invalid anchor accepted")
		}
	}
	if _, err := VerifyAnchoredExtensionContext(context.Background(), j.Directory, wrongPublic, anchor, limits); err == nil {
		t.Fatal("checkpoint from another key accepted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyAnchoredExtensionContext(canceled, j.Directory, public, anchor, limits); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled verification returned %v", err)
	}
	if _, err := VerifyAnchoredExtensionContext(nil, j.Directory, public, anchor, limits); err == nil {
		t.Fatal("nil context accepted")
	}
	for _, restricted := range []AnchoredVerificationLimits{
		{},
		{MaxEntries: 2, MaxEntryBytes: 4096, MaxTotalBytes: 16384},
		{MaxEntries: 10, MaxEntryBytes: 1, MaxTotalBytes: 16384},
		{MaxEntries: 10, MaxEntryBytes: 4096, MaxTotalBytes: 1},
		{MaxEntries: 100001, MaxEntryBytes: 4096, MaxTotalBytes: 16384},
		{MaxEntries: 10, MaxEntryBytes: 1024*1024 + 1, MaxTotalBytes: 16384},
		{MaxEntries: 10, MaxEntryBytes: 4096, MaxTotalBytes: 64*1024*1024 + 1},
	} {
		if _, err := VerifyAnchoredExtensionContext(context.Background(), j.Directory, public, anchor, restricted); err == nil {
			t.Fatalf("invalid or exceeded resource limits accepted: %+v", restricted)
		}
	}
	if err := os.WriteFile(filepath.Join(j.Directory, "unrelated.txt"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAnchoredExtensionContext(context.Background(), j.Directory, public, anchor, AnchoredVerificationLimits{MaxEntries: 3, MaxEntryBytes: 4096, MaxTotalBytes: 16384}); err == nil {
		t.Fatal("non-journal files did not count toward the directory limit")
	}
	thirdPath := filepath.Join(j.Directory, "000000000003.json")
	thirdBytes, err := os.ReadFile(thirdPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(thirdPath, []byte(`{"bad":"entry"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAnchoredExtensionContext(context.Background(), j.Directory, public, anchor, limits); err == nil {
		t.Fatal("invalid entry after the anchor was accepted")
	}
	if err := os.WriteFile(thirdPath, thirdBytes, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(j.Directory, "000000000004.json")
	if err := os.Symlink(thirdPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAnchoredExtensionContext(context.Background(), j.Directory, public, anchor, limits); err == nil {
		t.Fatal("symlinked journal entry was accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	// A journal signed by the same key can still be a valid fork. An external
	// checkpoint distinguishes it from the originally acknowledged branch.
	fork := Journal{Directory: t.TempDir(), Private: private}
	if _, err := fork.Append(event("event-one")); err != nil {
		t.Fatal(err)
	}
	if _, err := fork.Append(event("forked-event-two")); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(fork.Directory, public, nil); err != nil {
		t.Fatalf("fixture fork is not independently valid: %v", err)
	}
	if _, err := VerifyAnchoredExtensionContext(context.Background(), fork.Directory, public, anchor, limits); err == nil {
		t.Fatal("signed fork passed the pinned checkpoint")
	}
	if err := os.Remove(filepath.Join(j.Directory, "000000000003.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAnchoredExtensionContext(context.Background(), j.Directory, public, anchor, limits); err != nil {
		t.Fatalf("exact checkpoint rejected: %v", err)
	}
	if err := os.Remove(filepath.Join(j.Directory, "000000000002.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAnchoredExtensionContext(context.Background(), j.Directory, public, anchor, limits); err == nil {
		t.Fatal("truncation before the checkpoint accepted")
	}
}
