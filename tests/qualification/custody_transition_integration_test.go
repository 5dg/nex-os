//go:build integration

package qualification_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/5dg/nex-os/packages/evidence"
)

// E alone performs the external transition. This process retains the browser
// cookie in memory and exchanges only non-secret phase markers on disk.
// Run once for NEX_QUAL_TRANSITION=rotation, and again for restore. E must wait
// for before.ready, rotate/restart or perform its frozen backup/restore, then
// write transition.applied. No completed workflow fixture is fabricated.
func TestQualificationCustodyTransition(t *testing.T) {
	mode := os.Getenv("NEX_QUAL_TRANSITION")
	if mode != "rotation" && mode != "restore" {
		t.Fatal("NEX_QUAL_TRANSITION must explicitly select rotation or restore")
	}
	state := os.Getenv("NEX_QUAL_STATE_DIR")
	signals := os.Getenv("NEX_QUAL_TRANSITION_SIGNAL_DIR")
	if !filepath.IsAbs(state) || !filepath.IsAbs(signals) {
		t.Fatal("absolute qualification state and transition signal directories required")
	}
	info, e := os.Stat(signals)
	if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		t.Fatal("E must provide a private empty transition signal directory")
	}
	entries, e := os.ReadDir(signals)
	if e != nil || len(entries) != 0 {
		t.Fatal("transition signals must use a new empty directory")
	}
	beforeCA, e := os.ReadFile(filepath.Join(state, "current-pki", "ca.crt"))
	if e != nil {
		t.Fatal("current qualification CA unavailable")
	}
	oldBrowser := newSystemBrowser(t)
	oldBrowser.login("alice")
	status, sessionJSON := oldBrowser.request("GET", "/api/session", nil, "", "")
	var session struct {
		Expires string `json:"expires_at"`
	}
	if status != 200 || json.Unmarshal(sessionJSON, &session) != nil {
		t.Fatal("pre-transition session lifetime unavailable")
	}
	expires, err := time.Parse(time.RFC3339Nano, session.Expires)
	if err != nil {
		t.Fatal("invalid server-owned session lifetime")
	}
	var visible []map[string]any
	oldBrowser.workflow(map[string]any{"operation": "documents"}, 200, &visible)
	if len(visible) == 0 {
		t.Fatal("pre-transition authenticated database boundary unavailable")
	}
	public, e := os.ReadFile(filepath.Join(state, "evidence-public"))
	if e != nil || len(public) != ed25519.PublicKeySize {
		t.Fatal("pinned evidence public key unavailable")
	}
	beforeJournal, e := evidence.Verify(filepath.Join(state, "evidence"), ed25519.PublicKey(public), nil)
	if e != nil || len(beforeJournal) == 0 {
		t.Fatal("pre-transition real signed journal required")
	}
	before := custodySnapshot(t, state)
	if len(before) == 0 {
		t.Fatal("run actual browser review/approve/export before custody transition")
	}
	checkpoint := struct {
		Mode  string            `json:"mode"`
		Files map[string]string `json:"file_sha256"`
		Head  evidence.Proof    `json:"journal_head"`
	}{mode, before, beforeJournal[len(beforeJournal)-1].Proof}
	encoded, e := json.Marshal(checkpoint)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(signals, "checkpoint.json"), encoded, 0600); e != nil {
		t.Fatal("cannot write public custody checkpoint")
	}
	if e = os.WriteFile(filepath.Join(signals, "before.ready"), []byte(mode+"\n"), 0600); e != nil {
		t.Fatal("cannot signal transition readiness")
	}
	t.Log("Authenticated browser and public custody checkpoint ready; awaiting E-controlled " + mode + ".")
	deadline := time.Now().Add(3 * time.Minute)
	for {
		if _, e = os.Stat(filepath.Join(signals, "transition.applied")); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("E-controlled transition was not signaled within three minutes")
		}
		time.Sleep(250 * time.Millisecond)
	}
	afterCA, e := os.ReadFile(filepath.Join(state, "current-pki", "ca.crt"))
	if e != nil {
		t.Fatal("post-transition qualification CA unavailable")
	}
	if mode == "rotation" && sha256.Sum256(beforeCA) == sha256.Sum256(afterCA) {
		t.Fatal("rotation did not replace the immutable trust generation")
	}
	if !time.Now().Add(5 * time.Second).Before(expires) {
		t.Fatal("old session reached credential expiry; cannot attribute invalidation to restart")
	}
	// Preserve the old session handle but use newly trusted server CA. This
	// isolates session invalidation from the expected old-CA TLS rejection.
	newTransport := systemClient(t, "")
	oldBrowser.client.Transport = newTransport.Transport
	if code, _ := oldBrowser.request("GET", "/api/session", nil, "", ""); code != 401 {
		t.Fatalf("pre-transition browser session survived process restart: %d", code)
	}
	newBrowser := newSystemBrowser(t)
	newBrowser.login("alice")
	newBrowser.workflow(map[string]any{"operation": "documents"}, 200, &visible)
	after := custodySnapshot(t, state)
	for path, digest := range before {
		if after[path] != digest {
			t.Fatalf("prior custody bytes changed or disappeared: %s", path)
		}
	}
	afterPublic, e := os.ReadFile(filepath.Join(state, "evidence-public"))
	if e != nil || string(afterPublic) != string(public) {
		t.Fatal("historical evidence verification key changed during transport transition")
	}
	afterJournal, e := evidence.Verify(filepath.Join(state, "evidence"), ed25519.PublicKey(public), nil)
	if e != nil || len(afterJournal) < len(beforeJournal) {
		t.Fatal("historical journal no longer verifies")
	}
	for i, entry := range beforeJournal {
		if afterJournal[i].Proof != entry.Proof {
			t.Fatal("historical journal prefix changed")
		}
	}
	if e = os.WriteFile(filepath.Join(signals, "after.verified"), []byte(mode+"\n"), 0600); e != nil {
		t.Fatal("cannot signal verified custody transition")
	}
}

func custodySnapshot(t *testing.T, state string) map[string]string {
	t.Helper()
	out := map[string]string{}
	receipts := 0
	for _, name := range []string{"model-receipts", "export-receipts", "evidence"} {
		root := filepath.Join(state, name)
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return fs.ErrInvalid
			}
			if entry.IsDir() {
				return nil
			}
			if !strings.HasSuffix(entry.Name(), ".state") && !strings.HasSuffix(entry.Name(), ".done") && !strings.HasSuffix(entry.Name(), ".json") {
				return nil
			}
			info, e := entry.Info()
			if e != nil {
				return e
			}
			if !info.Mode().IsRegular() || info.Size() > 1<<20 {
				return fs.ErrInvalid
			}
			raw, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			sum := sha256.Sum256(raw)
			relative, e := filepath.Rel(state, path)
			if e != nil {
				return e
			}
			out[relative] = hex.EncodeToString(sum[:])
			if name == "export-receipts" {
				receipts++
			}
			if len(out) > 10000 {
				return fs.ErrInvalid
			}
			return nil
		})
		if err != nil {
			t.Fatal("cannot snapshot bounded local custody domain")
		}
	}
	if receipts == 0 {
		t.Fatal("at least one genuine completed export receipt is required before transition")
	}
	return out
}
