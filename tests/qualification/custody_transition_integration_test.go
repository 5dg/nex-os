//go:build integration

package qualification_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/5dg/nex-os/packages/contracts"
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
	afterState := state
	if mode == "restore" {
		afterState = os.Getenv("NEX_QUAL_RESTORE_STATE_DIR")
		if !filepath.IsAbs(afterState) || filepath.Clean(afterState) == filepath.Clean(state) {
			t.Fatal("restore requires a distinct absolute NEX_QUAL_RESTORE_STATE_DIR")
		}
	}
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
	completedJob := ""
	for i := len(beforeJournal) - 1; i >= 0; i-- {
		event := beforeJournal[i].Event
		if event.Action == "export.completed" && event.ActorID == "alice" && event.JobID != "" {
			completedJob = event.JobID
			break
		}
	}
	if completedJob == "" {
		t.Fatal("pre-transition actual completed Alice export evidence required")
	}
	var beforeJob contracts.ReviewJob
	oldBrowser.workflow(map[string]any{"operation": "job", "id": completedJob}, 200, &beforeJob)
	if beforeJob.State != "completed" || beforeJob.Answer == "" || beforeJob.Provider != "development" || beforeJob.ExportID == "" {
		t.Fatal("pre-transition protected completed export job unavailable")
	}
	type timelineEvent struct {
		evidence.Event
		Proof    evidence.Proof `json:"integrity_reference"`
		Verified bool           `json:"integrity_verified"`
	}
	var beforeEvents []timelineEvent
	oldBrowser.workflow(map[string]any{"operation": "events", "id": completedJob}, 200, &beforeEvents)
	if len(beforeEvents) == 0 {
		t.Fatal("pre-transition signed database timeline absent")
	}
	for _, event := range beforeEvents {
		if !event.Verified || !evidence.VerifyEvent(ed25519.PublicKey(public), event.Proof, event.Event) {
			t.Fatal("pre-transition database event does not match signed custody")
		}
	}
	// Job and timeline reads themselves append current-authority audit events.
	// Pin the custody head after those authenticated reads have committed.
	beforeJournal, e = evidence.Verify(filepath.Join(state, "evidence"), ed25519.PublicKey(public), nil)
	if e != nil || len(beforeJournal) == 0 {
		t.Fatal("pre-transition audited reads did not leave a valid custody journal")
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
	afterCA, e := os.ReadFile(filepath.Join(afterState, "current-pki", "ca.crt"))
	if e != nil {
		t.Fatal("post-transition qualification CA unavailable")
	}
	if mode == "rotation" && sha256.Sum256(beforeCA) == sha256.Sum256(afterCA) {
		t.Fatal("rotation did not replace the immutable trust generation")
	}
	if !time.Now().Add(5 * time.Second).Before(expires) {
		t.Fatal("old session reached credential expiry; cannot attribute invalidation to restart")
	}
	if mode == "rotation" {
		response, err := oldBrowser.client.Get(oldBrowser.origin + "/api/session")
		if err == nil {
			response.Body.Close()
			t.Fatal("prior CA still authenticated the rotated workspace")
		}
		var unknown x509.UnknownAuthorityError
		if !errors.As(err, &unknown) {
			t.Fatal("prior CA was not rejected specifically by verified trust after rotation")
		}
	}
	if mode == "restore" {
		t.Setenv("NEX_QUAL_STATE_DIR", afterState)
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
	var afterJob contracts.ReviewJob
	newBrowser.workflow(map[string]any{"operation": "job", "id": completedJob}, 200, &afterJob)
	if afterJob != beforeJob {
		t.Fatal("protected completed job/result differs through post-transition application")
	}
	var afterEvents []timelineEvent
	newBrowser.workflow(map[string]any{"operation": "events", "id": completedJob}, 200, &afterEvents)
	if len(afterEvents) < len(beforeEvents) {
		t.Fatal("historical signed database timeline disappeared across custody transition")
	}
	for i, event := range afterEvents {
		if !event.Verified || !evidence.VerifyEvent(ed25519.PublicKey(public), event.Proof, event.Event) {
			t.Fatal("restored database timeline does not match original signed custody")
		}
		if i < len(beforeEvents) {
			beforeJSON, _ := json.Marshal(beforeEvents[i])
			afterJSON, _ := json.Marshal(event)
			if string(beforeJSON) != string(afterJSON) {
				t.Fatal("historical signed database timeline prefix changed")
			}
		} else if event.Action != "document.read" || event.Producer != "control" || event.ActorID != "alice" || event.JobID != completedJob {
			t.Fatal("unexpected post-transition job mutation beyond audited authority reads")
		}
	}
	after := custodySnapshot(t, afterState)
	for path, digest := range before {
		if after[path] != digest {
			t.Fatalf("prior custody bytes changed or disappeared: %s", path)
		}
	}
	afterPublic, e := os.ReadFile(filepath.Join(afterState, "evidence-public"))
	if e != nil || string(afterPublic) != string(public) {
		t.Fatal("historical evidence verification key changed during transport transition")
	}
	afterJournal, e := evidence.Verify(filepath.Join(afterState, "evidence"), ed25519.PublicKey(public), nil)
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
