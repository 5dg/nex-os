package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/5dg/nex-os/packages/broker"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSigningReadinessCanonicalVectors(t *testing.T) {
	b, e := os.ReadFile("readiness-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var vectors []struct {
		Producer, Nonce string
		KeyFingerprint  string `json:"key_fingerprint"`
		Public          string `json:"public_key"`
		Canonical       string `json:"canonical_hex"`
		Signature       string
	}
	if e = json.Unmarshal(b, &vectors); e != nil {
		t.Fatal(e)
	}
	for _, v := range vectors {
		t.Run(v.Producer, func(t *testing.T) {
			public, e := base64.RawURLEncoding.DecodeString(v.Public)
			if e != nil {
				t.Fatal(e)
			}
			p := ChallengeProof{Producer: v.Producer, Nonce: v.Nonce, KeyFingerprint: v.KeyFingerprint, Signature: v.Signature}
			if hex.EncodeToString(challengeMessage(v.Producer, v.Nonce, v.KeyFingerprint)) != v.Canonical || !VerifyChallenge(public, p, v.Producer, v.Nonce) {
				t.Fatal("readiness canonical contract differs")
			}
			if VerifyChallenge(public, p, v.Producer, strings.Repeat("0", 64)) {
				t.Fatal("replayed nonce accepted")
			}
			other := "kernel"
			if v.Producer == other {
				other = "control"
			}
			if VerifyChallenge(public, p, other, v.Nonce) {
				t.Fatal("producer substituted")
			}
			p.KeyFingerprint = "sha256:" + strings.Repeat("0", 64)
			if VerifyChallenge(public, p, v.Producer, v.Nonce) {
				t.Fatal("key fingerprint substituted")
			}
		})
	}
}
func TestChallengeProvesCredentialAndPinnedKeyWithoutAppend(t *testing.T) {
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	directory := filepath.Join(t.TempDir(), "journal")
	journal, e := OpenJournal(directory, private)
	if e != nil {
		t.Fatal(e)
	}
	defer journal.Close()
	control := make([]byte, 32)
	kernel := make([]byte, 32)
	kernel[0] = 1
	server := httptest.NewServer(Handler(journal, control, kernel))
	defer server.Close()
	client := broker.NewClient(server.URL+"/append/control", "evidence.append.control", control)
	if e = Challenge(context.Background(), client, public, "control"); e != nil {
		t.Fatal(e)
	}
	wrongPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	if Challenge(context.Background(), client, wrongPublic, "control") == nil {
		t.Fatal("wrong signing pin reported ready")
	}
	if Challenge(context.Background(), client, public, "kernel") == nil {
		t.Fatal("wrong producer credential reported ready")
	}
	files, e := filepath.Glob(filepath.Join(directory, "*.json"))
	if e != nil || len(files) != 0 {
		t.Fatal("readiness appended evidence", files, e)
	}
	// Liveness cannot substitute for the pinned-key proof.
	response, e := http.Get(server.URL + "/healthz")
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("liveness failed")
	}
	if e = journal.Close(); e != nil {
		t.Fatal(e)
	}
	if Challenge(context.Background(), client, public, "control") == nil {
		t.Fatal("closed custody reported ready")
	}
}
func TestChallengeRequiresCurrentPeerAndUntamperedStorage(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	journal, e := OpenJournal(filepath.Join(t.TempDir(), "journal"), private)
	if e != nil {
		t.Fatal(e)
	}
	defer journal.Close()
	nonce := strings.Repeat("a", 64)
	if _, e = journal.ChallengeContext(context.Background(), "kernel", nonce, func() error { return errors.New("peer expired during storage verification") }); e == nil {
		t.Fatal("expired peer received readiness proof")
	}
	event := Event{ID: "event-123", TenantID: "tenant", ActorID: "actor", Action: "synthetic", Detail: json.RawMessage(`{"ok":true}`)}
	if _, e = journal.Append(event); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(journal.Directory, "000000000001.json"), []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = journal.ChallengeContext(context.Background(), "kernel", nonce, nil); e == nil {
		t.Fatal("corrupt journal reported ready")
	}
}
func TestReadinessAndAppendRespectCancelledContext(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	journal, e := OpenJournal(filepath.Join(t.TempDir(), "journal"), private)
	if e != nil {
		t.Fatal(e)
	}
	defer journal.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = journal.ChallengeContext(ctx, "control", strings.Repeat("1", 64), nil); e == nil {
		t.Fatal("cancelled readiness succeeded")
	}
	if _, e = journal.AppendContext(ctx, Event{ID: "event-123", TenantID: "tenant", Action: "synthetic"}, nil); e == nil {
		t.Fatal("cancelled append succeeded")
	}
	files, _ := filepath.Glob(filepath.Join(journal.Directory, "*.json"))
	if len(files) != 0 {
		t.Fatal("cancelled request appended")
	}
}

func TestReadinessAndAppendDoNotWaitForeverForWriter(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	journal, e := OpenJournal(filepath.Join(t.TempDir(), "journal"), private)
	if e != nil {
		t.Fatal(e)
	}
	defer journal.Close()
	journal.mu.Lock()
	defer journal.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := journal.ChallengeContext(ctx, "control", strings.Repeat("1", 64), nil); !errors.Is(e, context.Canceled) {
		t.Fatal("challenge ignored bounded lock acquisition", e)
	}
	if _, e := journal.AppendContext(ctx, Event{ID: "event-123", TenantID: "tenant", Action: "synthetic"}, nil); !errors.Is(e, context.Canceled) {
		t.Fatal("append ignored bounded lock acquisition", e)
	}
}

func TestQualifiedAppendCannotOmitCustody(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	journal := &Journal{Directory: t.TempDir(), Private: private}
	key := make([]byte, 32)
	server := httptest.NewServer(HandlerWithPeer(journal, key, key, func(*http.Request, string) error { return nil }))
	defer server.Close()
	client := broker.NewClient(server.URL+"/append/control", "evidence.append.control", key)
	var proof Proof
	if e := client.Call(context.Background(), Event{ID: "event-123", TenantID: "tenant", Action: "synthetic"}, &proof); e == nil {
		t.Fatal("qualified append without exclusive custody")
	}
	files, _ := filepath.Glob(filepath.Join(journal.Directory, "*.json"))
	if len(files) != 0 {
		t.Fatal("unowned writer appended")
	}
}
