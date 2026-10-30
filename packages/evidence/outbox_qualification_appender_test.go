package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/5dg/nex-os/packages/trust"
	"github.com/5dg/nex-os/tests/qualification/fixtures/pki"
)

func outboxFixtureIdentity(t *testing.T, ca *pki.Authority, role trust.Role) *trust.Config {
	t.Helper()
	leaf, err := ca.Issue(pki.Spec{Name: string(role), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, URIs: []string{role.URI()}, ClientAuth: true, ServerAuth: true})
	if err != nil {
		t.Fatal(err)
	}
	files, err := ca.WriteFiles(t.TempDir(), string(role), leaf)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := trust.LoadFiles(trust.Qualification, role, files.CA, files.Certificate, files.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func outboxFixtureServer(t *testing.T, cfg *trust.Config, handler http.Handler) *httptest.Server {
	t.Helper()
	tlsConfig, err := cfg.ServerTLS(true)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = tlsConfig
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func TestQualificationOutboxAppenderActualService(t *testing.T) {
	ca, err := pki.NewAuthority("outbox appender fixture")
	if err != nil {
		t.Fatal(err)
	}
	guard := outboxFixtureIdentity(t, ca, trust.Guard)
	service := outboxFixtureIdentity(t, ca, trust.Evidence)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := OpenJournal(t.TempDir(), private)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	key := make([]byte, 32)
	key[0] = 42
	handler := HandlerWithPeer(journal, make([]byte, 32), append([]byte(nil), key...), func(r *http.Request, producer string) error {
		return service.CheckPeer(r.TLS, []trust.Role{trust.Guard})
	})
	var lose atomic.Bool
	lose.Store(true)
	server := outboxFixtureServer(t, service, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if lose.Swap(false) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, r)
			if response.Code != http.StatusOK {
				t.Errorf("fixture did not append before dropping response: %d %s", response.Code, response.Body.String())
			}
			http.Error(w, "response lost after append", http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	appender, err := NewQualificationOutboxAppender(server.URL, key, guard)
	if err != nil {
		t.Fatal(err)
	}
	key[0] ^= 1 // the appender must have copied its credential
	_, event := candidateEvidenceFixture()
	raw, err := json.Marshal(normalized(event))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = appender.AppendExact(context.Background(), raw); err == nil {
		t.Fatal("ambiguous response treated as success")
	}
	proof, err := appender.AppendExact(context.Background(), raw)
	if err != nil {
		t.Fatal("identical event retry failed", err)
	}
	verifier, err := NewPinnedOutboxProofVerifier(public)
	if err != nil || verifier.VerifyExact(context.Background(), raw, proof) != nil {
		t.Fatal("service proof does not bind the original event")
	}
	again, err := appender.AppendExact(context.Background(), raw)
	if err != nil || string(proof) != string(again) {
		t.Fatal("identical retry did not return the same proof")
	}
	entries, err := Verify(journal.Directory, public, nil)
	if err != nil || len(entries) != 1 {
		t.Fatal("lost-response retry duplicated or corrupted the journal")
	}
	changed := []byte(strings.Replace(string(raw), `"tenant-a"`, `"tenant-b"`, 1))
	if _, err = appender.AppendExact(context.Background(), changed); err == nil {
		t.Fatal("same event ID with changed content was accepted")
	}
	if _, err = appender.AppendExact(context.Background(), append([]byte(" "), raw...)); err == nil {
		t.Fatal("noncanonical event was sent")
	}
	wrongKey, err := NewQualificationOutboxAppender(server.URL, key, guard)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wrongKey.AppendExact(context.Background(), raw); err == nil {
		t.Fatal("wrong capability accepted")
	}
	entries, err = Verify(journal.Directory, public, nil)
	if err != nil || len(entries) != 1 {
		t.Fatal("rejected request modified the journal")
	}
}

func TestQualificationOutboxAppenderRejectsUnsafeRoutesAndIdentity(t *testing.T) {
	ca, err := pki.NewAuthority("outbox route fixture")
	if err != nil {
		t.Fatal(err)
	}
	guard := outboxFixtureIdentity(t, ca, trust.Guard)
	control := outboxFixtureIdentity(t, ca, trust.Control)
	key := make([]byte, 32)
	for _, route := range []string{"http://example.invalid", "https://example.invalid/other", "https://example.invalid/?q=x", "https://user@example.invalid", "https://example.invalid/#fragment"} {
		if _, err := NewQualificationOutboxAppender(route, key, guard); err == nil {
			t.Fatalf("unsafe route accepted: %q", route)
		}
	}
	if _, err := NewQualificationOutboxAppender("https://example.invalid", key, control); err == nil {
		t.Fatal("wrong client role accepted")
	}
	var reached atomic.Int32
	wrongServer := outboxFixtureServer(t, control, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	appender, err := NewQualificationOutboxAppender(wrongServer.URL, key, guard)
	if err != nil {
		t.Fatal(err)
	}
	_, event := candidateEvidenceFixture()
	raw, err := json.Marshal(normalized(event))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = appender.AppendExact(context.Background(), raw); err == nil || reached.Load() != 0 {
		t.Fatal("request reached a service with the wrong identity")
	}
	otherCA, err := pki.NewAuthority("untrusted evidence service")
	if err != nil {
		t.Fatal(err)
	}
	foreignEvidence := outboxFixtureIdentity(t, otherCA, trust.Evidence)
	foreignServer := outboxFixtureServer(t, foreignEvidence, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	foreignAppender, err := NewQualificationOutboxAppender(foreignServer.URL, key, guard)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = foreignAppender.AppendExact(context.Background(), raw); err == nil || reached.Load() != 0 {
		t.Fatal("request reached a service signed by an untrusted CA")
	}
	evidence := outboxFixtureIdentity(t, ca, trust.Evidence)
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	defer redirectTarget.Close()
	redirectServer := outboxFixtureServer(t, evidence, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusTemporaryRedirect)
	}))
	redirectAppender, err := NewQualificationOutboxAppender(redirectServer.URL, key, guard)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = redirectAppender.AppendExact(context.Background(), raw); err == nil || reached.Load() != 0 {
		t.Fatal("redirect leaked a capability or was treated as success")
	}
	tooLarge := outboxFixtureServer(t, evidence, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 16*1024+1)))
	}))
	largeAppender, err := NewQualificationOutboxAppender(tooLarge.URL, key, guard)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = largeAppender.AppendExact(context.Background(), raw); err == nil {
		t.Fatal("oversized proof was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = appender.AppendExact(ctx, raw); err == nil {
		t.Fatal("cancelled request accepted")
	}
}
