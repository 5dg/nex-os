package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// This runs after the Rust transaction test on the same explicitly disposable
// restricted TLS database. It proves wire-format interoperation, not custody.
func TestCandidateOutboxRustToGoBridge(t *testing.T) {
	raw := os.Getenv("NEX_EVIDENCE_BRIDGE_GO_DSN")
	if raw == "" {
		t.Skip("synthetic bridge database not configured")
	}
	if os.Getenv("NEX_EVIDENCE_BRIDGE_FIXTURE") != "disposable-only" {
		t.Fatal("disposable fixture required")
	}
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || len(parsed.Query()["sslmode"]) != 1 || parsed.Query().Get("sslmode") != "verify-full" || len(parsed.Query()["sslrootcert"]) != 1 || parsed.Query().Get("sslrootcert") == "" {
		t.Fatal("verified fixture TLS required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg, err := pgxpool.ParseConfig(raw)
	if err != nil || cfg.ConnConfig.TLSConfig == nil || cfg.ConnConfig.TLSConfig.InsecureSkipVerify {
		t.Fatal("invalid fixture TLS")
	}
	cfg.ConnConfig.Fallbacks = nil
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("fixture database unavailable")
	}
	defer pool.Close()
	var database, role string
	var restricted bool
	if pool.QueryRow(ctx, `SELECT current_database(),current_user`).Scan(&database, &role) != nil || !strings.HasPrefix(database, "nex_evidence_bridge_") || !strings.HasPrefix(role, "nex_evidence_bridge_") {
		t.Fatal("non-disposable fixture")
	}
	if pool.QueryRow(ctx, `SELECT NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=pg_roles.oid) AND NOT EXISTS(SELECT FROM pg_database WHERE datname=current_database() AND datdba=pg_roles.oid) FROM pg_roles WHERE rolname=current_user`).Scan(&restricted) != nil || !restricted {
		t.Fatal("restricted role required")
	}
	var vectors []struct {
		Event     Event  `json:"event"`
		Canonical string `json:"canonical"`
	}
	vectorBytes, err := os.ReadFile("candidate-outbox-vectors.json")
	if err != nil || json.Unmarshal(vectorBytes, &vectors) != nil || len(vectors) != 1 {
		t.Fatal("invalid bridge vector")
	}
	scope, _ := candidateEvidenceFixture()
	var state string
	var stored []byte
	if pool.QueryRow(ctx, `SELECT state,event_bytes FROM nex_candidate_evidence.outbox WHERE event_id=$1`, scope.EventID).Scan(&state, &stored) != nil || state != "pending" || string(stored) != vectors[0].Canonical {
		t.Fatal("Rust committed row differs from Go vector")
	}
	canonical, err := canonicalCandidateEvent(scope, vectors[0].Event)
	if err != nil || string(canonical) != string(stored) {
		t.Fatal("Go rejected Rust event")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("fixture key unavailable")
	}
	journal := &Journal{Directory: t.TempDir(), Private: private}
	appender := &syntheticOutboxAppender{journal: journal}
	authority := &syntheticOutboxAuthority{}
	store, err := NewCandidateEvidenceOutbox(pool, &syntheticOutboxFence{}, syntheticOutboxVerifier{public: public})
	if err != nil || store.ReadyForRelease(ctx, scope, authority) == nil {
		t.Fatal("pending event allowed release")
	}
	if store.Dispatch(ctx, scope, authority, appender) != nil || store.ReadyForRelease(ctx, scope, authority) != nil {
		t.Fatal("Go dispatch of Rust event failed")
	}
	entries, err := Verify(journal.Directory, public, nil)
	if err != nil || len(entries) != 1 || appender.calls.Load() != 1 {
		t.Fatal("bridge did not append one valid event")
	}
	t.Log("synthetic Rust to Go bridge completed")
}
