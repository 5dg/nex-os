package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type syntheticOutboxFence struct{ blocked atomic.Bool }

func (f *syntheticOutboxFence) Check(context.Context) error {
	if f.blocked.Load() {
		return errors.New("fixture fence closed")
	}
	return nil
}

type syntheticOutboxAuthority struct {
	revoked          atomic.Bool
	revokeAfterFirst atomic.Bool
	releases         atomic.Int32
}

func (a *syntheticOutboxAuthority) AuthorizeDispatch(context.Context, CandidateEvidenceScope) error {
	if a.revoked.Load() {
		return errors.New("fixture revoked")
	}
	return nil
}
func (a *syntheticOutboxAuthority) AuthorizeRelease(context.Context, CandidateEvidenceScope) error {
	if a.revoked.Load() {
		return errors.New("fixture revoked")
	}
	if a.releases.Add(1) == 1 && a.revokeAfterFirst.Load() {
		a.revoked.Store(true)
	}
	return nil
}

type syntheticOutboxAppender struct {
	journal *Journal
	calls   atomic.Int32
	lose    atomic.Bool
}

func (a *syntheticOutboxAppender) AppendExact(ctx context.Context, raw []byte) ([]byte, error) {
	a.calls.Add(1)
	var event Event
	if json.Unmarshal(raw, &event) != nil {
		return nil, errors.New("fixture invalid event")
	}
	proof, err := a.journal.AppendContext(ctx, event, nil)
	if err != nil {
		return nil, err
	}
	if a.lose.Swap(false) {
		return nil, errors.New("fixture response lost after append")
	}
	return json.Marshal(proof)
}

type syntheticOutboxVerifier struct{ public ed25519.PublicKey }

type syntheticFixedProofAppender struct{ proof []byte }

func (a syntheticFixedProofAppender) AppendExact(context.Context, []byte) ([]byte, error) {
	return append([]byte(nil), a.proof...), nil
}

func (v syntheticOutboxVerifier) VerifyExact(_ context.Context, raw, proofBytes []byte) error {
	var event Event
	var proof Proof
	if json.Unmarshal(raw, &event) != nil || json.Unmarshal(proofBytes, &proof) != nil || proof.Sequence < 1 || !VerifyEvent(v.public, proof, event) {
		return errors.New("fixture proof denied")
	}
	return nil
}

// The coordinator must create a fresh empty database and separate restricted
// login; this test never touches old databases or live evidence state.
func TestCandidateEvidenceOutboxPostgresRecovery(t *testing.T) {
	adminURL, roleURL := os.Getenv("NEX_EVIDENCE_OUTBOX_ADMIN_DSN"), os.Getenv("NEX_EVIDENCE_OUTBOX_ROLE_DSN")
	if adminURL == "" || roleURL == "" {
		t.Skip("fresh synthetic evidence database not configured")
	}
	if os.Getenv("NEX_EVIDENCE_OUTBOX_FIXTURE") != "disposable-only" {
		t.Fatal("explicit disposable fixture required")
	}
	for _, raw := range []string{adminURL, roleURL} {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || len(u.Query()["sslmode"]) != 1 || u.Query().Get("sslmode") != "verify-full" || len(u.Query()["sslrootcert"]) != 1 || u.Query().Get("sslrootcert") == "" {
			t.Fatal("verified fixture TLS URLs required")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	adminCfg, err := pgxpool.ParseConfig(adminURL)
	if err != nil || adminCfg.ConnConfig.TLSConfig == nil || adminCfg.ConnConfig.TLSConfig.InsecureSkipVerify {
		t.Fatal("invalid fixture admin TLS")
	}
	adminCfg.ConnConfig.Fallbacks = nil
	roleCfg, err := pgxpool.ParseConfig(roleURL)
	if err != nil || roleCfg.ConnConfig.TLSConfig == nil || roleCfg.ConnConfig.TLSConfig.InsecureSkipVerify {
		t.Fatal("invalid fixture service TLS")
	}
	roleCfg.ConnConfig.Fallbacks = nil
	admin, err := pgxpool.NewWithConfig(ctx, adminCfg)
	if err != nil {
		t.Fatal("fixture admin unavailable")
	}
	defer admin.Close()
	role, err := pgxpool.NewWithConfig(ctx, roleCfg)
	if err != nil {
		t.Fatal("fixture service unavailable")
	}
	defer role.Close()
	var db, adminName, roleDB, roleName string
	if admin.QueryRow(ctx, `SELECT current_database(),current_user`).Scan(&db, &adminName) != nil || role.QueryRow(ctx, `SELECT current_database(),current_user`).Scan(&roleDB, &roleName) != nil || !strings.HasPrefix(db, "nex_evidence_outbox_") || db != roleDB || !strings.HasPrefix(roleName, "nex_evidence_outbox_") || roleName == adminName {
		t.Fatal("non-disposable fixture database or login")
	}
	var empty, restricted, owner bool
	if admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT FROM pg_namespace WHERE nspname='nex_candidate_evidence')`).Scan(&empty) != nil || !empty {
		t.Fatal("fresh outbox schema required")
	}
	if admin.QueryRow(ctx, `SELECT NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=pg_roles.oid) FROM pg_roles WHERE rolname=$1`, roleName).Scan(&restricted) != nil || !restricted {
		t.Fatal("restricted fixture login required")
	}
	if admin.QueryRow(ctx, `SELECT d.datdba=r.oid FROM pg_database d JOIN pg_roles r ON r.rolname=$1 WHERE d.datname=current_database()`, roleName).Scan(&owner) != nil || owner {
		t.Fatal("fixture role must not own database")
	}
	schema, err := os.ReadFile("production_outbox.sql")
	if err != nil {
		t.Fatal("fixture schema unavailable")
	}
	if _, err = admin.Exec(ctx, string(schema)); err != nil {
		t.Fatal("fixture schema creation failed")
	}
	quoted := pgx.Identifier{roleName}.Sanitize()
	for _, q := range []string{`GRANT USAGE ON SCHEMA nex_candidate_evidence TO ` + quoted, `GRANT SELECT,INSERT ON nex_candidate_evidence.outbox TO ` + quoted, `GRANT UPDATE(state,proof_bytes) ON nex_candidate_evidence.outbox TO ` + quoted} {
		if _, err = admin.Exec(ctx, q); err != nil {
			t.Fatal("fixture grant failed")
		}
	}
	for _, column := range []string{"event_id", "tenant_id", "actor_id", "job_id", "resource_id", "resource_version", "delegation_id", "operation_id", "payload_digest", "context_digest", "event_bytes", "event_sha256"} {
		var allowed bool
		if role.QueryRow(ctx, `SELECT has_column_privilege(current_user,'nex_candidate_evidence.outbox',$1,'UPDATE')`, column).Scan(&allowed) != nil || allowed {
			t.Fatal("immutable outbox column writable")
		}
	}
	var canDelete bool
	if role.QueryRow(ctx, `SELECT has_table_privilege(current_user,'nex_candidate_evidence.outbox','DELETE')`).Scan(&canDelete) != nil || canDelete {
		t.Fatal("outbox deletion unexpectedly permitted")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	journal := &Journal{Directory: t.TempDir(), Private: private}
	appender := &syntheticOutboxAppender{journal: journal}
	authority := &syntheticOutboxAuthority{}
	fence := &syntheticOutboxFence{}
	store, err := NewCandidateEvidenceOutbox(role, fence, syntheticOutboxVerifier{public: public})
	if err != nil {
		t.Fatal(err)
	}
	scope, event := candidateEvidenceFixture()
	// A rolled-back candidate transaction leaves no dispatchable event.
	tx, err := role.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if store.Enqueue(ctx, tx, scope, event) != nil {
		t.Fatal("fixture enqueue failed")
	}
	if tx.Rollback(ctx) != nil {
		t.Fatal("fixture rollback failed")
	}
	if store.Dispatch(ctx, scope, authority, appender) == nil || appender.calls.Load() != 0 {
		t.Fatal("rolled-back event dispatched")
	}
	// A response lost after a successful append retries the exact bytes and ID;
	// the legacy journal returns its original proof without a second entry.
	tx, err = role.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if store.Enqueue(ctx, tx, scope, event) != nil || tx.Commit(ctx) != nil {
		t.Fatal("fixture event transaction failed")
	}
	appender.lose.Store(true)
	if store.Dispatch(ctx, scope, authority, appender) == nil || store.ReadyForRelease(ctx, scope, authority) == nil {
		t.Fatal("lost append response released data")
	}
	if store.Dispatch(ctx, scope, authority, appender) != nil || appender.calls.Load() != 2 {
		t.Fatal("identical event recovery failed")
	}
	entries, err := Verify(journal.Directory, public, nil)
	if err != nil || len(entries) != 1 {
		t.Fatal("recovery duplicated or damaged evidence")
	}
	if store.ReadyForRelease(ctx, scope, authority) != nil {
		t.Fatal("verified emitted event unavailable")
	}
	// A subsequent read observes the committed state and does not append again.
	// This does not simulate an ambiguous database commit response.
	if store.Dispatch(ctx, scope, authority, appender) != nil || appender.calls.Load() != 2 {
		t.Fatal("committed event was appended again")
	}
	// A service cannot authorize release with a forged signature or a valid
	// signature over different event bytes, even when the event ID matches.
	for _, tc := range []struct {
		id    string
		forge bool
	}{{"event-forged", true}, {"event-other", false}} {
		badScope, badEvent := candidateEvidenceFixture()
		badScope.EventID, badEvent.ID = tc.id, tc.id
		tx, err = role.Begin(ctx)
		if err != nil || store.Enqueue(ctx, tx, badScope, badEvent) != nil || tx.Commit(ctx) != nil {
			t.Fatal("proof fixture transaction failed")
		}
		signedEvent := badEvent
		if !tc.forge {
			signedEvent.Detail = json.RawMessage(strings.Replace(string(badEvent.Detail), `"provenance":{`, `"other":1,"provenance":{`, 1))
		}
		otherJournal := &Journal{Directory: t.TempDir(), Private: private}
		proof, err := otherJournal.AppendContext(ctx, signedEvent, nil)
		if err != nil {
			t.Fatal("proof fixture signing failed")
		}
		if tc.forge {
			proof.Signature = "forged"
		}
		proofBytes, err := json.Marshal(proof)
		if err != nil {
			t.Fatal("proof fixture encoding failed")
		}
		if store.Dispatch(ctx, badScope, authority, syntheticFixedProofAppender{proofBytes}) == nil || store.ReadyForRelease(ctx, badScope, authority) == nil {
			t.Fatal("invalid proof allowed dispatch or release")
		}
		var state string
		var storedProof []byte
		if role.QueryRow(ctx, `SELECT state,proof_bytes FROM nex_candidate_evidence.outbox WHERE event_id=$1`, tc.id).Scan(&state, &storedProof) != nil || state != "pending" || storedProof != nil {
			t.Fatal("invalid proof modified pending state")
		}
	}
	changed := event
	changed.Detail = json.RawMessage(strings.Replace(string(event.Detail), `"provenance":{`, `"other":1,"provenance":{`, 1))
	tx, err = role.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if store.Enqueue(ctx, tx, scope, changed) == nil {
		t.Fatal("same ID with changed event accepted")
	}
	_ = tx.Rollback(ctx)
	authority.releases.Store(0)
	authority.revokeAfterFirst.Store(true)
	if store.ReadyForRelease(ctx, scope, authority) == nil {
		t.Fatal("revoked session allowed release")
	}
	authority.revoked.Store(false)
	authority.revokeAfterFirst.Store(false)
	fence.blocked.Store(true)
	if store.Dispatch(ctx, scope, authority, appender) == nil || store.ReadyForRelease(ctx, scope, authority) == nil {
		t.Fatal("closed recovery fence allowed progress")
	}
	fence.blocked.Store(false)
	// Concurrent retries remain one immutable event and one proof.
	secondScope, secondEvent := candidateEvidenceFixture()
	secondScope.EventID = "event-002"
	secondEvent.ID = secondScope.EventID
	tx, err = role.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if store.Enqueue(ctx, tx, secondScope, secondEvent) != nil || tx.Commit(ctx) != nil {
		t.Fatal("second fixture transaction failed")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- store.Dispatch(ctx, secondScope, authority, appender) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal("concurrent idempotent dispatch failed")
		}
	}
	entries, err = Verify(journal.Directory, public, nil)
	if err != nil || len(entries) != 2 {
		t.Fatal("concurrent retry duplicated evidence")
	}
	files, err := filepath.Glob(filepath.Join(journal.Directory, "*.json"))
	if err != nil || len(files) != 2 {
		t.Fatal("unexpected synthetic journal files")
	}
}
