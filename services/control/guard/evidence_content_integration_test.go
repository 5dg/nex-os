//go:build integration

package guard_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/evidence"
	"github.com/5dg/nex-os/services/control/devseed"
	guardclient "github.com/5dg/nex-os/services/control/guard"
	"github.com/5dg/nex-os/services/control/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestRustRejectsValidSignatureForDifferentEvidenceContent uses the common
// Writer.append path through a real development-profile Rust process. Transport
// is explicitly the retained development fixture; this is not a qualification
// TLS test or a claim that an untrusted signer can obtain a trusted signing key.
func TestRustRejectsValidSignatureForDifferentEvidenceContent(t *testing.T) {
	database := os.Getenv("NEX_TEST_DATABASE_URL")
	if database == "" {
		t.Fatal("NEX_TEST_DATABASE_URL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, database)
	if err != nil {
		t.Fatal("fixture administrator connection unavailable")
	}
	defer admin.Close()
	schema := "proof_content_" + strings.ToLower(rand.Text())
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal("cannot create disposable proof fixture schema")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Error("cannot remove owned disposable proof fixture schema")
		}
	}()
	config, err := pgxpool.ParseConfig(database)
	if err != nil {
		t.Fatal("invalid private fixture database configuration")
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("fixture database pool unavailable")
	}
	defer db.Close()
	if err = migrations.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err = devseed.Seed(ctx, db, "http://synthetic-issuer"); err != nil {
		t.Fatal(err)
	}
	if err = devseed.SeedWorkflow(ctx, db, "http://synthetic-issuer"); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(database)
	if err != nil {
		t.Fatal("invalid private fixture database URI")
	}
	query := parsed.Query()
	query.Set("options", "-csearch_path="+schema)
	parsed.RawQuery = query.Encode()
	directory := t.TempDir()
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal("cannot write ephemeral fixture identity")
		}
		return path
	}
	key := func() []byte {
		t.Helper()
		data := make([]byte, 32)
		if _, err := rand.Read(data); err != nil {
			t.Fatal(err)
		}
		return data
	}
	modelKey, exportKey, writerKey := key(), key(), key()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	journal := &evidence.Journal{Directory: filepath.Join(directory, "journal"), Private: private}
	var alterAuthorization atomic.Bool
	var authenticWrongContentProofs atomic.Int32
	var exactProofs atomic.Int32
	signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path != "/append/kernel" {
			http.NotFound(w, r)
			return
		}
		var submitted evidence.Event
		if !broker.ReadLimit(w, r, writerKey, "evidence.append.kernel", &submitted, 128*1024) {
			return
		}
		submitted.Producer = "kernel"
		signed := submitted
		wrong := alterAuthorization.Load() && submitted.Action == "model.authorized"
		if wrong {
			// Keep event ID and producer exactly as submitted, but sign a distinct
			// event using the legitimate pinned key and normal v1 journal writer.
			signed.Action = "different.synthetic.event"
		}
		proof, err := journal.Append(signed)
		if err != nil || !evidence.VerifyEvent(public, proof, signed) {
			t.Error("fixture failed to produce a genuine content-bound v1 proof")
			http.Error(w, "fixture signing failure", 500)
			return
		}
		if wrong {
			if !evidence.VerifyProof(public, proof) || evidence.VerifyEvent(public, proof, submitted) || proof.EventID != submitted.ID || proof.Producer != submitted.Producer {
				t.Error("fixture did not isolate signed wrong content from signature/identity failures")
				http.Error(w, "fixture signing failure", 500)
				return
			}
			authenticWrongContentProofs.Add(1)
		} else {
			exactProofs.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proof)
	}))
	defer signer.Close()
	opa := os.Getenv("NEX_TEST_OPA_URL")
	if opa == "" {
		opa = "http://127.0.0.1:8181"
	}
	control, address, _ := startExecutionKernel(t, opa, []string{
		"NEX_PROFILE=development", "DATABASE_URL=" + parsed.String(),
		"MODEL_GUARD_KEY_FILE=" + write("model-key", modelKey), "EXPORT_GUARD_KEY_FILE=" + write("export-key", exportKey),
		"EVIDENCE_URL=" + signer.URL, "EVIDENCE_KEY_FILE=" + write("writer-key", writerKey), "EVIDENCE_PUBLIC_FILE=" + write("writer-public", public),
	})
	model, err := guardclient.NewRPC(address, modelKey, true)
	if err != nil {
		t.Fatal(err)
	}
	defer model.Close()
	prepare := func() (job, operation, digest string) {
		t.Helper()
		job, operation = rand.Text(), rand.Text()
		_, err := db.Exec(ctx, `INSERT INTO jobs(id,tenant_id,owner_id,delegation_id,state,phase,document_id,document_version,question,operation_id,lease_token,lease_until) VALUES($1,'tenant-a','alice','delegation-alice','running','review','review-alice','v1','What access review and export controls apply?',$2,'fixture-lease',clock_timestamp()+interval '5 minutes')`, job, operation)
		if err != nil {
			t.Fatal("cannot create untouched synthetic review fixture")
		}
		payload, digest, err := control.PrepareExecution(ctx, job, operation)
		if err != nil || len(payload) == 0 || digest == "" {
			t.Fatalf("positive real Rust preparation failed: %v", err)
		}
		return job, operation, digest
	}
	_, validOperation, validDigest := prepare()
	if allowed, err := model.AuthorizeExecution(ctx, validOperation, validDigest); err != nil || !allowed {
		t.Fatalf("positive exact-content proof did not grant through real Rust: allowed=%v error=%v", allowed, err)
	}
	var positiveState string
	if err := db.QueryRow(ctx, `SELECT status FROM execution_operations WHERE id=$1`, validOperation).Scan(&positiveState); err != nil || positiveState != "started" {
		t.Fatal("positive control did not commit a real started grant")
	}
	job, operation, digest := prepare()
	alterAuthorization.Store(true)
	allowed, authorizationErr := model.AuthorizeExecution(ctx, operation, digest)
	var state string
	var resultAbsent bool
	var committedAuthorizationEvents int
	if err := db.QueryRow(ctx, `SELECT status,result IS NULL,(SELECT count(*) FROM audit_events WHERE job_id=$2 AND action='model.authorized') FROM execution_operations WHERE id=$1`, operation, job).Scan(&state, &resultAbsent, &committedAuthorizationEvents); err != nil {
		t.Fatal("cannot inspect authoritative operation after signed wrong-content response")
	}
	if authenticWrongContentProofs.Load() != 1 || exactProofs.Load() < 3 {
		t.Fatalf("fixture path missing: genuine wrong-content proofs=%d exact proofs=%d", authenticWrongContentProofs.Load(), exactProofs.Load())
	}
	alterAuthorization.Store(false)
	_, healthyOperation, healthyDigest := prepare()
	if healthy, err := model.AuthorizeExecution(ctx, healthyOperation, healthyDigest); err != nil || !healthy {
		t.Fatalf("exact-content positive after negative was unavailable: allowed=%v error=%v", healthy, err)
	}
	if allowed || authorizationErr == nil || state != "pending" || !resultAbsent || committedAuthorizationEvents != 0 {
		t.Fatalf("valid signature for different content retained authority: allowed=%v error=%v status=%s result_absent=%v committed_authorization_events=%d; want error, pending operation, no authorization event", allowed, authorizationErr, state, resultAbsent, committedAuthorizationEvents)
	}
	// No model/export receiver is called by this test. A rejected proof must
	// roll back the authorization transition, not invent a provider outcome.
}
