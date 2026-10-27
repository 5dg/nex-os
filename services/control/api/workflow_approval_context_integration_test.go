//go:build integration

package api

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
	"github.com/5dg/nex-os/packages/evidence"
	"github.com/5dg/nex-os/services/control/auth"
	"github.com/5dg/nex-os/services/control/devseed"
	"github.com/5dg/nex-os/services/control/guard"
	"github.com/5dg/nex-os/services/control/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This test isolates the request-export HTTP transition and its real signed
// event. The completed review row is a setup precondition; it does not stand in
// for the separate Rust preparation/authorization/completion proof suite.
func TestRequestedApprovalEvidenceUsesPersistedTransition(t *testing.T) {
	ctx := context.Background()
	database := os.Getenv("NEX_TEST_DATABASE_URL")
	if database == "" {
		t.Fatal("NEX_TEST_DATABASE_URL required")
	}
	admin, e := pgxpool.New(ctx, database)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close()
	schema := "approval_context_" + strings.ToLower(rand.Text())
	if _, e = admin.Exec(ctx, "CREATE SCHEMA "+schema); e != nil {
		t.Fatal(e)
	}
	defer admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
	config, e := pgxpool.ParseConfig(database)
	if e != nil {
		t.Fatal(e)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	db, e := pgxpool.NewWithConfig(ctx, config)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if e = migrations.Apply(ctx, db); e != nil {
		t.Fatal(e)
	}

	tokenKey, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	var issuer *httptest.Server
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/openid-configuration" {
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer.URL, "jwks_uri": issuer.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
			return
		}
		enc := base64.RawURLEncoding
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "approval-context", "use": "sig", "alg": "RS256", "n": enc.EncodeToString(tokenKey.N.Bytes()), "e": enc.EncodeToString(big.NewInt(int64(tokenKey.E)).Bytes())}}})
	}))
	defer issuer.Close()
	if e = devseed.Seed(ctx, db, issuer.URL); e != nil {
		t.Fatal(e)
	}
	if e = devseed.SeedWorkflow(ctx, db, issuer.URL); e != nil {
		t.Fatal(e)
	}
	verifier, e := auth.New(ctx, issuer.URL, "approval-context-api")
	if e != nil {
		t.Fatal(e)
	}
	token := func(subject string) string {
		t.Helper()
		claims, _ := json.Marshal(map[string]any{"iss": issuer.URL, "sub": subject, "aud": "approval-context-api", "exp": time.Now().Add(time.Minute).Unix()})
		enc := base64.RawURLEncoding
		body := enc.EncodeToString([]byte(`{"alg":"RS256","kid":"approval-context"}`)) + "." + enc.EncodeToString(claims)
		digest := sha256.Sum256([]byte(body))
		signature, e := rsa.SignPKCS1v15(rand.Reader, tokenKey, crypto.SHA256, digest[:])
		if e != nil {
			t.Fatal(e)
		}
		return body + "." + enc.EncodeToString(signature)
	}
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	writerKey := make([]byte, 32)
	if _, e = rand.Read(writerKey); e != nil {
		t.Fatal(e)
	}
	directory := filepath.Join(t.TempDir(), "journal")
	if e = os.MkdirAll(directory, 0700); e != nil {
		t.Fatal(e)
	}
	signer := httptest.NewServer(evidence.Handler(&evidence.Journal{Directory: directory, Private: private}, writerKey, make([]byte, 32)))
	defer signer.Close()
	opa := os.Getenv("NEX_TEST_OPA_URL")
	if opa == "" {
		opa = "http://127.0.0.1:8181"
	}
	s := &Server{DB: db, Auth: verifier, Policy: guard.New(opa), Environment: "development", EvidenceRPC: broker.NewClient(signer.URL+"/append/control", "evidence.append.control", writerKey), EvidencePublic: public}
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	job, reviewOperation := rand.Text(), rand.Text()
	if _, e = db.Exec(ctx, `INSERT INTO jobs(id,tenant_id,delegation_id,state,owner_id,document_id,document_version,question,operation_id,answer,provider) VALUES($1,'tenant-a','delegation-alice','completed','alice','review-alice','v1','synthetic question',$2,'synthetic completed answer','development')`, job, reviewOperation); e != nil {
		t.Fatal(e)
	}
	request := func(subject string, want int) []byte {
		t.Helper()
		r, e := http.NewRequest("POST", server.URL+"/v1/jobs/"+job+"/export", strings.NewReader(`{"destination_id":"local-evidence"}`))
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("Content-Type", "application/json")
		if subject != "" {
			r.Header.Set("Authorization", "Bearer "+token(subject))
		}
		response, e := server.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		body, e := io.ReadAll(io.LimitReader(response.Body, 16384))
		if e != nil {
			t.Fatal(e)
		}
		if response.StatusCode != want {
			t.Fatalf("%s HTTP=%d want=%d body=%s", subject, response.StatusCode, want, body)
		}
		return body
	}
	request("", 401)
	request("bob", 403)
	var approvals int
	if e = db.QueryRow(ctx, `SELECT count(*) FROM approvals WHERE job_id=$1`, job).Scan(&approvals); e != nil || approvals != 0 {
		t.Fatalf("denied request changed approvals: %d %v", approvals, e)
	}
	var response contracts.ApprovalView
	if e = json.Unmarshal(request("alice", 201), &response); e != nil {
		t.Fatal(e)
	}
	var state, newApproval, newOperation, digest string
	if e = db.QueryRow(ctx, `SELECT j.state,j.approval_id,j.operation_id,a.request_digest FROM jobs j JOIN approvals a ON a.id=j.approval_id AND a.tenant_id=j.tenant_id WHERE j.id=$1`, job).Scan(&state, &newApproval, &newOperation, &digest); e != nil {
		t.Fatal(e)
	}
	if state != "approval_required" || newApproval == "" || newApproval != response.ID || newOperation == "" || newOperation == reviewOperation || digest != response.RequestDigest || response.JobID != job {
		t.Fatalf("HTTP transition precondition failed: state=%s approval=%s operation=%s", state, newApproval, newOperation)
	}
	var event evidence.Event
	var detail, rawProof []byte
	var timestamp time.Time
	if e = db.QueryRow(ctx, `SELECT id,tenant_id,actor_id,job_id,resource_id,delegation_id,action,decision,created_at,integrity_reference FROM audit_events WHERE job_id=$1 AND action='approval.requested'`, job).Scan(&event.ID, &event.TenantID, &event.ActorID, &event.JobID, &event.ResourceID, &event.DelegationID, &event.Action, &detail, &timestamp, &rawProof); e != nil {
		t.Fatal(e)
	}
	event.Detail = detail
	event.Timestamp = timestamp.UnixMicro()
	event.Producer = "control"
	var proof evidence.Proof
	if e = json.Unmarshal(rawProof, &proof); e != nil {
		t.Fatal(e)
	}
	if !evidence.VerifyEvent(public, proof, event) {
		t.Fatal("positive precondition: requested-approval event must have a valid real signature")
	}
	if event.TenantID != "tenant-a" || event.ActorID != "alice" || event.JobID != job || event.ResourceID != "review-alice" || event.DelegationID != "delegation-alice" {
		t.Fatal("event ownership changed", event.ID)
	}
	var context map[string]string
	if e = json.Unmarshal(detail, &context); e != nil {
		t.Fatal(e)
	}
	if context["job_id"] != job || context["approval_id"] != newApproval || context["operation_id"] != newOperation {
		t.Fatalf("signed approval.requested context is stale: job=%q want=%q approval=%q want=%q operation=%q want=%q previous_review=%q", context["job_id"], job, context["approval_id"], newApproval, context["operation_id"], newOperation, reviewOperation)
	}
}
