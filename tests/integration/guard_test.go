//go:build integration

package integration

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/5dg/nex-os/policies"
	"github.com/5dg/nex-os/services/control/api"
	"github.com/5dg/nex-os/services/control/auth"
	"github.com/5dg/nex-os/services/control/devseed"
	"github.com/5dg/nex-os/services/control/guard"
	"github.com/5dg/nex-os/services/control/migrations"
	"github.com/5dg/nex-os/services/model"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestGovernance(t *testing.T) {
	ctx := context.Background()
	database := os.Getenv("NEX_TEST_DATABASE_URL")
	if database == "" {
		t.Fatal("NEX_TEST_DATABASE_URL required: start local dependencies; no integration tests were skipped")
	}
	admin, err := pgxpool.New(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "test_" + strings.ToLower(rand.Text())
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
	config, err := pgxpool.ParseConfig(database)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = migrations.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err = migrations.Apply(ctx, db); err != nil {
		t.Fatalf("migration repeat: %v", err)
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	var issuer *httptest.Server
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/openid-configuration" {
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer.URL, "jwks_uri": issuer.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
			return
		}
		e := base64.RawURLEncoding
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "test", "use": "sig", "alg": "RS256", "n": e.EncodeToString(key.N.Bytes()), "e": e.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	}))
	defer issuer.Close()
	if err = devseed.Seed(ctx, db, issuer.URL); err != nil {
		t.Fatal(err)
	}
	if err = devseed.Seed(ctx, db, issuer.URL); err != nil {
		t.Fatal(err)
	}
	var count int
	db.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&count)
	if count != 2 {
		t.Fatalf("seed duplicated users: %d", count)
	}
	verifier, err := auth.New(ctx, issuer.URL, "test-audience")
	if err != nil {
		t.Fatal(err)
	}
	opa := os.Getenv("NEX_TEST_OPA_URL")
	if opa == "" {
		opa = "http://127.0.0.1:8181"
	}
	s := &api.Server{DB: db, Auth: verifier, Policy: guard.New(opa), Model: model.Development{}, Environment: "development"}
	parentTest := t
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	token := func(subject string, changes map[string]any, signer *rsa.PrivateKey) string {
		t.Helper()
		claims := map[string]any{"iss": issuer.URL, "sub": subject, "aud": "test-audience", "exp": time.Now().Add(time.Minute).Unix()}
		for k, v := range changes {
			claims[k] = v
		}
		b, _ := json.Marshal(claims)
		enc := base64.RawURLEncoding
		body := enc.EncodeToString([]byte(`{"alg":"RS256","kid":"test"}`)) + "." + enc.EncodeToString(b)
		d := sha256.Sum256([]byte(body))
		sig, err := rsa.SignPKCS1v15(rand.Reader, signer, crypto.SHA256, d[:])
		if err != nil {
			t.Fatal(err)
		}
		return body + "." + enc.EncodeToString(sig)
	}
	alice := token("alice", nil, key)
	bob := token("bob", nil, key)
	call := func(path, tok, body string, want int) map[string]any {
		t.Helper()
		r, _ := http.NewRequest("POST", server.URL+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		response, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		b, _ := io.ReadAll(response.Body)
		if response.StatusCode != want {
			t.Fatalf("status %d, want %d: %s", response.StatusCode, want, b)
		}
		var out map[string]any
		if err = json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	request := func(delegation, action, resource string) string {
		b, _ := json.Marshal(map[string]string{"delegation_id": delegation, "action": action, "resource_id": resource})
		return string(b)
	}
	for _, tt := range []struct {
		name, tok, delegation, action, resource, effect string
		status                                          int
	}{
		{"permit tenant A", alice, "delegation-alice", "document.read", "document-alice", "allow", 200},
		{"permit tenant B", bob, "delegation-bob", "document.read", "document-bob", "allow", 200},
		{"deny cross tenant A to B", alice, "delegation-alice", "document.read", "document-bob", "deny", 403},
		{"deny cross tenant B to A", bob, "delegation-bob", "document.read", "document-alice", "deny", 403},
		{"deny borrowed delegation", alice, "delegation-bob", "document.read", "document-alice", "deny", 403},
		{"deny unknown action", alice, "delegation-alice", "shell.execute", "document-alice", "deny", 403},
		{"deny restricted", alice, "delegation-alice", "document.read", "restricted-alice", "deny", 403},
		{"require approval", alice, "delegation-alice", "document.export", "document-alice", "require_approval", 200},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out := call("/v1/actions/authorize", tt.tok, request(tt.delegation, tt.action, tt.resource), tt.status)
			if out["effect"] != tt.effect || out["policy_digest"] != guard.Digest() {
				t.Fatalf("unexpected decision: %v", out)
			}
			var n int
			if err := db.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE id=$1", out["decision_id"]).Scan(&n); err != nil || n != 1 {
				t.Fatalf("missing audit record: %v %d", err, n)
			}
		})
	}
	good := request("delegation-alice", "document.read", "document-alice")
	for _, tt := range []struct{ name, tok string }{
		{"missing token", ""},
		{"expired token", token("alice", map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}, key)},
		{"wrong audience", token("alice", map[string]any{"aud": "other"}, key)},
		{"wrong issuer", token("alice", map[string]any{"iss": "https://untrusted.invalid"}, key)},
	} {
		t.Run(tt.name, func(t *testing.T) { call("/v1/actions/authorize", tt.tok, good, 401) })
	}
	t.Run("wrong signature", func(t *testing.T) {
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		call("/v1/actions/authorize", token("alice", nil, other), good, 401)
	})
	t.Run("unregistered identity", func(t *testing.T) { call("/v1/actions/authorize", token("outsider", nil, key), good, 403) })
	t.Run("tenant claim ignored", func(t *testing.T) {
		call("/v1/actions/authorize", token("alice", map[string]any{"tenant_id": "tenant-b", "permissions": []string{"*"}}, key), request("delegation-alice", "document.read", "document-bob"), 403)
	})
	for _, field := range []string{`"tenant_id":"tenant-b"`, `"actor":{"id":"bob"}`, `"approval_valid":true`} {
		t.Run("reject forged "+field, func(t *testing.T) {
			call("/v1/actions/authorize", alice, strings.TrimSuffix(good, "}")+","+field+"}", 400)
		})
	}
	for _, tt := range []struct{ name, sql, restore string }{
		{"revoked delegation", `UPDATE delegations SET revoked_at=now() WHERE id='delegation-alice'`, `UPDATE delegations SET revoked_at=NULL WHERE id='delegation-alice'`},
		{"expired delegation", `UPDATE delegations SET expires_at=now()-interval '1 minute' WHERE id='delegation-alice'`, `UPDATE delegations SET expires_at=now()+interval '1 day' WHERE id='delegation-alice'`},
		{"permission removed", `UPDATE users SET permissions='{}' WHERE id='alice'`, `UPDATE users SET permissions=ARRAY['document.read','document.export','model.invoke'] WHERE id='alice'`},
		{"delegation scope removed", `UPDATE delegations SET permissions='{}' WHERE id='delegation-alice'`, `UPDATE delegations SET permissions=ARRAY['document.read','document.export','model.invoke'] WHERE id='delegation-alice'`},
		{"document ACL removed", `UPDATE resources SET reader_ids='{}' WHERE id='document-alice'`, `UPDATE resources SET reader_ids=ARRAY['alice'] WHERE id='document-alice'`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := db.Exec(ctx, tt.sql); err != nil {
				t.Fatal(err)
			}
			defer db.Exec(ctx, tt.restore)
			call("/v1/actions/authorize", alice, good, 403)
		})
	}
	t.Run("policy unavailable", func(t *testing.T) {
		saved := s.Policy
		s.Policy = guard.New("http://127.0.0.1:1")
		defer func() { s.Policy = saved }()
		call("/v1/actions/authorize", alice, good, 503)
	})
	t.Run("malformed policy result", func(t *testing.T) {
		fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				json.NewEncoder(w).Encode(map[string]any{"result": []any{map[string]any{"raw": string(policies.Source)}}})
			} else {
				fmt.Fprint(w, `{"result":{"effect":"allow"}}`)
			}
		}))
		defer fake.Close()
		saved := s.Policy
		s.Policy = guard.New(fake.URL)
		defer func() { s.Policy = saved }()
		call("/v1/actions/authorize", alice, good, 503)
	})
	t.Run("policy source mismatch", func(t *testing.T) {
		fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"result":[{"raw":"altered policy"}]}`) }))
		defer fake.Close()
		saved := s.Policy
		s.Policy = guard.New(fake.URL)
		defer func() { s.Policy = saved }()
		call("/v1/actions/authorize", alice, good, 503)
	})
	t.Run("audit unavailable", func(t *testing.T) {
		if _, err := db.Exec(ctx, "ALTER TABLE audit_events RENAME TO unavailable_events"); err != nil {
			t.Fatal(err)
		}
		defer db.Exec(ctx, "ALTER TABLE unavailable_events RENAME TO audit_events")
		call("/v1/actions/authorize", alice, good, 503)
	})
	t.Run("development model is explicit", func(t *testing.T) {
		out := call("/v1/models/invoke", alice, `{"delegation_id":"delegation-alice","resource_id":"dev-model","prompt":"SYNTHETIC_SECRET_MARKER","max_output_tokens":64}`, 200)
		if out["provider"] != "development" || !strings.Contains(out["text"].(string), "No Bedrock") {
			t.Fatal(out)
		}
		var found bool
		db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_events WHERE decision::text LIKE '%SYNTHETIC_SECRET_MARKER%')`).Scan(&found)
		if found {
			t.Fatal("prompt leaked into audit")
		}
	})
	t.Run("model delegation mismatch", func(t *testing.T) {
		call("/v1/models/invoke", bob, `{"delegation_id":"delegation-alice","resource_id":"dev-model","prompt":"synthetic","max_output_tokens":64}`, 403)
	})
	t.Run("trailing JSON rejected", func(t *testing.T) { call("/v1/actions/authorize", alice, good+good, 400) })
	t.Run("oversized body rejected", func(t *testing.T) {
		call("/v1/actions/authorize", alice, `{"action":"`+strings.Repeat("x", 9000)+`"}`, 400)
	})
	t.Run("seed preserves changed permissions", func(t *testing.T) {
		if _, err := db.Exec(ctx, `UPDATE users SET permissions='{}' WHERE id='alice'`); err != nil {
			t.Fatal(err)
		}
		defer db.Exec(ctx, `UPDATE users SET permissions=ARRAY['document.read','document.export','model.invoke'] WHERE id='alice'`)
		if err := devseed.Seed(ctx, db, issuer.URL); err != nil {
			t.Fatal(err)
		}
		call("/v1/actions/authorize", alice, good, 403)
	})
	t.Run("lease fencing survives service restart", func(t *testing.T) {
		if e := devseed.SeedWorkflow(ctx, db, issuer.URL); e != nil {
			t.Fatal(e)
		}
		s.WorkerKey = make([]byte, 32)
		rand.Read(s.WorkerKey)
		workerToken := base64.RawURLEncoding.EncodeToString(s.WorkerKey)
		created := call("/v1/jobs", alice, `{"delegation_id":"delegation-alice","document_id":"review-alice","question":"Synthetic recovery check","idempotency_key":"recovery-check-001"}`, 202)
		first := call("/internal/work/claim", workerToken, `{}`, 200)
		if first["job_id"] != created["id"] {
			t.Fatal("wrong queued job claimed")
		}
		server.Close()
		server = httptest.NewServer(s.Handler())
		parentTest.Cleanup(server.Close)
		if _, e := db.Exec(ctx, `UPDATE jobs SET lease_until=now()-interval '1 second' WHERE id=$1`, created["id"]); e != nil {
			t.Fatal(e)
		}
		second := call("/internal/work/claim", workerToken, `{}`, 200)
		if second["job_id"] != first["job_id"] || second["lease_token"] == first["lease_token"] {
			t.Fatal("expired work was not recovered with a new lease")
		}
		body, _ := json.Marshal(first)
		call("/internal/work/"+created["id"].(string)+"/step", workerToken, string(body), 409)
	})
	t.Run("explicit approval decision required", func(t *testing.T) {
		call("/v1/approvals/unused-reference/decision", alice, `{"request_digest":"known"}`, 400)
		call("/v1/approvals/unused-reference/decision", alice, `{"approve":null,"request_digest":"known"}`, 400)
	})
	t.Run("migration checksum protected", func(t *testing.T) {
		if _, err := db.Exec(ctx, `UPDATE schema_migrations SET checksum='tampered'`); err != nil {
			t.Fatal(err)
		}
		if err := migrations.Apply(ctx, db); err == nil {
			t.Fatal("changed migration checksum accepted")
		}
	})
}
