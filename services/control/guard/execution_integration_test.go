//go:build integration

package guard_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
	"github.com/5dg/nex-os/packages/evidence"
	"github.com/5dg/nex-os/services/control/devseed"
	guardclient "github.com/5dg/nex-os/services/control/guard"
	"github.com/5dg/nex-os/services/control/migrations"
	modelservice "github.com/5dg/nex-os/services/model"
	exportservice "github.com/5dg/nex-os/services/tool-executor"
	"github.com/jackc/pgx/v5/pgxpool"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRustExecutionState(t *testing.T) {
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
	schema := "kernel_" + strings.ToLower(rand.Text())
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
	if e = devseed.Seed(ctx, db, "http://synthetic-issuer"); e != nil {
		t.Fatal(e)
	}
	if e = devseed.SeedWorkflow(ctx, db, "http://synthetic-issuer"); e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(database)
	if e != nil {
		t.Fatal(e)
	}
	q := u.Query()
	q.Set("options", "-csearch_path="+schema)
	u.RawQuery = q.Encode()
	modelKey := make([]byte, 32)
	rand.Read(modelKey)
	exportKey := make([]byte, 32)
	rand.Read(exportKey)
	writerKey := make([]byte, 32)
	rand.Read(writerKey)
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	directory := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(directory, name)
		if e := os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	journal := &evidence.Journal{Directory: filepath.Join(directory, "journal"), Private: private}
	writer := evidence.Handler(journal, make([]byte, 32), writerKey)
	var available atomic.Bool
	var signerDelay atomic.Int64
	var delayedSignatures atomic.Int32
	available.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !available.Load() {
			http.Error(w, "unavailable", 503)
			return
		}
		if r.URL.Path == "/append/kernel" {
			if delay := time.Duration(signerDelay.Load()); delay > 0 {
				delayedSignatures.Add(1)
				time.Sleep(delay)
			}
		}
		writer.ServeHTTP(w, r)
	}))
	defer server.Close()
	control, address, _ := startExecutionKernel(t, "http://127.0.0.1:8181", []string{"DATABASE_URL=" + u.String(), "MODEL_GUARD_KEY_FILE=" + write("model", modelKey), "EXPORT_GUARD_KEY_FILE=" + write("export", exportKey), "EVIDENCE_URL=" + server.URL, "EVIDENCE_KEY_FILE=" + write("writer", writerKey), "EVIDENCE_PUBLIC_FILE=" + write("public", public)})
	model, e := guardclient.NewRPC(address, modelKey, true)
	if e != nil {
		t.Fatal(e)
	}
	defer model.Close()
	executor, e := guardclient.NewRPC(address, exportKey, true)
	if e != nil {
		t.Fatal(e)
	}
	defer executor.Close()
	type operation struct{ job, approval, id, digest, binding string }
	makeCase := func(t *testing.T, kind string, approved bool) operation {
		t.Helper()
		x := operation{job: rand.Text(), approval: rand.Text(), id: rand.Text(), digest: broker.Hash([]byte(rand.Text()))}
		expires := time.Now().UTC().Truncate(time.Second).Add(5 * time.Minute)
		var documentHash string
		if e := db.QueryRow(ctx, `SELECT content_digest FROM document_bodies WHERE tenant_id='tenant-a' AND resource_id='review-alice'`).Scan(&documentHash); e != nil {
			t.Fatal(e)
		}
		fields := []string{x.approval, x.job, "tenant-a", "alice", "delegation-alice", "document.export", "review-alice", "v1", documentHash, broker.Hash([]byte("synthetic answer")), "local-evidence", guardclient.Digest(), strconv.FormatInt(expires.Unix(), 10)}
		b := []byte("nex.export.v1\x00")
		for _, field := range fields {
			b = binary.BigEndian.AppendUint64(b, uint64(len([]byte(field))))
			b = append(b, []byte(field)...)
		}
		x.binding = broker.Hash(b)
		state, phase := "running", "export"
		if kind == "model" {
			phase = "review"
		}
		if !approved {
			state = "approval_required"
			phase = "review"
		}
		_, e := db.Exec(ctx, `INSERT INTO jobs(id,tenant_id,owner_id,delegation_id,state,phase,document_id,document_version,question,answer,operation_id,approval_id,lease_token,lease_until) VALUES($1,'tenant-a','alice','delegation-alice',$2,$3,'review-alice','v1','synthetic question','synthetic answer',$4,$5,'test-lease',now()+interval '5 minutes')`, x.job, state, phase, x.id, x.approval)
		if e != nil {
			t.Fatal(e)
		}
		_, e = db.Exec(ctx, `INSERT INTO approvals(id,tenant_id,job_id,request_digest,destination_id,expires_at,policy_digest,approved_at,approver_id) VALUES($1,'tenant-a',$2,$3,'local-evidence',$4,$5,CASE WHEN $6 THEN now() ELSE NULL END,CASE WHEN $6 THEN 'carol' ELSE NULL END)`, x.approval, x.job, x.binding, expires, guardclient.Digest(), approved)
		if e != nil {
			t.Fatal(e)
		}

		if kind == "export" && approved {
			// Establish real Rust-validated model provenance before export.
			reviewOperation := rand.Text()
			_, e = db.Exec(ctx, `UPDATE jobs SET state='running',phase='review',operation_id=$2,answer='' WHERE id=$1`, x.job, reviewOperation)
			if e != nil {
				t.Fatal(e)
			}
			_, reviewDigest, e := control.PrepareExecution(ctx, x.job, reviewOperation)
			if e != nil {
				t.Fatal(e)
			}
			if ok, e := model.AuthorizeExecution(ctx, reviewOperation, reviewDigest); e != nil || !ok {
				t.Fatal(e)
			}
			if e := model.CompleteExecution(ctx, reviewOperation, reviewDigest, contracts.GenerationResult{Text: "synthetic answer", Provider: "development", ModelID: "deterministic-review-v1"}); e != nil {
				t.Fatal(e)
			}
			_, e = db.Exec(ctx, `UPDATE jobs SET state='running',phase='export',operation_id=$2 WHERE id=$1`, x.job, x.id)
			if e != nil {
				t.Fatal(e)
			}
		}
		if approved {
			_, x.digest, e = control.PrepareExecution(ctx, x.job, x.id)
		} else {
			_, e = db.Exec(ctx, `INSERT INTO execution_operations(id,tenant_id,job_id,kind,request_digest) VALUES($1,'tenant-a',$2,$3,$4)`, x.id, x.job, kind, x.digest)
		}
		if e != nil {
			t.Fatal(e)
		}

		return x
	}
	sql := func(statement string, args ...any) {
		t.Helper()
		if _, e := db.Exec(ctx, statement, args...); e != nil {
			t.Fatal(e)
		}
	}
	assertDenied := func(t *testing.T, client *guardclient.Client, x operation) {
		t.Helper()
		allowed, e := client.AuthorizeExecution(ctx, x.id, x.digest)
		if allowed || !errors.Is(e, guardclient.ErrDenied) {
			t.Fatalf("expected denial, got %v %v", allowed, e)
		}
	}
	loadGeneration := func(t *testing.T, x operation) contracts.Generation {
		t.Helper()
		var raw []byte
		if e := db.QueryRow(ctx, `SELECT payload FROM execution_manifests WHERE operation_id=$1`, x.id).Scan(&raw); e != nil {
			t.Fatal(e)
		}
		var in contracts.Generation
		if e := json.Unmarshal(raw, &in); e != nil {
			t.Fatal(e)
		}
		return in
	}
	loadExport := func(t *testing.T, x operation) contracts.Export {
		t.Helper()
		var raw []byte
		if e := db.QueryRow(ctx, `SELECT payload FROM execution_manifests WHERE operation_id=$1`, x.id).Scan(&raw); e != nil {
			t.Fatal(e)
		}
		var in contracts.Export
		if e := json.Unmarshal(raw, &in); e != nil {
			t.Fatal(e)
		}
		return in
	}
	t.Run("receiver denies substituted model bytes before provider", func(t *testing.T) {
		x := makeCase(t, "model", true)
		in := loadGeneration(t, x)
		in.Prompt = "substituted provider instructions"
		// Even a producer-selected matching digest cannot replace the sealed payload.
		sql(`UPDATE execution_operations SET request_digest=$2 WHERE id=$1`, x.id, contracts.ExecutionDigest(in))
		var calls atomic.Int32
		service := &modelservice.Service{Key: modelKey, Validate: model, Receipts: broker.ReceiptStore{Directory: t.TempDir()}, Generator: testGenerator(func(context.Context, contracts.Generation) (contracts.GenerationResult, error) {
			calls.Add(1)
			return contracts.GenerationResult{}, nil
		})}
		receiver := httptest.NewServer(service.Handler())
		defer receiver.Close()
		var out contracts.GenerationResult
		if e := broker.NewClient(receiver.URL+"/execute", "model.execute", modelKey).Call(ctx, in, &out); !errors.Is(e, broker.ErrNotStarted) && !errors.Is(e, broker.ErrUnknown) {
			t.Fatal("substitution was not denied with a typed conservative outcome", e)
		}
		if calls.Load() != 0 {
			t.Fatal("unapproved model callback ran")
		}
		var status string
		if e := db.QueryRow(ctx, `SELECT status FROM execution_operations WHERE id=$1`, x.id).Scan(&status); e != nil || status != "pending" {
			t.Fatal("substitution changed operation state", status, e)
		}
	})
	t.Run("receiver denies substituted export bytes before artifact", func(t *testing.T) {
		x := makeCase(t, "export", true)
		in := loadExport(t, x)
		in.Content = "different unapproved artifact"
		sql(`UPDATE execution_operations SET request_digest=$2 WHERE id=$1`, x.id, contracts.ExecutionDigest(in))
		receipts := broker.ReceiptStore{Directory: t.TempDir()}
		receiver := httptest.NewServer((&exportservice.Service{Key: exportKey, Validate: executor, Receipts: receipts}).Handler())
		defer receiver.Close()
		var out contracts.ExportResult
		if e := broker.NewClient(receiver.URL+"/execute", "export.execute", exportKey).Call(ctx, in, &out); !errors.Is(e, broker.ErrNotStarted) && !errors.Is(e, broker.ErrUnknown) {
			t.Fatal("substitution was not denied with a typed conservative outcome", e)
		}
		if raw, e := receipts.Inspect(x.id, contracts.ExecutionDigest(in)); len(raw) != 0 || !errors.Is(e, broker.ErrNotStarted) && !errors.Is(e, broker.ErrUnknown) {
			t.Fatal("substitution produced an accessible artifact", e)
		}
		var consumed bool
		if e := db.QueryRow(ctx, `SELECT consumed_at IS NOT NULL FROM approvals WHERE id=$1`, x.approval).Scan(&consumed); e != nil || consumed {
			t.Fatal("substitution consumed approval", e)
		}
	})
	t.Run("receiver exports exact sealed content and reconciles from receipt", func(t *testing.T) {
		x := makeCase(t, "export", true)
		in := loadExport(t, x)
		receipts := broker.ReceiptStore{Directory: t.TempDir()}
		receiver := httptest.NewServer((&exportservice.Service{Key: exportKey, Validate: executor, Receipts: receipts}).Handler())
		defer receiver.Close()
		var first contracts.ExportResult
		if e := broker.NewClient(receiver.URL+"/execute", "export.execute", exportKey).Call(ctx, in, &first); e != nil {
			t.Fatal(e)
		}
		if first.ArtifactID != x.id || first.ContentDigest != broker.Hash([]byte(in.Content)) {
			t.Fatal("content differs from sealed preview", first)
		}
		raw, e := receipts.Inspect(x.id, contracts.ExecutionDigest(in))
		if e != nil {
			t.Fatal(e)
		}
		var artifact struct {
			Content string `json:"content"`
		}
		if e := json.Unmarshal(raw, &artifact); e != nil || artifact.Content != in.Content {
			t.Fatal("durable artifact differs", e)
		}
		restarted := httptest.NewServer((&exportservice.Service{Key: exportKey, Validate: executor, Receipts: broker.ReceiptStore{Directory: receipts.Directory}}).Handler())
		defer restarted.Close()
		var recovered contracts.ExportResult
		if e := broker.NewClient(restarted.URL+"/status", "export.execute", exportKey).Call(ctx, in, &recovered); e != nil || recovered != first {
			t.Fatal("receipt reconciliation failed", e)
		}
		var count int
		if e := db.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE job_id=$1 AND action='export.authorized'`, x.job).Scan(&count); e != nil || count != 1 {
			t.Fatal("duplicate authorization", count, e)
		}
	})

	t.Run("escaped 12KiB result completes signs approves and exports exact bytes", func(t *testing.T) {
		x := makeCase(t, "model", true)
		generation := loadGeneration(t, x)
		// U+0001 is valid PostgreSQL text and expands to six JSON bytes. NUL is
		// deliberately excluded because PostgreSQL text cannot represent it.
		expected := contracts.GenerationResult{Text: strings.Repeat("\x01", 12000), Provider: "development", ModelID: "deterministic-review-v1"}
		modelReceiver := httptest.NewServer((&modelservice.Service{Key: modelKey, Validate: model, Receipts: broker.ReceiptStore{Directory: t.TempDir()}, Generator: testGenerator(func(context.Context, contracts.Generation) (contracts.GenerationResult, error) { return expected, nil })}).Handler())
		defer modelReceiver.Close()
		var result contracts.GenerationResult
		if e := broker.NewClient(modelReceiver.URL+"/execute", "model.execute", modelKey).Call(ctx, generation, &result); e != nil || result != expected {
			t.Fatal("maximum escaped model result failed", e)
		}
		var documentHash string
		var expires time.Time
		if e := db.QueryRow(ctx, `SELECT content_digest FROM document_bodies WHERE tenant_id='tenant-a' AND resource_id='review-alice'`).Scan(&documentHash); e != nil {
			t.Fatal(e)
		}
		if e := db.QueryRow(ctx, `SELECT expires_at FROM approvals WHERE id=$1`, x.approval).Scan(&expires); e != nil {
			t.Fatal(e)
		}
		fields := []string{x.approval, x.job, "tenant-a", "alice", "delegation-alice", "document.export", "review-alice", "v1", documentHash, broker.Hash([]byte(expected.Text)), "local-evidence", guardclient.Digest(), strconv.FormatInt(expires.Unix(), 10)}
		b := []byte("nex.export.v1\x00")
		for _, field := range fields {
			b = binary.BigEndian.AppendUint64(b, uint64(len([]byte(field))))
			b = append(b, []byte(field)...)
		}
		binding := broker.Hash(b)
		exportOperation := rand.Text()
		sql(`UPDATE approvals SET approved_at=NULL,approver_id=NULL,request_digest=$2 WHERE id=$1`, x.approval, binding)
		sql(`UPDATE jobs SET state='approval_required',operation_id=$2 WHERE id=$1`, x.job, exportOperation)
		if allowed, e := control.DecideApproval(ctx, x.approval, binding, "carol", "tenant-a", true); e != nil || !allowed {
			t.Fatal("maximum result approval failed", e)
		}
		sql(`UPDATE jobs SET state='running',lease_until=clock_timestamp()+interval '5 minutes' WHERE id=$1`, x.job)
		payload, digest, e := control.PrepareExecution(ctx, x.job, exportOperation)
		if e != nil {
			t.Fatal("maximum result export preparation failed", e)
		}
		var in contracts.Export
		if e := json.Unmarshal(payload, &in); e != nil {
			t.Fatal(e)
		}
		if in.Content != expected.Text+"\n\nSource: review-alice@v1" || contracts.ExecutionDigest(in) != digest {
			t.Fatal("prepared export changed escaped bytes")
		}
		receipts := broker.ReceiptStore{Directory: t.TempDir()}
		exportReceiver := httptest.NewServer((&exportservice.Service{Key: exportKey, Validate: executor, Receipts: receipts}).Handler())
		defer exportReceiver.Close()
		var artifact contracts.ExportResult
		if e := broker.NewClient(exportReceiver.URL+"/execute", "export.execute", exportKey).Call(ctx, in, &artifact); e != nil || artifact.ContentDigest != broker.Hash([]byte(in.Content)) {
			t.Fatal("maximum escaped export failed", e)
		}
		var count int
		if e := db.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE job_id=$1 AND action IN ('model.completed','export.completed') AND integrity_reference IS NOT NULL`, x.job).Scan(&count); e != nil || count != 2 {
			t.Fatal("maximum result outcome evidence missing", count, e)
		}
	})

	t.Run("receiver rejects tampered durable export content before completion", func(t *testing.T) {
		x := makeCase(t, "export", true)
		in := loadExport(t, x)
		digest := contracts.ExecutionDigest(in)
		receipts := broker.ReceiptStore{Directory: t.TempDir()}
		if _, e := receipts.DoAuthorized(x.id, digest, func() error {
			allowed, e := executor.AuthorizeExecution(ctx, x.id, digest)
			if e != nil {
				return e
			}
			if !allowed {
				return guardclient.ErrDenied
			}
			return nil
		}, func() (any, error) {
			return map[string]string{"artifact_id": x.id, "content_digest": broker.Hash([]byte(in.Content)), "content": in.Content}, nil
		}); e != nil {
			t.Fatal(e)
		}
		// A valid JSON record can still contain corrupt artifact bytes. Preserve the
		// claimed content digest to ensure the receiver verifies the actual content.
		path := filepath.Join(receipts.Directory, x.id+".state")
		raw, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		var state map[string]json.RawMessage
		if e := json.Unmarshal(raw, &state); e != nil {
			t.Fatal(e)
		}
		var artifact map[string]string
		if e := json.Unmarshal(state["result"], &artifact); e != nil {
			t.Fatal(e)
		}
		artifact["content"] = "tampered durable artifact"
		state["result"], e = json.Marshal(artifact)
		if e != nil {
			t.Fatal(e)
		}
		raw, e = json.Marshal(state)
		if e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
		receiver := httptest.NewServer((&exportservice.Service{Key: exportKey, Validate: executor, Receipts: receipts}).Handler())
		defer receiver.Close()
		var out contracts.ExportResult
		if e := broker.NewClient(receiver.URL+"/status", "export.execute", exportKey).Call(ctx, in, &out); !errors.Is(e, broker.ErrUnknown) {
			t.Fatal("tampered artifact was reported as valid", e)
		}
		var completed bool
		if e := db.QueryRow(ctx, `SELECT status='completed' FROM execution_operations WHERE id=$1`, x.id).Scan(&completed); e != nil || completed {
			t.Fatal("tampered artifact committed completion", e)
		}
	})
	t.Run("receiver signing denial is not started and same operation can retry", func(t *testing.T) {
		x := makeCase(t, "model", true)
		in := loadGeneration(t, x)
		var calls atomic.Int32
		expected := contracts.GenerationResult{Text: "synthetic retry result", Provider: "development", ModelID: "deterministic-review-v1"}
		receipts := broker.ReceiptStore{Directory: t.TempDir()}
		receiver := httptest.NewServer((&modelservice.Service{Key: modelKey, Validate: model, Receipts: receipts, Generator: testGenerator(func(context.Context, contracts.Generation) (contracts.GenerationResult, error) {
			calls.Add(1)
			return expected, nil
		})}).Handler())
		defer receiver.Close()
		defer available.Store(true)
		client := broker.NewClient(receiver.URL+"/execute", "model.execute", modelKey)
		var out contracts.GenerationResult
		available.Store(false)
		if e := client.Call(ctx, in, &out); !errors.Is(e, broker.ErrNotStarted) {
			t.Fatal("pre-effect signing failure was not identified", e)
		}
		if calls.Load() != 0 {
			t.Fatal("provider called without signed authority")
		}
		var status string
		if e := db.QueryRow(ctx, `SELECT status FROM execution_operations WHERE id=$1`, x.id).Scan(&status); e != nil || status != "pending" {
			t.Fatal("denial poisoned operation", status, e)
		}
		available.Store(true)
		if e := client.Call(ctx, in, &out); e != nil || out != expected {
			t.Fatal("same operation did not retry safely", e)
		}
		if calls.Load() != 1 {
			t.Fatal("provider call count", calls.Load())
		}
	})
	t.Run("durable receiver outcome survives signing outage without repeating provider", func(t *testing.T) {
		x := makeCase(t, "model", true)
		in := loadGeneration(t, x)
		receipts := broker.ReceiptStore{Directory: t.TempDir()}
		var calls atomic.Int32
		expected := contracts.GenerationResult{Text: "synthetic durable receiver result", Provider: "development", ModelID: "deterministic-review-v1"}
		generator := testGenerator(func(context.Context, contracts.Generation) (contracts.GenerationResult, error) {
			calls.Add(1)
			available.Store(false)
			return expected, nil
		})
		receiver := httptest.NewServer((&modelservice.Service{Key: modelKey, Validate: model, Receipts: receipts, Generator: generator}).Handler())
		defer receiver.Close()
		defer available.Store(true)
		var out contracts.GenerationResult
		if e := broker.NewClient(receiver.URL+"/execute", "model.execute", modelKey).Call(ctx, in, &out); !errors.Is(e, broker.ErrUnknown) {
			t.Fatal("completion signing outage should be unknown", e)
		}
		if calls.Load() != 1 {
			t.Fatal("provider call count", calls.Load())
		}
		var status string
		if e := db.QueryRow(ctx, `SELECT status FROM execution_operations WHERE id=$1`, x.id).Scan(&status); e != nil || status != "started" {
			t.Fatal("uncommitted completion state", status, e)
		}
		if _, e := receipts.Inspect(x.id, contracts.ExecutionDigest(in)); e != nil {
			t.Fatal("durable result missing", e)
		}
		available.Store(true)
		restarted := httptest.NewServer((&modelservice.Service{Key: modelKey, Validate: model, Receipts: broker.ReceiptStore{Directory: receipts.Directory}, Generator: generator}).Handler())
		defer restarted.Close()
		if e := broker.NewClient(restarted.URL+"/status", "model.execute", modelKey).Call(ctx, in, &out); e != nil || out != expected {
			t.Fatal("failed to report durable receipt", e)
		}
		if e := broker.NewClient(restarted.URL+"/execute", "model.execute", modelKey).Call(ctx, in, &out); e != nil {
			t.Fatal("completed receipt replay failed", e)
		}
		if calls.Load() != 1 {
			t.Fatal("provider repeated during reconciliation", calls.Load())
		}
		var result json.RawMessage
		if e := db.QueryRow(ctx, `SELECT status,result FROM execution_operations WHERE id=$1`, x.id).Scan(&status, &result); e != nil || status != "completed" {
			t.Fatal("completion did not reconcile", status, e)
		}
		var recorded contracts.GenerationResult
		if e := json.Unmarshal(result, &recorded); e != nil || recorded != expected {
			t.Fatal("protected result differs", e)
		}
		var count int
		if e := db.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE job_id=$1 AND action='model.completed'`, x.job).Scan(&count); e != nil || count != 1 {
			t.Fatal("completion evidence duplicated", count, e)
		}
	})
	t.Run("unknown receiver effect is never repeated or falsely completed", func(t *testing.T) {
		x := makeCase(t, "model", true)
		in := loadGeneration(t, x)
		var calls atomic.Int32
		receipts := broker.ReceiptStore{Directory: t.TempDir()}
		generator := testGenerator(func(context.Context, contracts.Generation) (contracts.GenerationResult, error) {
			calls.Add(1)
			return contracts.GenerationResult{}, errors.New("provider disconnected after possible effect")
		})
		receiver := httptest.NewServer((&modelservice.Service{Key: modelKey, Validate: model, Receipts: receipts, Generator: generator}).Handler())
		defer receiver.Close()
		var out contracts.GenerationResult
		if e := broker.NewClient(receiver.URL+"/execute", "model.execute", modelKey).Call(ctx, in, &out); !errors.Is(e, broker.ErrUnknown) {
			t.Fatal(e)
		}
		restarted := httptest.NewServer((&modelservice.Service{Key: modelKey, Validate: model, Receipts: broker.ReceiptStore{Directory: receipts.Directory}, Generator: generator}).Handler())
		defer restarted.Close()
		for _, path := range []string{"/execute", "/status"} {
			if e := broker.NewClient(restarted.URL+path, "model.execute", modelKey).Call(ctx, in, &out); !errors.Is(e, broker.ErrUnknown) {
				t.Fatal("unknown effect not preserved", path, e)
			}
		}
		if calls.Load() != 1 {
			t.Fatal("provider repeated uncertain effect", calls.Load())
		}
		var completed bool
		if e := db.QueryRow(ctx, `SELECT status='completed' FROM execution_operations WHERE id=$1`, x.id).Scan(&completed); e != nil || completed {
			t.Fatal("unknown result falsely completed", e)
		}
	})

	t.Run("matching producer digest cannot authorize unrelated payload", func(t *testing.T) {
		x := makeCase(t, "export", true)
		x.digest = broker.Hash([]byte("substituted producer payload"))
		sql(`UPDATE execution_operations SET request_digest=$2 WHERE id=$1`, x.id, x.digest)
		assertDenied(t, executor, x)
		var consumed bool
		if e := db.QueryRow(ctx, `SELECT consumed_at IS NOT NULL FROM approvals WHERE id=$1`, x.approval).Scan(&consumed); e != nil || consumed {
			t.Fatal("unrelated payload consumed approval", e)
		}
	})

	for _, field := range []string{"content", "tenant_id", "destination_id", "request_digest"} {
		t.Run("export substitution "+field, func(t *testing.T) {
			x := makeCase(t, "export", true)
			var raw []byte
			if e := db.QueryRow(ctx, `SELECT payload FROM execution_manifests WHERE operation_id=$1`, x.id).Scan(&raw); e != nil {
				t.Fatal(e)
			}
			var in contracts.Export
			if e := json.Unmarshal(raw, &in); e != nil {
				t.Fatal(e)
			}
			switch field {
			case "content":
				in.Content = "unapproved bytes"
			case "tenant_id":
				in.TenantID = "tenant-b"
			case "destination_id":
				in.DestinationID = "other"
			case "request_digest":
				in.RequestDigest = "other"
			}
			x.digest = contracts.ExecutionDigest(in)
			sql(`UPDATE execution_operations SET request_digest=$2 WHERE id=$1`, x.id, x.digest)
			assertDenied(t, executor, x)
			var consumed bool
			db.QueryRow(ctx, `SELECT consumed_at IS NOT NULL FROM approvals WHERE id=$1`, x.approval).Scan(&consumed)
			if consumed {
				t.Fatal("substitution consumed approval")
			}
		})
	}
	for _, field := range []string{"prompt", "route_id", "max_tokens", "classification", "tenant_id"} {
		t.Run("model substitution "+field, func(t *testing.T) {
			x := makeCase(t, "model", true)
			var raw []byte
			if e := db.QueryRow(ctx, `SELECT payload FROM execution_manifests WHERE operation_id=$1`, x.id).Scan(&raw); e != nil {
				t.Fatal(e)
			}
			var in contracts.Generation
			if e := json.Unmarshal(raw, &in); e != nil {
				t.Fatal(e)
			}
			switch field {
			case "prompt":
				in.Prompt = "arbitrary instructions"
			case "route_id":
				in.RouteID = "other"
			case "max_tokens":
				in.MaxTokens = 10000
			case "classification":
				in.Classification = "public"
			case "tenant_id":
				in.TenantID = "tenant-b"
			}
			x.digest = contracts.ExecutionDigest(in)
			sql(`UPDATE execution_operations SET request_digest=$2 WHERE id=$1`, x.id, x.digest)
			assertDenied(t, model, x)
		})
	}
	t.Run("legacy operation cannot be upgraded", func(t *testing.T) {
		x := makeCase(t, "export", true)
		// Retain a valid pending operation and approval with no sealed manifest,
		// as on pre-v2 history. Denial must not rely on invalid job authority.
		sql(`DELETE FROM execution_manifests WHERE operation_id=$1`, x.id)
		if _, _, e := control.PrepareExecution(ctx, x.job, x.id); !errors.Is(e, guardclient.ErrDenied) {
			t.Fatal("legacy operation upgraded", e)
		}
		var count int
		if e := db.QueryRow(ctx, `SELECT count(*) FROM execution_manifests WHERE operation_id=$1`, x.id).Scan(&count); e != nil || count != 0 {
			t.Fatal("legacy history received a retroactive manifest", e)
		}
	})

	t.Run("executor cannot prepare", func(t *testing.T) {
		x := makeCase(t, "export", true)
		if _, _, e := executor.PrepareExecution(ctx, x.job, x.id); e == nil {
			t.Fatal("executor prepared operation")
		}
	})
	t.Run("started operation cannot authorize a second effect", func(t *testing.T) {
		x := makeCase(t, "export", true)
		if ok, e := executor.AuthorizeExecution(ctx, x.id, x.digest); e != nil || !ok {
			t.Fatal(e)
		}
		assertDenied(t, executor, x)
	})
	t.Run("authenticated outcome is idempotent and protected", func(t *testing.T) {
		x := makeCase(t, "export", true)
		if ok, e := executor.AuthorizeExecution(ctx, x.id, x.digest); e != nil || !ok {
			t.Fatal(e)
		}
		result := contracts.ExportResult{ArtifactID: x.id, ContentDigest: broker.Hash([]byte("synthetic answer\n\nSource: review-alice@v1"))}
		if e := control.CompleteExecution(ctx, x.id, x.digest, result); e == nil {
			t.Fatal("control forged outcome")
		}
		if e := model.CompleteExecution(ctx, x.id, x.digest, result); e == nil {
			t.Fatal("wrong service forged outcome")
		}
		if e := executor.CompleteExecution(ctx, x.id, x.digest, result); e != nil {
			t.Fatal(e)
		}
		if e := executor.CompleteExecution(ctx, x.id, x.digest, result); e != nil {
			t.Fatal("repeat completion", e)
		}
		result.ContentDigest = "different"
		if e := executor.CompleteExecution(ctx, x.id, x.digest, result); e == nil {
			t.Fatal("outcome rewritten")
		}
	})
	t.Run("exact export and signed kernel evidence", func(t *testing.T) {
		x := makeCase(t, "export", true)
		ok, e := executor.AuthorizeExecution(ctx, x.id, x.digest)
		if e != nil || !ok {
			t.Fatalf("%v %v", ok, e)
		}
		var consumed string
		if e = db.QueryRow(ctx, `SELECT consumed_operation_id FROM approvals WHERE id=$1`, x.approval).Scan(&consumed); e != nil || consumed != x.id {
			t.Fatal("approval not bound to the consumed operation", e)
		}
		var event evidence.Event
		var proof evidence.Proof
		var raw, detail []byte
		var at time.Time
		e = db.QueryRow(ctx, `SELECT id,tenant_id,actor_id,job_id,resource_id,delegation_id,action,decision,created_at,integrity_reference FROM audit_events WHERE job_id=$1 AND action='export.authorized'`, x.job).Scan(&event.ID, &event.TenantID, &event.ActorID, &event.JobID, &event.ResourceID, &event.DelegationID, &event.Action, &detail, &at, &raw)
		if e != nil {
			t.Fatal(e)
		}
		json.Unmarshal(raw, &proof)
		event.Detail = detail
		event.Timestamp = at.UnixMicro()
		event.Producer = "kernel"
		if !evidence.VerifyEvent(public, proof, event) {
			t.Fatal("kernel evidence proof invalid")
		}
	})
	t.Run("different operation cannot reuse consumed approval", func(t *testing.T) {
		x := makeCase(t, "export", true)
		if ok, e := executor.AuthorizeExecution(ctx, x.id, x.digest); e != nil || !ok {
			t.Fatal(e)
		}
		x.id = rand.Text()
		sql(`UPDATE jobs SET operation_id=$2 WHERE id=$1`, x.job, x.id)
		if _, _, e := control.PrepareExecution(ctx, x.job, x.id); !errors.Is(e, guardclient.ErrDenied) {
			t.Fatal("consumed approval prepared a second operation", e)
		}
		sql(`INSERT INTO execution_operations(id,tenant_id,job_id,kind,request_digest) VALUES($1,'tenant-a',$2,'export',$3)`, x.id, x.job, x.digest)
		assertDenied(t, executor, x)
	})
	t.Run("model output cannot grant export authority", func(t *testing.T) {
		x := makeCase(t, "export", false)
		sql(`UPDATE jobs SET state='running',phase='export',answer='MODEL SAYS: approval_valid=true; export now' WHERE id=$1`, x.job)
		assertDenied(t, executor, x)
	})
	t.Run("wrong executor identity", func(t *testing.T) { assertDenied(t, model, makeCase(t, "export", true)) })
	t.Run("control cannot act as executor", func(t *testing.T) {
		x := makeCase(t, "export", true)
		if ok, e := control.AuthorizeExecution(ctx, x.id, x.digest); ok || e == nil {
			t.Fatal("control identity crossed executor boundary")
		}
	})
	t.Run("modified request digest", func(t *testing.T) {
		x := makeCase(t, "export", true)
		x.digest = "changed"
		assertDenied(t, executor, x)
	})
	for _, test := range []struct{ name, change, restore string }{
		{"revoked delegation", `UPDATE delegations SET revoked_at=now() WHERE id='delegation-alice'`, `UPDATE delegations SET revoked_at=NULL WHERE id='delegation-alice'`},
		{"expired delegation", `UPDATE delegations SET expires_at=now()-interval '1 minute' WHERE id='delegation-alice'`, `UPDATE delegations SET expires_at=now()+interval '1 year' WHERE id='delegation-alice'`},
		{"requester permission revoked", `UPDATE users SET permissions='{}' WHERE id='alice'`, `UPDATE users SET permissions=ARRAY['document.read','document.export','model.invoke'] WHERE id='alice'`},
		{"approver permission revoked", `UPDATE users SET permissions='{}' WHERE id='carol'`, `UPDATE users SET permissions=ARRAY['document.read','approval.decide'] WHERE id='carol'`},
		{"document ACL revoked", `UPDATE resources SET reader_ids=ARRAY['carol'] WHERE id='review-alice'`, `UPDATE resources SET reader_ids=ARRAY['alice','carol'] WHERE id='review-alice'`},
		{"document version changed", `UPDATE resources SET version='v2' WHERE id='review-alice'`, `UPDATE resources SET version='v1' WHERE id='review-alice'`},
		{"document integrity failed", `UPDATE document_bodies SET content_digest='invalid' WHERE resource_id='review-alice'`, `UPDATE document_bodies SET content_digest=$1 WHERE resource_id='review-alice'`},
		{"destination disabled", `UPDATE export_destinations SET enabled=false WHERE tenant_id='tenant-a'`, `UPDATE export_destinations SET enabled=true WHERE tenant_id='tenant-a'`},
	} {
		t.Run(test.name, func(t *testing.T) {
			x := makeCase(t, "export", true)
			var savedHash string
			db.QueryRow(ctx, `SELECT content_digest FROM document_bodies WHERE resource_id='review-alice'`).Scan(&savedHash)
			sql(test.change)
			defer func() {
				if strings.Contains(test.restore, "$1") {
					sql(test.restore, savedHash)
				} else {
					sql(test.restore)
				}
			}()
			assertDenied(t, executor, x)
		})
	}
	for _, test := range []struct{ name, change string }{{"approval expired", `UPDATE approvals SET expires_at=now()-interval '1 minute' WHERE id=$1`}, {"approval binding altered", `UPDATE approvals SET request_digest='altered' WHERE id=$1`}, {"policy version changed", `UPDATE approvals SET policy_digest='old' WHERE id=$1`}, {"answer changed after approval", `UPDATE jobs SET answer='modified' WHERE approval_id=$1`}} {
		t.Run(test.name, func(t *testing.T) {
			x := makeCase(t, "export", true)
			sql(test.change, x.approval)
			assertDenied(t, executor, x)
		})
	}

	for _, which := range []string{"another job", "another tenant", "same job review"} {
		t.Run("approval evidence retains current context with "+which+" manifest", func(t *testing.T) {
			x := makeCase(t, "export", true)
			var proposed string
			switch which {
			case "another job":
				proposed = makeCase(t, "model", true).id
			case "same job review":
				if e := db.QueryRow(ctx, `SELECT review_operation_id FROM jobs WHERE id=$1`, x.job).Scan(&proposed); e != nil {
					t.Fatal(e)
				}
			case "another tenant":
				proposed = rand.Text()
				foreignJob := rand.Text()
				sql(`INSERT INTO jobs(id,tenant_id,owner_id,delegation_id,state,phase,document_id,document_version,question,operation_id,lease_token,lease_until) VALUES($1,'tenant-b','bob','delegation-bob','running','review','review-bob','v1','synthetic question',$2,'test-lease',clock_timestamp()+interval '5 minutes')`, foreignJob, proposed)
				if _, _, e := control.PrepareExecution(ctx, foreignJob, proposed); e != nil {
					t.Fatal(e)
				}
			}
			// The trusted adapter may make a scheduling mistake. Approval evidence
			// must use its validated current job, never a manifest selected by that
			// mutable scheduler field, even when the manifest belongs to this job.
			sql(`UPDATE approvals SET approved_at=NULL,approver_id=NULL WHERE id=$1`, x.approval)
			sql(`UPDATE jobs SET state='approval_required',phase='review',operation_id=$2 WHERE id=$1`, x.job, proposed)
			if allowed, e := control.DecideApproval(ctx, x.approval, x.binding, "carol", "tenant-a", true); e != nil || !allowed {
				t.Fatalf("valid current approval failed: %v %v", allowed, e)
			}
			var event evidence.Event
			var proof evidence.Proof
			var raw, detail []byte
			var at time.Time
			e := db.QueryRow(ctx, `SELECT id,tenant_id,actor_id,job_id,resource_id,delegation_id,action,decision,created_at,integrity_reference FROM audit_events WHERE job_id=$1 AND action='approval.decided'`, x.job).Scan(&event.ID, &event.TenantID, &event.ActorID, &event.JobID, &event.ResourceID, &event.DelegationID, &event.Action, &detail, &at, &raw)
			if e != nil {
				t.Fatal("current approval event missing or attributed to foreign job", e)
			}
			if event.TenantID != "tenant-a" || event.ActorID != "carol" || event.JobID != x.job || event.ResourceID != "review-alice" || event.DelegationID != "delegation-alice" {
				t.Fatalf("misattributed current approval event: %+v", event)
			}
			var fields map[string]any
			if e := json.Unmarshal(detail, &fields); e != nil {
				t.Fatal(e)
			}
			if fields["approval_id"] != x.approval || fields["approval_digest"] != x.binding || fields["job_id"] != x.job || fields["document_id"] != "review-alice" || fields["document_version"] != "v1" || fields["provenance"] != nil {
				t.Fatalf("approval borrowed unrelated execution context: %s", detail)
			}
			if e := json.Unmarshal(raw, &proof); e != nil {
				t.Fatal(e)
			}
			event.Detail = detail
			event.Timestamp = at.UnixMicro()
			event.Producer = "kernel"
			if !evidence.VerifyEvent(public, proof, event) {
				t.Fatal("current approval proof invalid")
			}
			// A valid approval is not authority to execute an unrelated operation.
			sql(`UPDATE jobs SET state='running',phase='export',lease_until=clock_timestamp()+interval '5 minutes' WHERE id=$1`, x.job)
			if _, _, e := control.PrepareExecution(ctx, x.job, proposed); e == nil {
				t.Fatal("unrelated execution manifest was reused")
			}
			in := loadExport(t, x)
			in.OperationID = proposed
			if allowed, e := executor.AuthorizeExecution(ctx, proposed, contracts.ExecutionDigest(in)); allowed || e == nil {
				t.Fatal("unrelated execution authorized", allowed, e)
			}
			var consumed bool
			if e := db.QueryRow(ctx, `SELECT consumed_at IS NOT NULL FROM approvals WHERE id=$1`, x.approval).Scan(&consumed); e != nil || consumed {
				t.Fatal("unrelated manifest consumed current approval", e)
			}
		})
	}
	t.Run("concurrent human decisions consume once", func(t *testing.T) {
		x := makeCase(t, "export", false)
		var successes atomic.Int32
		var group sync.WaitGroup
		for i := 0; i < 2; i++ {
			group.Add(1)
			go func() {
				defer group.Done()
				if ok, e := control.DecideApproval(ctx, x.approval, x.binding, "carol", "tenant-a", true); e == nil && ok {
					successes.Add(1)
				}
			}()
		}
		group.Wait()
		if successes.Load() != 1 {
			t.Fatalf("accepted %d decisions", successes.Load())
		}
	})
	t.Run("self approval rejected", func(t *testing.T) {
		x := makeCase(t, "export", false)
		if ok, e := control.DecideApproval(ctx, x.approval, x.binding, "alice", "tenant-a", true); ok || !errors.Is(e, guardclient.ErrDenied) {
			t.Fatal("self approval accepted", e)
		}
	})
	t.Run("cross tenant approver rejected", func(t *testing.T) {
		x := makeCase(t, "export", false)
		if ok, e := control.DecideApproval(ctx, x.approval, x.binding, "dave", "tenant-a", true); ok || !errors.Is(e, guardclient.ErrDenied) {
			t.Fatal("cross tenant approval accepted", e)
		}
	})
	t.Run("unapproved model classification", func(t *testing.T) {
		x := makeCase(t, "model", true)
		sql(`UPDATE model_routes SET approved_classifications=ARRAY['public'] WHERE tenant_id='tenant-a'`)
		defer sql(`UPDATE model_routes SET approved_classifications=ARRAY['public','internal','confidential'] WHERE tenant_id='tenant-a'`)
		assertDenied(t, model, x)
	})

	t.Run("stale model result cannot approve changed source at same version", func(t *testing.T) {
		x := makeCase(t, "export", true)
		var original, originalDigest string
		var expires time.Time
		if e := db.QueryRow(ctx, `SELECT content,content_digest FROM document_bodies WHERE tenant_id='tenant-a' AND resource_id='review-alice'`).Scan(&original, &originalDigest); e != nil {
			t.Fatal(e)
		}
		if e := db.QueryRow(ctx, `SELECT expires_at FROM approvals WHERE id=$1`, x.approval).Scan(&expires); e != nil {
			t.Fatal(e)
		}
		changed := original + "\nSource changed without version bump."
		changedDigest := broker.Hash([]byte(changed))
		sql(`UPDATE document_bodies SET content=$1,content_digest=$2 WHERE tenant_id='tenant-a' AND resource_id='review-alice'`, changed, changedDigest)
		defer sql(`UPDATE document_bodies SET content=$1,content_digest=$2 WHERE tenant_id='tenant-a' AND resource_id='review-alice'`, original, originalDigest)
		fields := []string{x.approval, x.job, "tenant-a", "alice", "delegation-alice", "document.export", "review-alice", "v1", changedDigest, broker.Hash([]byte("synthetic answer")), "local-evidence", guardclient.Digest(), strconv.FormatInt(expires.Unix(), 10)}
		b := []byte("nex.export.v1\x00")
		for _, field := range fields {
			b = binary.BigEndian.AppendUint64(b, uint64(len([]byte(field))))
			b = append(b, []byte(field)...)
		}
		sql(`UPDATE approvals SET request_digest=$2 WHERE id=$1`, x.approval, broker.Hash(b))
		fresh := rand.Text()
		sql(`UPDATE jobs SET operation_id=$2 WHERE id=$1`, x.job, fresh)
		if _, _, e := control.PrepareExecution(ctx, x.job, fresh); !errors.Is(e, guardclient.ErrDenied) {
			t.Fatal("stale review result authorized changed source", e)
		}
	})
	t.Run("lease expiry during signing rolls back authorization", func(t *testing.T) {
		x := makeCase(t, "export", true)
		sql(`UPDATE jobs SET lease_until=clock_timestamp()+interval '1 second' WHERE id=$1`, x.job)
		delayedSignatures.Store(0)
		signerDelay.Store(int64(1500 * time.Millisecond))
		defer signerDelay.Store(0)
		if allowed, e := executor.AuthorizeExecution(ctx, x.id, x.digest); allowed || e == nil {
			t.Fatal("expired authority accepted after delayed signing")
		}
		if delayedSignatures.Load() == 0 {
			t.Fatal("test did not reach signing while the lease was valid")
		}
		var consumed bool
		var status string
		if e := db.QueryRow(ctx, `SELECT a.consumed_at IS NOT NULL,o.status FROM approvals a JOIN execution_operations o ON o.job_id=a.job_id AND o.id=$2 WHERE a.id=$1`, x.approval, x.id).Scan(&consumed, &status); e != nil || consumed || status != "pending" {
			t.Fatal("expired operation was committed", consumed, status, e)
		}
	})
	t.Run("late completion evidence retains original operation", func(t *testing.T) {
		x := makeCase(t, "model", true)
		if allowed, e := model.AuthorizeExecution(ctx, x.id, x.digest); e != nil || !allowed {
			t.Fatal(e)
		}
		replacement := rand.Text()
		sql(`UPDATE jobs SET operation_id=$2,state='cancelled' WHERE id=$1`, x.job, replacement)
		result := contracts.GenerationResult{Text: "late synthetic completion", Provider: "development", ModelID: "deterministic-review-v1"}
		if e := model.CompleteExecution(ctx, x.id, x.digest, result); e != nil {
			t.Fatal(e)
		}
		var recorded string
		var proof []byte
		if e := db.QueryRow(ctx, `SELECT decision->>'operation_id',integrity_reference FROM audit_events WHERE job_id=$1 AND action='model.completed'`, x.job).Scan(&recorded, &proof); e != nil || recorded != x.id {
			t.Fatal("completion attributed to replacement operation", recorded, e)
		}
		var state, answer string
		if e := db.QueryRow(ctx, `SELECT state,answer FROM jobs WHERE id=$1`, x.job).Scan(&state, &answer); e != nil || state != "cancelled" || answer == result.Text {
			t.Fatal("late completion resurrected or rewrote another operation", state, e)
		}
	})

	t.Run("late export completion retains original approval context", func(t *testing.T) {
		x := makeCase(t, "export", true)
		in := loadExport(t, x)
		if allowed, e := executor.AuthorizeExecution(ctx, x.id, x.digest); e != nil || !allowed {
			t.Fatal(e)
		}
		replacement := rand.Text()
		sql(`UPDATE jobs SET operation_id=$2,approval_id=NULL,state='cancelled' WHERE id=$1`, x.job, replacement)
		result := contracts.ExportResult{ArtifactID: x.id, ContentDigest: broker.Hash([]byte(in.Content))}
		if e := executor.CompleteExecution(ctx, x.id, x.digest, result); e != nil {
			t.Fatal(e)
		}
		var recorded, approval, digest string
		if e := db.QueryRow(ctx, `SELECT decision->>'operation_id',decision->>'approval_id',decision->>'approval_digest' FROM audit_events WHERE job_id=$1 AND action='export.completed'`, x.job).Scan(&recorded, &approval, &digest); e != nil || recorded != x.id || approval != x.approval || digest != x.binding {
			t.Fatal("completion attributed to mutable replacement context", recorded, approval, digest, e)
		}
		var state, artifact string
		if e := db.QueryRow(ctx, `SELECT state,export_id FROM jobs WHERE id=$1`, x.job).Scan(&state, &artifact); e != nil || state != "cancelled" || artifact != "" {
			t.Fatal("late completion resurrected or rewrote another operation", state, e)
		}
	})
	t.Run("signed evidence outage rolls back consumption", func(t *testing.T) {
		x := makeCase(t, "export", true)
		available.Store(false)
		defer available.Store(true)
		if ok, e := executor.AuthorizeExecution(ctx, x.id, x.digest); ok || e == nil {
			t.Fatal("audit outage permitted execution")
		}
		var consumed bool
		db.QueryRow(ctx, `SELECT consumed_at IS NOT NULL FROM approvals WHERE id=$1`, x.approval).Scan(&consumed)
		if consumed {
			t.Fatal("approval consumed without required audit evidence")
		}
	})
	t.Run("audit database failure rolls back consumption", func(t *testing.T) {
		x := makeCase(t, "export", true)
		sql(`ALTER TABLE audit_events RENAME TO unavailable_events`)
		defer sql(`ALTER TABLE unavailable_events RENAME TO audit_events`)
		if ok, e := executor.AuthorizeExecution(ctx, x.id, x.digest); ok || e == nil {
			t.Fatal("audit database outage permitted execution")
		}
		var consumed bool
		db.QueryRow(ctx, `SELECT consumed_at IS NOT NULL FROM approvals WHERE id=$1`, x.approval).Scan(&consumed)
		if consumed {
			t.Fatal("approval consumed without committed evidence")
		}
	})
}

type testGenerator func(context.Context, contracts.Generation) (contracts.GenerationResult, error)

func (f testGenerator) Generate(ctx context.Context, in contracts.Generation) (contracts.GenerationResult, error) {
	return f(ctx, in)
}

// This external-package fixture permits testing real receiver services without
// an import cycle through their guard client dependency.
func startExecutionKernel(t *testing.T, opa string, extra []string) (*guardclient.Client, string, []byte) {
	t.Helper()
	binary := os.Getenv("NEX_TEST_GUARD_BINARY")
	if binary == "" {
		t.Fatal("NEX_TEST_GUARD_BINARY required")
	}
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		t.Fatal(e)
	}
	keyPath := filepath.Join(t.TempDir(), "control-key")
	if e := os.WriteFile(keyPath, key, 0600); e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := listener.Addr().String()
	listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, binary)
	command.Env = append(os.Environ(), "APP_ENV=development", "GUARD_MODE=execution", "GUARD_LISTEN_ADDR="+address, "GUARD_KEY_FILE="+keyPath, "OPA_URL="+opa)
	command.Env = append(command.Env, extra...)
	if e := command.Start(); e != nil {
		cancel()
		t.Fatal(e)
	}
	t.Cleanup(func() { cancel(); command.Wait() })
	client, e := guardclient.NewRPC(address, key, true)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { client.Close() })
	for i := 0; i < 100; i++ {
		connection, e := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if e == nil {
			connection.Close()
			return client, address, key
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("execution kernel did not listen")
	return nil, "", nil
}
