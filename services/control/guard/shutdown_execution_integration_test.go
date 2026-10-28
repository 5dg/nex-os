//go:build integration

package guard_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/evidence"
	"github.com/5dg/nex-os/services/control/devseed"
	guardclient "github.com/5dg/nex-os/services/control/guard"
	"github.com/5dg/nex-os/services/control/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Actual development-transport Rust + PostgreSQL execution/drain test. Qualified
// TLS listener behavior is covered separately; no model/provider is invoked here.
func TestRustSIGTERMDrainsActualGrantAndRestartDoesNotRepeat(t *testing.T) {
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
	schema := "shutdown_grant_" + strings.ToLower(rand.Text())
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

	var hold atomic.Bool
	var signedAuthorizations atomic.Int32
	entered, release := make(chan struct{}, 1), make(chan struct{})
	signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(200)
			return
		}
		var event evidence.Event
		if r.URL.Path != "/append/kernel" || !broker.ReadLimit(w, r, writerKey, "evidence.append.kernel", &event, 128*1024) {
			return
		}
		event.Producer = "kernel"
		if event.Action == "model.authorized" {
			signedAuthorizations.Add(1)
			if hold.Load() {
				entered <- struct{}{}
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
			}
		}
		proof, err := journal.Append(event)
		if err != nil {
			http.Error(w, "fixture signing failed", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proof)
	}))
	defer signer.Close()
	opa := os.Getenv("NEX_TEST_OPA_URL")
	if opa == "" {
		opa = "http://127.0.0.1:8181"
	}
	extra := []string{"NEX_PROFILE=development", "DATABASE_URL=" + parsed.String(), "MODEL_GUARD_KEY_FILE=" + write("model-key", modelKey), "EXPORT_GUARD_KEY_FILE=" + write("export-key", exportKey), "EVIDENCE_URL=" + signer.URL, "EVIDENCE_KEY_FILE=" + write("writer-key", writerKey), "EVIDENCE_PUBLIC_FILE=" + write("writer-public", public)}
	control, address, command, diagnostic := startDrainExecutionKernel(t, opa, extra)
	model, err := guardclient.NewRPC(address, modelKey, true)
	if err != nil {
		t.Fatal(err)
	}
	defer model.Close()
	job, operation := rand.Text(), rand.Text()
	if _, err = db.Exec(ctx, `INSERT INTO jobs(id,tenant_id,owner_id,delegation_id,state,phase,document_id,document_version,question,operation_id,lease_token,lease_until) VALUES($1,'tenant-a','alice','delegation-alice','running','review','review-alice','v1','What access review and export controls apply?',$2,'fixture-lease',clock_timestamp()+interval '5 minutes')`, job, operation); err != nil {
		t.Fatal("cannot seed isolated grant")
	}
	_, digest, err := control.PrepareExecution(ctx, job, operation)
	if err != nil {
		t.Fatal(err)
	}
	hold.Store(true)
	returned := make(chan error, 1)
	go func() {
		allowed, err := model.AuthorizeExecution(ctx, operation, digest)
		if err == nil && !allowed {
			err = context.Canceled
		}
		returned <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("grant did not reach actual held signer")
	}
	// The independent reader sees pending while the actual Rust transaction has
	// already updated started but cannot commit until its exact proof returns.
	var state string
	if err = db.QueryRow(ctx, "SELECT status FROM execution_operations WHERE id=$1", operation).Scan(&state); err != nil || state != "pending" {
		t.Fatal("held grant did not remain uncommitted")
	}
	if err = command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for !strings.Contains(diagnostic.String(), "shutdown started; new admission closed") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(diagnostic.String(), "shutdown started; new admission closed") {
		close(release)
		t.Fatal("SIGTERM did not close admission")
	}
	probe, cancelProbe := context.WithTimeout(ctx, 300*time.Millisecond)
	_, newErr := model.AuthorizeExecution(probe, operation, digest)
	cancelProbe()
	if newErr == nil {
		t.Error("new grant was admitted during shutdown")
	}
	close(release)
	if err = <-returned; err != nil {
		t.Fatalf("pre-admitted exact grant did not drain: %v", err)
	}
	watchdog := time.AfterFunc(5*time.Second, func() { _ = command.Process.Kill() })
	err = command.Wait()
	watchdog.Stop()
	if err != nil || !strings.Contains(diagnostic.String(), "shutdown completed; request and database drivers drained") {
		t.Fatalf("actual DB grant did not exit cleanly: %v", err)
	}
	var receipts int
	var resultAbsent bool
	if err = db.QueryRow(ctx, `SELECT status,result IS NULL,(SELECT count(*) FROM audit_events WHERE job_id=$2 AND action='model.authorized') FROM execution_operations WHERE id=$1`, operation, job).Scan(&state, &resultAbsent, &receipts); err != nil || state != "started" || !resultAbsent || receipts != 1 {
		t.Fatal("drain changed committed uncertain grant state")
	}
	hold.Store(false)
	_, restartAddress, _, _ := startDrainExecutionKernel(t, opa, extra)
	restartModel, err := guardclient.NewRPC(restartAddress, modelKey, true)
	if err != nil {
		t.Fatal(err)
	}
	defer restartModel.Close()
	observed, err := restartModel.ExecutionState(ctx, operation, digest)
	if err != nil || observed != "started" {
		t.Fatal("restart did not preserve authenticated started observation")
	}
	again, retryErr := restartModel.AuthorizeExecution(ctx, operation, digest)
	if retryErr == nil || again || signedAuthorizations.Load() != 1 {
		t.Fatal("restart re-granted or re-signed ambiguous started operation")
	}
	if err = db.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE job_id=$1 AND action='model.authorized'`, job).Scan(&receipts); err != nil || receipts != 1 {
		t.Fatal("restart created a second authorization receipt")
	}
}

func startDrainExecutionKernel(t *testing.T, opa string, extra []string) (*guardclient.Client, string, *exec.Cmd, *qualProcessLog) {
	t.Helper()
	binary := os.Getenv("NEX_TEST_GUARD_BINARY")
	if binary == "" {
		t.Fatal("NEX_TEST_GUARD_BINARY required")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "control-key")
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	command := exec.Command(binary)
	command.Env = append(os.Environ(), "APP_ENV=development", "GUARD_MODE=execution", "GUARD_LISTEN_ADDR="+address, "GUARD_KEY_FILE="+keyPath, "OPA_URL="+opa)
	command.Env = append(command.Env, extra...)
	diagnostic := &qualProcessLog{}
	command.Stdout = diagnostic
	command.Stderr = diagnostic
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	client, err := guardclient.NewRPC(address, key, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		connection, e := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if e == nil {
			connection.Close()
			return client, address, command, diagnostic
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("private execution kernel did not listen")
	return nil, "", nil, nil
}
