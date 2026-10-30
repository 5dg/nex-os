package broker

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type testReceiptFence struct{ blocked atomic.Bool }

func (f *testReceiptFence) Check(context.Context) error {
	if f.blocked.Load() {
		return errors.New("recovery fence closed")
	}
	return nil
}

// This suite requires an isolated, disposable PostgreSQL instance prepared by
// the runtime coordinator. It never drops databases, schemas, roles or records.
func TestPostgresReceiptsIntegration(t *testing.T) {
	dsn := os.Getenv("NEX_RECEIPT_TEST_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL receipt fixture not configured")
	}
	if os.Getenv("NEX_RECEIPT_TEST_FIXTURE") != "disposable-only" {
		t.Fatal("explicit disposable receipt fixture required")
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(config.ConnConfig.Database, "nex_receipt_test_") {
		t.Fatal("dedicated nex_receipt_test_ database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	var current string
	if err := admin.QueryRow(ctx, "SELECT current_database()").Scan(&current); err != nil || current != config.ConnConfig.Database {
		t.Fatal("fixture database identity mismatch")
	}
	schema, err := os.ReadFile("production_receipts.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, string(schema)); err != nil {
		t.Fatalf("fresh fixture schema required: %v", err)
	}
	for _, stmt := range []string{
		"CREATE ROLE nex_receipt_test_model NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT",
		"CREATE ROLE nex_receipt_test_export NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT",
		"GRANT USAGE ON SCHEMA nex_model_receipts TO nex_receipt_test_model",
		"GRANT SELECT, INSERT ON nex_model_receipts.operations TO nex_receipt_test_model",
		"GRANT UPDATE(owner_nonce,state,result_bytes) ON nex_model_receipts.operations TO nex_receipt_test_model",
		"GRANT USAGE ON SCHEMA nex_export_receipts TO nex_receipt_test_export",
		"GRANT SELECT, INSERT ON nex_export_receipts.operations TO nex_receipt_test_export",
		"GRANT UPDATE(owner_nonce,state,result_bytes) ON nex_export_receipts.operations TO nex_receipt_test_export",
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("fixture role setup failed: %v", err)
		}
	}
	rolePool := func(role string) *pgxpool.Pool {
		t.Helper()
		cfg := config.Copy()
		cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			_, err := conn.Exec(ctx, "SET ROLE "+role)
			return err
		}
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		return pool
	}
	modelDB := rolePool("nex_receipt_test_model")
	exportDB := rolePool("nex_receipt_test_export")
	fence := &testReceiptFence{}
	access := ReceiptAccess(func(_ context.Context, id, digest string) error {
		if id == "" || !validReceiptDigest(digest) {
			return errors.New("invalid access scope")
		}
		return nil
	})
	model, err := NewPostgresReceiptStore(modelDB, "model", fence)
	if err != nil {
		t.Fatal(err)
	}
	export, err := NewPostgresReceiptStore(exportDB, "export", fence)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := modelDB.Exec(ctx, "SELECT * FROM nex_export_receipts.operations"); err == nil {
		t.Fatal("model receiver read export receipts")
	}
	if _, err := exportDB.Exec(ctx, "SELECT * FROM nex_model_receipts.operations"); err == nil {
		t.Fatal("export receiver read model receipts")
	}
	if _, err := modelDB.Exec(ctx, "DELETE FROM nex_model_receipts.operations WHERE false"); err == nil {
		t.Fatal("model receiver has delete permission")
	}
	if _, err := modelDB.Exec(ctx, "UPDATE nex_model_receipts.operations SET request_digest=request_digest WHERE false"); err == nil {
		t.Fatal("model receiver can alter an existing digest")
	}
	digest := Hash([]byte("exact request"))
	if _, err := model.Inspect(ctx, "missing-op", digest, access); !errors.Is(err, ErrUnknown) {
		t.Fatal("missing row was treated as proof of no effect")
	}
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	done := make(chan error, 1)
	go func() {
		_, err := model.DoAuthorized(ctx, "operation-001", digest, access, func(context.Context) error { return nil }, func(context.Context) (any, error) {
			calls.Add(1)
			close(started)
			<-release
			return map[string]string{"result": "once"}, nil
		})
		done <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("fixture effect did not start")
	}
	var concurrent sync.WaitGroup
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		concurrent.Add(1)
		go func() {
			defer concurrent.Done()
			_, err := model.DoAuthorized(ctx, "operation-001", digest, access, func(context.Context) error { return nil }, func(context.Context) (any, error) { calls.Add(1); return "duplicate", nil })
			errs <- err
		}()
	}
	concurrent.Wait()
	close(errs)
	for err := range errs {
		if !errors.Is(err, ErrUnknown) {
			t.Fatalf("concurrent uncertain operation: %v", err)
		}
	}
	releaseOnce.Do(func() { close(release) })
	if err := <-done; err != nil || calls.Load() != 1 {
		t.Fatalf("expected one completed effect: %v, calls=%d", err, calls.Load())
	}
	result, err := model.DoAuthorized(ctx, "operation-001", digest, access, func(context.Context) error { t.Error("completed operation reauthorized"); return nil }, func(context.Context) (any, error) { t.Error("completed effect repeated"); return nil, nil })
	if err != nil || string(result) != `{"result":"once"}` {
		t.Fatalf("completed result was not preserved: %s %v", result, err)
	}
	revoked := ReceiptAccess(func(context.Context, string, string) error { return errors.New("authority revoked") })
	if result, err := model.Inspect(ctx, "operation-001", digest, revoked); !errors.Is(err, ErrUnknown) || result != nil {
		t.Fatal("revoked caller read completed result")
	}
	if result, err := model.DoAuthorized(ctx, "operation-001", digest, revoked, func(context.Context) error { t.Error("revoked replay reauthorized"); return nil }, func(context.Context) (any, error) { t.Error("revoked replay dispatched"); return nil, nil }); !errors.Is(err, ErrUnknown) || result != nil {
		t.Fatal("revoked caller replayed completed result")
	}
	if result, err := model.Inspect(ctx, "operation-001", digest, nil); !errors.Is(err, ErrUnknown) || result != nil {
		t.Fatal("missing access check returned completed result")
	}
	fence.blocked.Store(true)
	if result, err := model.Inspect(ctx, "operation-001", digest, access); !errors.Is(err, ErrUnknown) || result != nil {
		t.Fatal("closed recovery fence returned result")
	}
	fence.blocked.Store(false)
	var accessChecks atomic.Int32
	revokedAfterEffect := ReceiptAccess(func(_ context.Context, id, gotDigest string) error {
		if id != "operation-006" || gotDigest != digest || accessChecks.Add(1) >= 3 {
			return errors.New("authority revoked")
		}
		return nil
	})
	if result, err := model.DoAuthorized(ctx, "operation-006", digest, revokedAfterEffect, func(context.Context) error { return nil }, func(context.Context) (any, error) { return "recorded", nil }); !errors.Is(err, ErrUnknown) || result != nil {
		t.Fatal("revoked authority received the just-completed result")
	}
	if result, err := model.Inspect(ctx, "operation-006", digest, access); err != nil || string(result) != `"recorded"` {
		t.Fatal("completed effect was not durably retained for an authorized reader")
	}
	var beforeDispatchChecks atomic.Int32
	revokedBeforeEffect := ReceiptAccess(func(context.Context, string, string) error {
		if beforeDispatchChecks.Add(1) >= 2 {
			return errors.New("authority revoked")
		}
		return nil
	})
	if _, err := model.DoAuthorized(ctx, "operation-007", digest, revokedBeforeEffect, func(context.Context) error { return nil }, func(context.Context) (any, error) { t.Error("revoked effect dispatched"); return nil, nil }); !errors.Is(err, ErrUnknown) {
		t.Fatal("revocation before dispatch was not conservatively unknown")
	}
	if _, err := model.DoAuthorized(ctx, "operation-007", digest, access, func(context.Context) error { t.Error("uncertain grant reauthorized"); return nil }, func(context.Context) (any, error) { t.Error("uncertain effect redispatched"); return nil, nil }); !errors.Is(err, ErrUnknown) {
		t.Fatal("uncertain grant was retried")
	}
	if _, err := model.Inspect(ctx, "operation-001", Hash([]byte("different")), access); !errors.Is(err, ErrUnknown) {
		t.Fatal("digest mismatch was accepted")
	}
	for i, state := range []string{"prepared", "started"} {
		id := "abandoned-" + state
		if _, err := admin.Exec(ctx, "INSERT INTO nex_model_receipts.operations(operation_id,request_digest,owner_nonce,state) VALUES($1,$2,$3,$4)", id, digest, strings.Repeat("a", 32), state); err != nil {
			t.Fatal(err)
		}
		if _, err := model.DoAuthorized(ctx, id, digest, access, func(context.Context) error { t.Error("abandoned operation reauthorized"); return nil }, func(context.Context) (any, error) { t.Error("abandoned effect repeated"); return nil, nil }); !errors.Is(err, ErrUnknown) {
			t.Fatalf("abandoned state %d was not unknown: %v", i, err)
		}
	}
	for _, tc := range []struct {
		id        string
		authorize func(context.Context) error
		effect    func(context.Context) (any, error)
	}{
		{"operation-002", func(context.Context) error { return errors.New("authorization outcome unavailable") }, func(context.Context) (any, error) { t.Error("unauthorized effect"); return nil, nil }},
		{"operation-003", func(context.Context) error { return nil }, func(context.Context) (any, error) { return nil, errors.New("provider outcome unavailable") }},
		{"operation-005", func(context.Context) error { return nil }, func(context.Context) (any, error) { return nil, nil }},
	} {
		if _, err := model.DoAuthorized(ctx, tc.id, digest, access, tc.authorize, tc.effect); !errors.Is(err, ErrUnknown) {
			t.Fatalf("ambiguous outcome %s: %v", tc.id, err)
		}
		if _, err := model.DoAuthorized(ctx, tc.id, digest, access, func(context.Context) error { t.Error("uncertain operation reauthorized"); return nil }, func(context.Context) (any, error) { t.Error("uncertain effect repeated"); return nil, nil }); !errors.Is(err, ErrUnknown) {
			t.Fatalf("uncertain operation was retried: %s", tc.id)
		}
	}
	if _, err := export.DoAuthorized(ctx, "operation-004", digest, access, func(context.Context) error { return ErrNotStarted }, func(context.Context) (any, error) { t.Error("denied effect ran"); return nil, nil }); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("authenticated no-effect denial lost: %v", err)
	}
	if _, err := export.Inspect(ctx, "operation-004", digest, access); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("no-effect state unavailable: %v", err)
	}
	if _, err := export.DoAuthorized(ctx, "operation-004", digest, access, func(context.Context) error { return nil }, func(context.Context) (any, error) { return "approved", nil }); err != nil {
		t.Fatalf("explicitly not-started operation could not be retried: %v", err)
	}
	if _, err := NewPostgresReceiptStore(admin, "model;DROP SCHEMA public", fence); err == nil {
		t.Fatal("arbitrary SQL domain accepted")
	}
}
