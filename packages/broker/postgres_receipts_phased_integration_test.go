package broker

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type fixturePhaseAuthorizer struct {
	status  atomic.Value // string; synthetic Guard status only
	revoked atomic.Bool
	hook    func(ReceiptPhase, ReceiptClaim)
}

func (a *fixturePhaseAuthorizer) CheckReceiptPhase(_ context.Context, phase ReceiptPhase, claim ReceiptClaim) (string, error) {
	if a.revoked.Load() || claim.OperationID() == "" || !validReceiptDigest(claim.Digest()) {
		return "", errors.New("fixture access denied")
	}
	if (phase == ReceiptDispatchEffect || phase == ReceiptReceiverHandoff) != (claim.Nonce() != "") {
		return "", errors.New("fixture claimant scope denied")
	}
	if a.hook != nil {
		a.hook(phase, claim)
	}
	if a.revoked.Load() {
		return "", errors.New("fixture access revoked")
	}
	return a.status.Load().(string), nil
}

// Runs only against a newly created disposable database and a separate
// restricted login. No shared or existing receipt schema is modified.
func TestPostgresPhasedReceiptsIntegration(t *testing.T) {
	adminURL, roleURL := os.Getenv("NEX_PHASED_RECEIPT_ADMIN_DSN"), os.Getenv("NEX_PHASED_RECEIPT_ROLE_DSN")
	if adminURL == "" || roleURL == "" {
		t.Skip("dedicated phased receipt database not configured")
	}
	if os.Getenv("NEX_PHASED_RECEIPT_FIXTURE") != "disposable-only" {
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
	adminConfig, err := pgxpool.ParseConfig(adminURL)
	if err != nil || adminConfig.ConnConfig.TLSConfig == nil || adminConfig.ConnConfig.TLSConfig.InsecureSkipVerify {
		t.Fatal("invalid fixture admin TLS")
	}
	adminConfig.ConnConfig.Fallbacks = nil
	roleConfig, err := pgxpool.ParseConfig(roleURL)
	if err != nil || roleConfig.ConnConfig.TLSConfig == nil || roleConfig.ConnConfig.TLSConfig.InsecureSkipVerify {
		t.Fatal("invalid fixture receiver TLS")
	}
	roleConfig.ConnConfig.Fallbacks = nil
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal("fixture admin unavailable")
	}
	defer admin.Close()
	role, err := pgxpool.NewWithConfig(ctx, roleConfig)
	if err != nil {
		t.Fatal("fixture receiver unavailable")
	}
	defer role.Close()
	var database, adminName, roleDatabase, roleName string
	if admin.QueryRow(ctx, `SELECT current_database(),current_user`).Scan(&database, &adminName) != nil || role.QueryRow(ctx, `SELECT current_database(),current_user`).Scan(&roleDatabase, &roleName) != nil || !strings.HasPrefix(database, "nex_receipt_test_") || database != roleDatabase || !strings.HasPrefix(roleName, "nex_receipt_test_") || roleName == adminName {
		t.Fatal("non-disposable receipt database or login")
	}
	var empty, restricted, owner bool
	if admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT FROM pg_namespace WHERE nspname IN ('nex_model_receipts','nex_export_receipts'))`).Scan(&empty) != nil || !empty {
		t.Fatal("fresh receipt schemas required")
	}
	if admin.QueryRow(ctx, `SELECT NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=pg_roles.oid) FROM pg_roles WHERE rolname=$1`, roleName).Scan(&restricted) != nil || !restricted {
		t.Fatal("restricted fixture receiver required")
	}
	if admin.QueryRow(ctx, `SELECT d.datdba=r.oid FROM pg_database d JOIN pg_roles r ON r.rolname=$1 WHERE d.datname=current_database()`, roleName).Scan(&owner) != nil || owner {
		t.Fatal("receiver must not own fixture database")
	}
	schema, err := os.ReadFile("production_receipts.sql")
	if err != nil {
		t.Fatal("fixture schema missing")
	}
	if _, err = admin.Exec(ctx, string(schema)); err != nil {
		t.Fatal("fixture schema creation failed")
	}
	quoted := pgx.Identifier{roleName}.Sanitize()
	for _, q := range []string{`GRANT USAGE ON SCHEMA nex_model_receipts TO ` + quoted, `GRANT SELECT,INSERT ON nex_model_receipts.operations TO ` + quoted, `GRANT UPDATE(owner_nonce,state,result_bytes) ON nex_model_receipts.operations TO ` + quoted} {
		if _, err = admin.Exec(ctx, q); err != nil {
			t.Fatal("fixture receiver grant failed")
		}
	}
	fence := &testReceiptFence{}
	store, err := NewPostgresReceiptStore(role, "model", fence)
	if err != nil {
		t.Fatal("fixture store unavailable")
	}
	auth := &fixturePhaseAuthorizer{}
	auth.status.Store("pending")
	digest := Hash([]byte("synthetic request"))
	var calls atomic.Int32
	authorize := func(_ context.Context, c ReceiptClaim) error {
		if c.Nonce() == "" || c.OperationID() == "" || c.Digest() != digest {
			return errors.New("claim mismatch")
		}
		auth.status.Store("started")
		return nil
	}
	effect := func(context.Context) (any, error) { calls.Add(1); return map[string]string{"result": "synthetic"}, nil }
	result, err := store.DoPhasedAuthorized(ctx, "phase-success", digest, auth, authorize, effect)
	if err != nil || string(result) != `{"result":"synthetic"}` || calls.Load() != 1 {
		t.Fatal("claimant handoff failed")
	}
	if result, err := store.ReadPhasedCompleted(ctx, "phase-success", digest, auth); !errors.Is(err, ErrUnknown) || result != nil {
		t.Fatal("started Guard result was disclosed")
	}
	auth.status.Store("completed")
	if result, err := store.ReadPhasedCompleted(ctx, "phase-success", digest, auth); err != nil || string(result) != `{"result":"synthetic"}` {
		t.Fatal("completed read failed")
	}
	if _, err := store.DoPhasedAuthorized(ctx, "phase-success", digest, auth, authorize, effect); !errors.Is(err, ErrUnknown) || calls.Load() != 1 {
		t.Fatal("completed operation redispatched")
	}
	auth.status.Store("pending")
	_, err = store.DoPhasedAuthorized(ctx, "phase-revoked", digest, auth, authorize, func(context.Context) (any, error) { calls.Add(1); auth.revoked.Store(true); return "hidden", nil })
	if !errors.Is(err, ErrUnknown) {
		t.Fatal("revoked claimant received a result")
	}
	auth.revoked.Store(false)
	auth.status.Store("pending")
	if _, err = store.DoPhasedAuthorized(ctx, "phase-revoked", digest, auth, authorize, effect); !errors.Is(err, ErrUnknown) || calls.Load() != 2 {
		t.Fatal("completed hidden effect redispatched")
	}
	auth.status.Store("pending")
	_, err = store.DoPhasedAuthorized(ctx, "phase-uncertain", digest, auth, authorize, func(context.Context) (any, error) { calls.Add(1); return nil, errors.New("synthetic ambiguous effect") })
	if !errors.Is(err, ErrUnknown) {
		t.Fatal("uncertain effect did not remain unknown")
	}
	auth.status.Store("pending")
	if _, err = store.DoPhasedAuthorized(ctx, "phase-uncertain", digest, auth, authorize, effect); !errors.Is(err, ErrUnknown) || calls.Load() != 3 {
		t.Fatal("uncertain effect redispatched")
	}
	auth.status.Store("pending")
	auth.hook = func(phase ReceiptPhase, claim ReceiptClaim) {
		if phase == ReceiptDispatchEffect {
			replacement := strings.Repeat("f", 32)
			if replacement == claim.Nonce() {
				replacement = strings.Repeat("0", 32)
			}
			if changed, e := admin.Exec(ctx, `UPDATE nex_model_receipts.operations SET owner_nonce=$2 WHERE operation_id=$1`, claim.OperationID(), replacement); e != nil || changed.RowsAffected() != 1 {
				t.Error("fixture claim mutation failed")
			}
		}
	}
	if _, err = store.DoPhasedAuthorized(ctx, "phase-stale", digest, auth, authorize, effect); !errors.Is(err, ErrUnknown) || calls.Load() != 3 {
		t.Fatal("stale claimant dispatched")
	}
	auth.status.Store("pending")
	auth.hook = func(phase ReceiptPhase, _ ReceiptClaim) {
		if phase == ReceiptDispatchEffect {
			auth.revoked.Store(true)
		}
	}
	if _, err = store.DoPhasedAuthorized(ctx, "phase-before-effect-revoked", digest, auth, authorize, effect); !errors.Is(err, ErrUnknown) || calls.Load() != 3 {
		t.Fatal("revoked claimant dispatched")
	}
	auth.hook = nil
	auth.revoked.Store(false)
	auth.status.Store("pending")
	fence.blocked.Store(true)
	if _, err = store.DoPhasedAuthorized(ctx, "phase-fenced", digest, auth, authorize, effect); !errors.Is(err, ErrUnknown) || calls.Load() != 3 {
		t.Fatal("closed recovery fence dispatched")
	}
}
