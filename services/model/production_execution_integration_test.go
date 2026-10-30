package model

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Synthetic Guard and fence only. These prove coordinator/receipt ordering,
// not receiver identity, real Bedrock access, or effect-spanning fencing.
type modelPhaseFence struct{}

func (modelPhaseFence) Check(context.Context) error { return nil }

type modelPhaseAuthority struct {
	status        atomic.Value
	reads         atomic.Int32
	denyThirdRead atomic.Bool
}

func (a *modelPhaseAuthority) CheckReceiptPhase(_ context.Context, phase broker.ReceiptPhase, claim broker.ReceiptClaim) (string, error) {
	if claim.OperationID() == "" || claim.Digest() == "" || ((phase == broker.ReceiptDispatchEffect || phase == broker.ReceiptReceiverHandoff) != (claim.Nonce() != "")) {
		return "", errors.New("synthetic phase denied")
	}
	if phase == broker.ReceiptCompletedRead && a.reads.Add(1) == 3 && a.denyThirdRead.Load() {
		return "", errors.New("synthetic access revoked")
	}
	return a.status.Load().(string), nil
}

func TestModelPhasedPostgresIntegration(t *testing.T) {
	adminURL, roleURL := os.Getenv("NEX_MODEL_PHASE_ADMIN_DSN"), os.Getenv("NEX_MODEL_PHASE_ROLE_DSN")
	if adminURL == "" || roleURL == "" {
		t.Skip("fresh synthetic phased model database not configured")
	}
	if os.Getenv("NEX_MODEL_PHASE_FIXTURE") != "disposable-only" {
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
		t.Fatal("invalid fixture receiver TLS")
	}
	roleCfg.ConnConfig.Fallbacks = nil
	admin, err := pgxpool.NewWithConfig(ctx, adminCfg)
	if err != nil {
		t.Fatal("fixture admin unavailable")
	}
	defer admin.Close()
	role, err := pgxpool.NewWithConfig(ctx, roleCfg)
	if err != nil {
		t.Fatal("fixture receiver unavailable")
	}
	defer role.Close()
	var database, adminName, roleDB, roleName string
	if admin.QueryRow(ctx, `SELECT current_database(),current_user`).Scan(&database, &adminName) != nil || role.QueryRow(ctx, `SELECT current_database(),current_user`).Scan(&roleDB, &roleName) != nil || !strings.HasPrefix(database, "nex_model_phase_") || database != roleDB || !strings.HasPrefix(roleName, "nex_model_phase_") || roleName == adminName {
		t.Fatal("non-disposable fixture database or login")
	}
	var empty, restricted, owner bool
	if admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT FROM pg_namespace WHERE nspname IN ('nex_model_receipts','nex_export_receipts'))`).Scan(&empty) != nil || !empty {
		t.Fatal("fresh receipt schemas required")
	}
	if admin.QueryRow(ctx, `SELECT NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=pg_roles.oid) FROM pg_roles WHERE rolname=$1`, roleName).Scan(&restricted) != nil || !restricted {
		t.Fatal("restricted fixture login required")
	}
	if admin.QueryRow(ctx, `SELECT d.datdba=r.oid FROM pg_database d JOIN pg_roles r ON r.rolname=$1 WHERE d.datname=current_database()`, roleName).Scan(&owner) != nil || owner {
		t.Fatal("fixture receiver must not own database")
	}
	schema, err := os.ReadFile("../../packages/broker/production_receipts.sql")
	if err != nil {
		t.Fatal("fixture schema unavailable")
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
	receipts, err := broker.NewPostgresReceiptStore(role, "model", modelPhaseFence{})
	if err != nil {
		t.Fatal("fixture receipt store unavailable")
	}
	in, adapter, policy := productionBindingFixture()
	provider := adapter.route.client.(*converseStub)
	auth := &modelPhaseAuthority{}
	auth.status.Store("pending")
	manifest := modelManifestFunc(func(_ context.Context, in contracts.Generation) (string, error) {
		return contracts.ExecutionDigest(in), nil
	})
	var grants atomic.Int32
	authorize := func(_ context.Context, claim broker.ReceiptClaim) error {
		if claim.OperationID() != in.OperationID || claim.Digest() != contracts.ExecutionDigest(in) || len(claim.Nonce()) != 32 {
			return errors.New("synthetic one-shot scope denied")
		}
		grants.Add(1)
		auth.status.Store("started")
		return nil
	}
	coordinator, err := NewProductionModelCoordinator(adapter, policy, receipts, manifest, auth, authorize, 3*time.Second)
	if err != nil {
		t.Fatal("fixture coordinator unavailable")
	}
	result, err := coordinator.Execute(ctx, in)
	if err != nil || result.Text != "synthetic provider response" || grants.Load() != 1 || provider.calls != 1 {
		t.Fatal("model claimant handoff failed")
	}
	if result, err = coordinator.ReadCompleted(ctx, in); err == nil || result.Text != "" {
		t.Fatal("started Guard result was disclosed")
	}
	auth.status.Store("completed")
	auth.reads.Store(0)
	if result, err = coordinator.ReadCompleted(ctx, in); err != nil || result.Text != "synthetic provider response" || provider.calls != 1 {
		t.Fatal("completed result read failed")
	}
	auth.reads.Store(0)
	auth.denyThirdRead.Store(true)
	if result, err = coordinator.ReadCompleted(ctx, in); err == nil || result.Text != "" {
		t.Fatal("revoked result was disclosed")
	}
	auth.status.Store("pending")
	if _, err = coordinator.Execute(ctx, in); !errors.Is(err, broker.ErrUnknown) || provider.calls != 1 || grants.Load() != 1 {
		t.Fatal("completed model effect was repeated")
	}
	in.OperationID = "operation-ambiguous"
	provider.failure = true
	auth.status.Store("pending")
	if _, err = coordinator.Execute(ctx, in); !errors.Is(err, broker.ErrUnknown) || provider.calls != 2 {
		t.Fatal("ambiguous model outcome did not remain unknown")
	}
	auth.status.Store("pending")
	if _, err = coordinator.Execute(ctx, in); !errors.Is(err, broker.ErrUnknown) || provider.calls != 2 {
		t.Fatal("ambiguous model effect was retried")
	}
}
