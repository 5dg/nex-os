package executor

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

type s3PhaseFence struct{}

func (s3PhaseFence) Check(context.Context) error { return nil }

// Synthetic Guard decisions only: this fixture cannot prove authenticated
// per-instance ownership, revocation services or effect-spanning fencing.
type s3PhaseAuthority struct {
	status         atomic.Value
	reads          atomic.Int32
	denySecondRead atomic.Bool
}

func (a *s3PhaseAuthority) CheckReceiptPhase(_ context.Context, phase broker.ReceiptPhase, claim broker.ReceiptClaim) (string, error) {
	if claim.OperationID() == "" || claim.Digest() == "" {
		return "", errors.New("fixture scope denied")
	}
	if (phase == broker.ReceiptDispatchEffect || phase == broker.ReceiptReceiverHandoff) != (claim.Nonce() != "") {
		return "", errors.New("fixture claim denied")
	}
	// Inspect checks authority before and after each receipt read. The third
	// check occurs only after the S3 object fetch has returned.
	if phase == broker.ReceiptCompletedRead && a.reads.Add(1) == 3 && a.denySecondRead.Load() {
		return "", errors.New("fixture authority revoked")
	}
	return a.status.Load().(string), nil
}

func TestS3PhasedPostgresIntegration(t *testing.T) {
	adminURL, roleURL := os.Getenv("NEX_S3_PHASE_ADMIN_DSN"), os.Getenv("NEX_S3_PHASE_ROLE_DSN")
	if adminURL == "" || roleURL == "" {
		t.Skip("fresh synthetic phased export database not configured")
	}
	if os.Getenv("NEX_S3_PHASE_FIXTURE") != "disposable-only" {
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
	if admin.QueryRow(ctx, `SELECT current_database(),current_user`).Scan(&database, &adminName) != nil || role.QueryRow(ctx, `SELECT current_database(),current_user`).Scan(&roleDB, &roleName) != nil || !strings.HasPrefix(database, "nex_s3_phase_") || database != roleDB || !strings.HasPrefix(roleName, "nex_s3_phase_") || roleName == adminName {
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
	for _, q := range []string{`GRANT USAGE ON SCHEMA nex_export_receipts TO ` + quoted, `GRANT SELECT,INSERT ON nex_export_receipts.operations TO ` + quoted, `GRANT UPDATE(owner_nonce,state,result_bytes) ON nex_export_receipts.operations TO ` + quoted} {
		if _, err = admin.Exec(ctx, q); err != nil {
			t.Fatal("fixture receiver grant failed")
		}
	}
	store, err := broker.NewPostgresReceiptStore(role, "export", s3PhaseFence{})
	if err != nil {
		t.Fatal("fixture receipt store unavailable")
	}
	s, provider := newS3Fixture(t)
	in := fixtureExport()
	digest := contracts.ExecutionDigest(in)
	auth := &s3PhaseAuthority{}
	auth.status.Store("pending")
	var grants atomic.Int32
	authorize := func(_ context.Context, claim broker.ReceiptClaim) error {
		if claim.OperationID() != in.OperationID || claim.Digest() != digest || len(claim.Nonce()) != 32 {
			return errors.New("fixture one-shot scope denied")
		}
		grants.Add(1)
		auth.status.Store("started")
		return nil
	}
	result, err := s.ExecutePhased(ctx, in, digest, store, auth, authorize)
	if err != nil || result.ArtifactID != in.OperationID || grants.Load() != 1 {
		t.Fatal("durable phased S3 handoff failed")
	}
	if content, err := s.RetrievePhased(ctx, in, digest, store, auth); err == nil || content != nil {
		t.Fatal("started Guard operation released content")
	}
	auth.status.Store("completed")
	auth.reads.Store(0)
	content, err := s.RetrievePhased(ctx, in, digest, store, auth)
	if err != nil || string(content) != in.Content {
		t.Fatal("completed phased S3 read failed")
	}
	auth.reads.Store(0)
	auth.denySecondRead.Store(true)
	if content, err = s.RetrievePhased(ctx, in, digest, store, auth); err == nil || content != nil {
		t.Fatal("revocation after fetch released content")
	}
	auth.status.Store("pending")
	if _, err = s.ExecutePhased(ctx, in, digest, store, auth, authorize); !errors.Is(err, broker.ErrUnknown) {
		t.Fatal("completed effect was replayed")
	}
	provider.mu.Lock()
	puts := 0
	for _, request := range provider.requests {
		if strings.HasPrefix(request, "PUT ") {
			puts++
		}
	}
	provider.mu.Unlock()
	if puts != 1 || grants.Load() != 1 {
		t.Fatal("provider effect or one-shot grant was repeated")
	}
}
