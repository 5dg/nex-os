//go:build integration

package api

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/evidence"
	"github.com/5dg/nex-os/services/control/devseed"
	"github.com/5dg/nex-os/services/control/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The runtime coordinator must provision a fresh disposable cluster/database;
// LocalRoles creates cluster-level synthetic roles and must never target a
// retained or live database. The test leaves its fixture state for inspection.
func TestCommittedReconciliationActualControlRole(t *testing.T) {
	raw := os.Getenv("NEX_TEST_RECONCILIATION_ROLE_DSN")
	if raw == "" {
		t.Skip("fresh disposable role fixture not configured")
	}
	if os.Getenv("NEX_TEST_RECONCILIATION_ROLE_FIXTURE") != "disposable-only" {
		t.Fatal("explicit disposable role fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	config, err := pgxpool.ParseConfig(raw)
	if err != nil || config.ConnConfig.Host != "127.0.0.1" || len(config.ConnConfig.Fallbacks) != 0 || config.ConnConfig.TLSConfig != nil {
		t.Fatal("literal loopback-only disposable fixture connection required")
	}
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var database string
	var fresh, super bool
	if db.QueryRow(ctx, `SELECT current_database(), NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S')), (SELECT rolsuper FROM pg_roles WHERE rolname=current_user)`).Scan(&database, &fresh, &super) != nil || !strings.HasPrefix(database, "nex_reconciliation_role_") || !fresh || !super {
		t.Fatal("fresh local disposable role fixture required")
	}
	var noRoles bool
	if db.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN ('nex_control','nex_guard'))`).Scan(&noRoles) != nil || !noRoles {
		t.Fatal("fresh cluster without runtime roles required")
	}
	if err = migrations.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err = devseed.Seed(ctx, db, "http://synthetic-issuer"); err != nil {
		t.Fatal(err)
	}
	if err = devseed.SeedWorkflow(ctx, db, "http://synthetic-issuer"); err != nil {
		t.Fatal(err)
	}
	credentials := t.TempDir()
	for _, role := range []string{"control", "guard"} {
		secret := make([]byte, 32)
		if _, err = rand.Read(secret); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(credentials, role+"_database_password"), secret, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err = devseed.LocalRoles(ctx, db, credentials); err != nil {
		t.Fatal(err)
	}
	jobID, operationID := "role-job-"+rand.Text(), "role-operation-"+rand.Text()
	if _, err = db.Exec(ctx, `INSERT INTO jobs(id,tenant_id,delegation_id,state,owner_id,document_id,document_version,question,operation_id) VALUES($1,'tenant-a','delegation-alice','failed','alice','review-alice','v1','synthetic',$2)`, jobID, operationID); err != nil {
		t.Fatal(err)
	}
	scope := evidence.CommittedReconciliationScope{TenantID: "tenant-a", ActorID: "alice", JobID: jobID, ResourceID: "review-alice", DelegationID: "delegation-alice", OperationID: operationID, Kind: "model", RequestDigest: broker.Hash([]byte("synthetic request")), ProtectedResult: []byte(`{"text":"synthetic"}`)}
	for _, commit := range []bool{false, true} {
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `SET LOCAL ROLE nex_control`); err != nil {
			t.Fatal(err)
		}
		var insert, read, update, deleteAllowed bool
		if tx.QueryRow(ctx, `SELECT has_column_privilege(current_user,'committed_reconciliation_outbox','event_bytes','INSERT'),has_table_privilege(current_user,'committed_reconciliation_outbox','SELECT'),has_table_privilege(current_user,'committed_reconciliation_outbox','UPDATE'),has_table_privilege(current_user,'committed_reconciliation_outbox','DELETE')`).Scan(&insert, &read, &update, &deleteAllowed) != nil || !insert || read || update || deleteAllowed {
			t.Fatal("runtime role outbox privileges are not insert-only")
		}
		if _, err = tx.Exec(ctx, `UPDATE jobs SET state='completed' WHERE id=$1`, jobID); err != nil {
			t.Fatal(err)
		}
		if err = evidence.EnqueueCommittedReconciliation(ctx, tx, scope); err != nil {
			t.Fatal("runtime role could not enqueue the transition", err)
		}
		if commit {
			err = tx.Commit(ctx)
		} else {
			err = tx.Rollback(ctx)
		}
		if err != nil {
			t.Fatal(err)
		}
		var state string
		var count int
		if db.QueryRow(ctx, `SELECT j.state,(SELECT count(*) FROM committed_reconciliation_outbox WHERE job_id=j.id) FROM jobs j WHERE j.id=$1`, jobID).Scan(&state, &count) != nil || (!commit && (state != "failed" || count != 0)) || (commit && (state != "completed" || count != 1)) {
			t.Fatal("job and outbox did not commit or roll back together", state, count)
		}
	}
}
