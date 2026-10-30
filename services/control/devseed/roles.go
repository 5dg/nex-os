package devseed

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
)

// LocalRoles is a development bootstrap operation using the migration/admin
// connection. Runtime services never receive this connection or role passwords.
func LocalRoles(ctx context.Context, db *pgxpool.Pool, directory string) error {
	tx, e := db.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	for _, name := range []string{"control", "guard"} {
		key, e := os.ReadFile(directory + "/" + name + "_database_password")
		if e != nil || len(key) != 32 {
			return fmt.Errorf("local database identity unavailable: %s", name)
		}
		role := "nex_" + name
		if _, e = tx.Exec(ctx, `SELECT set_config('nex.bootstrap_password',$1,true)`, hex.EncodeToString(key)); e != nil {
			return e
		}
		statement := fmt.Sprintf(`DO $body$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='%s') THEN CREATE ROLE %s NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT; END IF; EXECUTE format('ALTER ROLE %s LOGIN PASSWORD %%L',current_setting('nex.bootstrap_password')); END $body$`, role, role, role)
		if _, e = tx.Exec(ctx, statement); e != nil {
			return e
		}
	}
	statements := []string{
		`GRANT USAGE ON SCHEMA public TO nex_control,nex_guard`,
		`REVOKE ALL ON ALL TABLES IN SCHEMA public FROM nex_control,nex_guard`,
		// Table-level REVOKE does not revoke old column-level grants. Clear both
		// before applying the current least-privilege profile on repeat seed.
		`DO $body$ DECLARE t record; c text; BEGIN
          FOR t IN SELECT tablename FROM pg_tables WHERE schemaname='public' LOOP
            SELECT string_agg(quote_ident(attname),',') INTO c FROM pg_attribute WHERE attrelid=format('public.%I',t.tablename)::regclass AND attnum>0 AND NOT attisdropped;
            IF c IS NOT NULL THEN EXECUTE format('REVOKE ALL (%s) ON public.%I FROM nex_control,nex_guard',c,t.tablename); END IF;
          END LOOP;
        END $body$`,
		`GRANT SELECT ON tenants,users,delegations,resources,document_bodies,model_routes,export_destinations,jobs,approvals,execution_operations,execution_manifests,audit_events,question_catalogue,document_admissions TO nex_control,nex_guard`,
		`GRANT UPDATE(lock_version) ON users,delegations,resources,document_bodies,model_routes,export_destinations,approvals TO nex_control,nex_guard`,
		`GRANT INSERT(id,tenant_id,delegation_id,state,owner_id,document_id,document_version,question,idempotency_key,request_digest,operation_id,question_id,question_version,execution_profile) ON jobs TO nex_control`,
		`GRANT UPDATE(state,phase,error_code,lease_token,lease_until,approval_id,operation_id) ON jobs TO nex_control`,
		`GRANT INSERT(id,tenant_id,job_id,request_digest,destination_id,expires_at,policy_digest) ON approvals TO nex_control`,
		`GRANT INSERT ON execution_operations,execution_manifests TO nex_guard`,
		`GRANT UPDATE(lock_version) ON question_catalogue,document_admissions TO nex_guard`,
		`GRANT UPDATE(approved_at,rejected_at,approver_id,consumed_at,consumed_operation_id) ON approvals TO nex_guard`,
		`GRANT UPDATE(state,phase,error_code,answer,provider,export_id,review_operation_id) ON jobs TO nex_guard`,
		`GRANT UPDATE(status,result,completed_at,qualification_receiver_cert_sha256) ON execution_operations TO nex_guard`,
		`GRANT INSERT ON audit_events TO nex_control,nex_guard`,
		`GRANT INSERT(event_id,tenant_id,job_id,operation_id,event_bytes,event_sha256) ON committed_reconciliation_outbox TO nex_control`,
		`GRANT UPDATE(integrity_reference) ON audit_events TO nex_control,nex_guard`,
	}
	for _, statement := range statements {
		if _, e = tx.Exec(ctx, statement); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}
