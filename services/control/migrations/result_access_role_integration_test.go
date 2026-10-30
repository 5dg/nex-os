//go:build integration

package migrations_test

// This fixture only accepts a newly created, explicitly named synthetic
// database and role. It is not a production migration or provisioning tool.
import (
	"context"
	"crypto/sha256"
	"embed"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/5dg/nex-os/services/control/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed 00[1-8]_*.sql
var historicalMigrations embed.FS

func TestSyntheticResultAccessRestrictedLocks(t *testing.T) {
	adminURL, roleURL := os.Getenv("NEX_RESULT_TEST_ADMIN_DSN"), os.Getenv("NEX_RESULT_TEST_ROLE_DSN")
	if adminURL == "" || roleURL == "" || os.Getenv("NEX_RESULT_TEST_DISPOSABLE") != "yes" {
		t.Fatal("explicit dedicated synthetic database and role required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	for _, raw := range []string{adminURL, roleURL} {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || len(u.Query()["sslmode"]) != 1 || u.Query().Get("sslmode") != "verify-full" || len(u.Query()["sslrootcert"]) != 1 || u.Query().Get("sslrootcert") == "" {
			t.Fatal("fixture connections require explicit verified TLS and test CA")
		}
	}
	adminConfig, err := pgxpool.ParseConfig(adminURL)
	if err != nil || adminConfig.ConnConfig.TLSConfig == nil || adminConfig.ConnConfig.TLSConfig.InsecureSkipVerify {
		t.Fatal("verified synthetic administrator TLS required")
	}
	adminConfig.ConnConfig.Fallbacks = nil
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal("synthetic admin connection failed")
	}
	defer admin.Close()
	roleConfig, err := pgx.ParseConfig(roleURL)
	if err != nil || roleConfig.TLSConfig == nil || roleConfig.TLSConfig.InsecureSkipVerify {
		t.Fatal("verified synthetic restricted-role TLS required")
	}
	roleConfig.Fallbacks = nil
	role, err := pgx.ConnectConfig(ctx, roleConfig)
	if err != nil {
		t.Fatal("synthetic restricted-role connection failed")
	}
	defer role.Close(context.Background())
	var database, adminName, roleDatabase, roleName string
	if admin.QueryRow(ctx, `SELECT current_database(),current_user`).Scan(&database, &adminName) != nil || role.QueryRow(ctx, `SELECT current_database(),current_user`).Scan(&roleDatabase, &roleName) != nil {
		t.Fatal("synthetic database identity unavailable")
	}
	if !strings.HasPrefix(database, "nex_result_fixture_") || database != roleDatabase || !strings.HasPrefix(roleName, "nex_result_fixture_") || roleName == adminName {
		t.Fatal("refusing a non-disposable database or role")
	}
	var empty, restricted bool
	if admin.QueryRow(ctx, `SELECT NOT EXISTS (SELECT FROM pg_tables WHERE schemaname='public')`).Scan(&empty) != nil || !empty {
		t.Fatal("fixture database must start empty")
	}
	if admin.QueryRow(ctx, `SELECT NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=pg_roles.oid) FROM pg_roles WHERE rolname=$1`, roleName).Scan(&restricted) != nil || !restricted {
		t.Fatal("fixture role is not restricted")
	}
	var ownsDatabase bool
	if admin.QueryRow(ctx, `SELECT d.datdba=r.oid FROM pg_database d JOIN pg_roles r ON r.rolname=$1 WHERE d.datname=current_database()`, roleName).Scan(&ownsDatabase) != nil || ownsDatabase {
		t.Fatal("fixture role must not own its database")
	}
	// Reconstruct the normally recorded pre-009 database, then preserve actual
	// v2/v3 records across 009 using the same checksum mechanism as Apply.
	names, err := fs.Glob(historicalMigrations, "00[1-8]_*.sql")
	if err != nil || len(names) != 8 {
		t.Fatal("historical migration fixture incomplete")
	}
	txHistory, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal("historical fixture transaction unavailable")
	}
	if _, err := txHistory.Exec(ctx, `CREATE TABLE schema_migrations (name text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal("historical migration record unavailable")
	}
	for _, name := range names {
		migration, err := historicalMigrations.ReadFile(name)
		if err != nil {
			t.Fatal("historical migration unavailable")
		}
		if _, err := txHistory.Exec(ctx, string(migration)); err != nil {
			t.Fatal("historical migration failed")
		}
		checksum := fmt.Sprintf("%x", sha256.Sum256(migration))
		if _, err := txHistory.Exec(ctx, `INSERT INTO schema_migrations(name,checksum) VALUES($1,$2)`, name, checksum); err != nil {
			t.Fatal("historical checksum record failed")
		}
	}
	for _, statement := range []string{
		`INSERT INTO tenants(id,name) VALUES('history-tenant','synthetic history')`,
		`INSERT INTO users(id,tenant_id,issuer,subject) VALUES('history-actor','history-tenant','https://fixture.invalid','history-subject')`,
		`INSERT INTO delegations(id,tenant_id,user_id,expires_at) VALUES('history-delegation','history-tenant','history-actor',now()+interval '1 day')`,
		`INSERT INTO jobs(id,tenant_id,delegation_id,owner_id,state) VALUES('history-job','history-tenant','history-delegation','history-actor','completed')`,
		`INSERT INTO execution_operations(id,tenant_id,job_id,kind,request_digest,status) VALUES('history-v2','history-tenant','history-job','model',repeat('2',64),'completed'),('history-v3','history-tenant','history-job','model',repeat('3',64),'completed')`,
		`INSERT INTO execution_manifests(operation_id,version,payload,payload_digest,context_digest,manifest_context,expires_at) VALUES('history-v2',2,'{"manifest_version":2,"prompt":"historical v2"}',repeat('2',64),repeat('a',64),'{"version":2,"source":"historical"}',now()+interval '1 day'),('history-v3',3,'{"manifest_version":3,"prompt":"historical v3"}',repeat('3',64),repeat('b',64),'{"version":3,"source":"historical"}',now()+interval '1 day')`,
	} {
		if _, err := txHistory.Exec(ctx, statement); err != nil {
			t.Fatal("historical fixture insertion failed")
		}
	}
	if err := txHistory.Commit(ctx); err != nil {
		t.Fatal("historical fixture commit failed")
	}
	readHistory := func() []string {
		rows, err := admin.Query(ctx, `SELECT operation_id,version,payload::text,payload_digest,manifest_context::text,context_digest FROM execution_manifests WHERE operation_id IN ('history-v2','history-v3') ORDER BY operation_id`)
		if err != nil {
			t.Fatal("historical rows unavailable")
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var id, payload, payloadDigest, contextValue, contextDigest string
			var version int
			if rows.Scan(&id, &version, &payload, &payloadDigest, &contextValue, &contextDigest) != nil {
				t.Fatal("historical rows unreadable")
			}
			out = append(out, fmt.Sprintf("%s|%d|%s|%s|%s|%s", id, version, payload, payloadDigest, contextValue, contextDigest))
		}
		if rows.Err() != nil || len(out) != 2 {
			t.Fatal("historical rows incomplete")
		}
		return out
	}
	before := readHistory()
	if err := migrations.Apply(ctx, admin); err != nil {
		t.Fatal("synthetic migrations failed")
	}
	after := readHistory()
	if before[0] != after[0] || before[1] != after[1] {
		t.Fatal("historical payload, context or digest changed")
	}
	// Use only identifier quoting for the fresh role; no credentials enter SQL.
	quoted := pgx.Identifier{roleName}.Sanitize()
	statements := []string{
		`REVOKE CREATE ON SCHEMA public FROM PUBLIC`,
		`REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC`,
		`GRANT USAGE ON SCHEMA public TO ` + quoted,
		`GRANT SELECT ON users,delegations,resources,document_bodies,model_routes,question_catalogue,jobs,execution_operations,execution_manifests,production_result_tenant_status,production_result_actor_status,production_result_sessions,production_result_identity_bindings TO ` + quoted,
		`GRANT UPDATE(lock_version) ON users,delegations,resources,document_bodies,model_routes,production_result_tenant_status,production_result_actor_status,production_result_sessions,production_result_identity_bindings TO ` + quoted,
		`GRANT UPDATE(result_access_lock_version) ON jobs,execution_operations,execution_manifests TO ` + quoted,
		`GRANT INSERT ON production_result_identity_bindings TO ` + quoted,
	}
	for _, statement := range statements {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatal("fixture grant failed")
		}
	}
	fixture := []string{
		`INSERT INTO tenants(id,name) VALUES('test-tenant','synthetic')`,
		`INSERT INTO users(id,tenant_id,issuer,subject) VALUES('test-actor','test-tenant','https://fixture.invalid','test-subject')`,
		`INSERT INTO delegations(id,tenant_id,user_id,expires_at) VALUES('test-delegation','test-tenant','test-actor',now()+interval '5 minutes')`,
		`INSERT INTO resources(id,tenant_id,kind,classification,version,reader_ids) VALUES('test-document','test-tenant','document','internal','v1',ARRAY['test-actor']),('dev-model','test-tenant','model','public','v1',ARRAY['test-actor'])`,
		`INSERT INTO document_bodies(tenant_id,resource_id,content,content_digest) VALUES('test-tenant','test-document','synthetic','b3cc0475bb78a5026098858e9889acf666d31062d513d303314eca31d36e72f2')`,
		`INSERT INTO model_routes(tenant_id,id,approved_classifications) VALUES('test-tenant','dev-model',ARRAY['internal'])`,
		`INSERT INTO jobs(id,tenant_id,delegation_id,owner_id,state,document_id,document_version,question,question_id,question_version,execution_profile) VALUES('test-job','test-tenant','test-delegation','test-actor','running','test-document','v1','synthetic','access-review-controls','v1','synthetic-qualification')`,
		`INSERT INTO execution_operations(id,tenant_id,job_id,kind,request_digest) VALUES('test-operation','test-tenant','test-job','model',repeat('a',64)),('test-bind','test-tenant','test-job','model',repeat('c',64))`,
		`INSERT INTO execution_manifests(operation_id,version,payload,payload_digest,context_digest,expires_at) VALUES('test-operation',3,'{}',repeat('a',64),repeat('b',64),now()+interval '5 minutes')`,
		`INSERT INTO production_result_tenant_status(tenant_id,enabled) VALUES('test-tenant',true)`,
		`INSERT INTO production_result_actor_status(tenant_id,actor_id,enabled) VALUES('test-tenant','test-actor',true)`,
		`INSERT INTO production_result_sessions(session_reference,issuer,subject,tenant_id,actor_id,delegation_id,expires_at) VALUES('test-session','https://fixture.invalid','test-subject','test-tenant','test-actor','test-delegation',now()+interval '5 minutes')`,
		`INSERT INTO production_result_identity_bindings(operation_id,request_digest,kind,tenant_id,actor_id,delegation_id,issuer,subject,original_session_reference) VALUES('test-operation',repeat('a',64),'model','test-tenant','test-actor','test-delegation','https://fixture.invalid','test-subject','test-session')`,
	}
	for _, statement := range fixture {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatal("synthetic fixture insertion failed")
		}
	}
	tx, err := role.Begin(ctx)
	if err != nil {
		t.Fatal("restricted transaction unavailable")
	}
	defer tx.Rollback(context.Background())
	// Exact query used by Guard job(), including all joined locks and the
	// qualification question catalogue. Separate lock probes cannot prove it.
	rows, err := tx.Query(ctx, `SELECT j.id,j.tenant_id,j.owner_id,j.delegation_id,j.document_id,j.document_version,j.question,j.question_id,j.question_version,j.execution_profile,j.answer,j.review_operation_id,j.state,j.phase,j.operation_id,j.approval_id,(j.lease_until>clock_timestamp()) AS leased,r.version AS live_version,r.classification,r.reader_ids,b.content,b.content_digest,u.permissions,q.classification AS question_classification,m.provider AS route_provider,m.region AS route_region,m.model_id AS route_model_id,m.effective_endpoint AS route_endpoint,m.features AS route_features,m.template_version AS route_template,d.permissions AS delegated_permissions,(d.revoked_at IS NULL AND d.expires_at>clock_timestamp()) AS delegation_valid FROM jobs j JOIN users u ON u.tenant_id=j.tenant_id AND u.id=j.owner_id JOIN delegations d ON d.tenant_id=j.tenant_id AND d.id=j.delegation_id AND d.user_id=j.owner_id JOIN resources r ON r.tenant_id=j.tenant_id AND r.id=j.document_id JOIN document_bodies b ON b.tenant_id=r.tenant_id AND b.resource_id=r.id JOIN model_routes m ON m.tenant_id=j.tenant_id AND m.id='dev-model' LEFT JOIN question_catalogue q ON q.id=j.question_id AND q.version=j.question_version WHERE j.id=$1 FOR UPDATE OF j FOR SHARE OF u,d,r,b,m`, "test-job")
	if err != nil || !rows.Next() {
		t.Fatal("restricted role cannot execute exact Guard job query")
	}
	rows.Close()
	rows, err = tx.Query(ctx, `SELECT o.kind,o.status,o.tenant_id,o.request_digest,m.version,m.payload,m.payload_digest,m.context_digest,m.manifest_context,(m.expires_at>clock_timestamp()) AS fresh FROM execution_operations o JOIN execution_manifests m ON m.operation_id=o.id WHERE o.id=$1 AND o.job_id=$2 AND o.tenant_id=$3 FOR SHARE OF o,m`, "test-operation", "test-job", "test-tenant")
	if err != nil || !rows.Next() {
		t.Fatal("restricted role cannot execute exact Guard operation query")
	}
	rows.Close()
	rows, err = tx.Query(ctx, `SELECT u.issuer,u.subject,ts.enabled AS tenant_enabled,us.enabled AS actor_enabled,s.issuer AS session_issuer,s.subject AS session_subject,s.tenant_id AS session_tenant,s.actor_id AS session_actor,s.delegation_id AS session_delegation,(s.revoked_at IS NULL AND s.expires_at>clock_timestamp()) AS session_current FROM users u JOIN production_result_tenant_status ts ON ts.tenant_id=u.tenant_id JOIN production_result_actor_status us ON us.tenant_id=u.tenant_id AND us.actor_id=u.id JOIN production_result_sessions s ON s.session_reference=$3 WHERE u.tenant_id=$1 AND u.id=$2 FOR SHARE OF u,ts,us,s`, "test-tenant", "test-actor", "test-session")
	if err != nil || !rows.Next() {
		t.Fatal("restricted role cannot execute exact Guard identity query")
	}
	rows.Close()
	rows, err = tx.Query(ctx, `SELECT request_digest,kind,tenant_id,actor_id,delegation_id,issuer,subject,original_session_reference FROM production_result_identity_bindings WHERE operation_id=$1 FOR SHARE`, "test-operation")
	if err != nil || !rows.Next() {
		t.Fatal("restricted role cannot execute exact Guard binding query")
	}
	rows.Close()
	for _, table := range []string{"users", "delegations", "jobs", "execution_operations", "execution_manifests", "production_result_tenant_status", "production_result_actor_status", "production_result_sessions", "production_result_identity_bindings"} {
		var ignored int
		lock := "FOR SHARE"
		if table == "jobs" {
			lock = "FOR UPDATE"
		}
		if err := tx.QueryRow(ctx, fmt.Sprintf("SELECT 1 FROM %s %s", pgx.Identifier{table}.Sanitize(), lock)).Scan(&ignored); err != nil {
			t.Fatalf("fixture lock denied on %s", table)
		}
	}
	for _, target := range []struct{ table, column string }{
		{"users", "issuer"}, {"users", "subject"}, {"users", "permissions"}, {"delegations", "permissions"}, {"delegations", "revoked_at"}, {"delegations", "expires_at"},
		{"jobs", "state"}, {"jobs", "owner_id"}, {"jobs", "delegation_id"}, {"execution_operations", "status"}, {"execution_operations", "request_digest"},
		{"execution_manifests", "payload"}, {"execution_manifests", "payload_digest"}, {"execution_manifests", "manifest_context"}, {"execution_manifests", "context_digest"},
		{"production_result_tenant_status", "enabled"}, {"production_result_actor_status", "enabled"}, {"production_result_sessions", "revoked_at"}, {"production_result_sessions", "actor_id"}, {"production_result_identity_bindings", "actor_id"}, {"production_result_identity_bindings", "original_session_reference"},
	} {
		var allowed bool
		if err := tx.QueryRow(ctx, `SELECT has_column_privilege(current_user,$1,$2,'UPDATE')`, target.table, target.column).Scan(&allowed); err != nil || allowed {
			t.Fatalf("security field unexpectedly writable: %s.%s", target.table, target.column)
		}
	}
	// Check every user column, not a hand-picked subset: effective privilege
	// includes any accidental PUBLIC or inherited privilege as well as grants.
	lockedTables := map[string]string{
		"users": "lock_version", "delegations": "lock_version", "resources": "lock_version", "document_bodies": "lock_version", "model_routes": "lock_version",
		"question_catalogue": "", "jobs": "result_access_lock_version", "execution_operations": "result_access_lock_version", "execution_manifests": "result_access_lock_version",
		"production_result_tenant_status": "lock_version", "production_result_actor_status": "lock_version", "production_result_sessions": "lock_version", "production_result_identity_bindings": "lock_version",
	}
	for table, inert := range lockedTables {
		columns, err := tx.Query(ctx, `SELECT attname FROM pg_attribute WHERE attrelid=to_regclass($1) AND attnum>0 AND NOT attisdropped ORDER BY attnum`, table)
		if err != nil {
			t.Fatal("fixture column metadata unavailable")
		}
		var names []string
		for columns.Next() {
			var name string
			if columns.Scan(&name) != nil {
				t.Fatal("fixture column metadata unreadable")
			}
			names = append(names, name)
		}
		if columns.Err() != nil || len(names) == 0 {
			t.Fatal("fixture table metadata incomplete")
		}
		columns.Close()
		for _, name := range names {
			var update, insert, references bool
			if err := tx.QueryRow(ctx, `SELECT has_column_privilege(current_user,$1,$2,'UPDATE'),has_column_privilege(current_user,$1,$2,'INSERT'),has_column_privilege(current_user,$1,$2,'REFERENCES')`, table, name).Scan(&update, &insert, &references); err != nil || update != (name == inert && inert != "") || insert != (table == "production_result_identity_bindings") || references {
				t.Fatalf("unexpected effective column privilege on %s.%s", table, name)
			}
		}
		for _, privilege := range []string{"INSERT", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"} {
			var allowed bool
			if tx.QueryRow(ctx, `SELECT has_table_privilege(current_user,$1,$2)`, table, privilege).Scan(&allowed) != nil || allowed != (privilege == "INSERT" && table == "production_result_identity_bindings") {
				t.Fatalf("unexpected %s permission on %s", privilege, table)
			}
		}
	}
	for _, table := range []string{"jobs", "execution_operations", "execution_manifests", "production_result_tenant_status", "production_result_actor_status", "production_result_sessions", "production_result_identity_bindings"} {
		for _, privilege := range []string{"DELETE", "TRUNCATE"} {
			var allowed bool
			if tx.QueryRow(ctx, `SELECT has_table_privilege(current_user,$1,$2)`, table, privilege).Scan(&allowed) != nil || allowed {
				t.Fatalf("unexpected %s permission on %s", privilege, table)
			}
		}
	}
	var canCreate bool
	if tx.QueryRow(ctx, `SELECT has_schema_privilege(current_user,'public','CREATE')`).Scan(&canCreate) != nil || canCreate {
		t.Fatal("fixture role can modify schema")
	}
	var canCreateDatabaseObjects, ownsSchema, ownsTable bool
	if tx.QueryRow(ctx, `SELECT has_database_privilege(current_user,current_database(),'CREATE'),(SELECT nspowner=(SELECT oid FROM pg_roles WHERE rolname=current_user) FROM pg_namespace WHERE nspname='public'),EXISTS(SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user))`).Scan(&canCreateDatabaseObjects, &ownsSchema, &ownsTable) != nil || canCreateDatabaseObjects || ownsSchema || ownsTable {
		t.Fatal("fixture role unexpectedly owns or can create database objects")
	}
	// The actual Bind INSERT must work under this login. The immutable binding
	// is a separate synthetic operation so the Check query above remains intact.
	inserted, err := tx.Exec(ctx, `INSERT INTO production_result_identity_bindings(operation_id,request_digest,kind,tenant_id,actor_id,delegation_id,issuer,subject,original_session_reference) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(operation_id) DO NOTHING`, "test-bind", strings.Repeat("c", 64), "model", "test-tenant", "test-actor", "test-delegation", "https://fixture.invalid", "test-subject", "test-session")
	if err != nil || inserted.RowsAffected() != 1 {
		t.Fatal("restricted role cannot insert the exact Guard binding")
	}
	var count int
	if tx.QueryRow(ctx, `SELECT count(*) FROM production_result_identity_bindings`).Scan(&count) != nil || count != 2 {
		t.Fatal("unexpected synthetic binding insertion count")
	}
	// A revocation transaction must wait for the same session row locked by the
	// Guard query, then become visible after that transaction ends. This does
	// not prove a distributed session or effect fence.
	var holderPID int32
	if tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&holderPID) != nil {
		t.Fatal("restricted backend unavailable")
	}
	revoker, err := admin.Acquire(ctx)
	if err != nil {
		t.Fatal("synthetic revoker connection unavailable")
	}
	defer revoker.Release()
	var revokerPID int32
	if revoker.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&revokerPID) != nil {
		t.Fatal("synthetic revoker backend unavailable")
	}
	updated := make(chan error, 1)
	go func() {
		_, err := revoker.Exec(ctx, `UPDATE production_result_sessions SET revoked_at=clock_timestamp() WHERE session_reference='test-session'`)
		updated <- err
	}()
	blocked := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := admin.QueryRow(ctx, `SELECT $1::integer = ANY(pg_blocking_pids($2::integer))`, holderPID, revokerPID).Scan(&blocked); err != nil {
			t.Fatal("fixture blocking state unavailable")
		}
		if blocked {
			break
		}
		select {
		case <-updated:
			t.Fatal("session revocation did not wait for the held row lock")
		case <-time.After(20 * time.Millisecond):
		}
	}
	if !blocked {
		t.Fatal("synthetic revoker never reached the expected row lock")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("restricted transaction did not finish")
	}
	select {
	case err := <-updated:
		if err != nil {
			t.Fatal("synthetic session revocation failed")
		}
	case <-ctx.Done():
		t.Fatal("synthetic session revocation remained blocked")
	}
	var revoked bool
	if err := role.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM production_result_sessions WHERE session_reference='test-session'`).Scan(&revoked); err != nil || !revoked {
		t.Fatal("revocation not visible after the locking transaction")
	}
}
