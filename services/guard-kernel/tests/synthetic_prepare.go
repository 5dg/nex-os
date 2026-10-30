// Synthetic Guard integration fixture preparation only. This program is never
// used by the production binary and must only target a fresh disposable DB.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/5dg/nex-os/services/control/migrations"
	"github.com/5dg/nex-os/tests/qualification/fixtures/pki"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	if os.Getenv("NEX_RESULT_TEST_DISPOSABLE") != "yes" || len(os.Args) != 2 {
		fail("explicit synthetic fixture mode required")
	}
	switch os.Args[1] {
	case "pki":
		preparePKI()
	case "database":
		prepareDatabase()
	default:
		fail("expected synthetic pki or database preparation")
	}
}
func fail(message string) { fmt.Fprintln(os.Stderr, message); os.Exit(1) }

func preparePKI() {
	root := os.Getenv("NEX_RESULT_TEST_PKI_DIR")
	base := filepath.Base(root)
	if filepath.Dir(root) != "/workspace" || !strings.HasPrefix(base, "nex-result-pki-") || len(base) < 20 {
		fail("a fresh /workspace/nex-result-pki-* directory is required")
	}
	entries := make([]pki.BundleEntry, 0, 7)
	for _, role := range []string{"guard", "control", "model", "export", "opa", "evidence"} {
		entries = append(entries, pki.BundleEntry{Name: role, DNSNames: []string{role}, URIs: []string{"spiffe://nex.local/service/" + role}, ClientAuth: true, ServerAuth: role == "guard" || role == "opa" || role == "evidence"})
	}
	// A second, independently issued certificate with the same workload role
	// models certificate replacement; it is not a production instance ID.
	entries = append(entries, pki.BundleEntry{Name: "model-rotated", DNSNames: []string{"model"}, URIs: []string{"spiffe://nex.local/service/model"}, ClientAuth: true})
	if _, err := pki.WriteBundle(root, pki.BundleConfig{ValidForSeconds: 3600, Entries: entries}); err != nil {
		fail("fresh synthetic PKI creation failed")
	}
	var controlKey, kernelKey, seed [32]byte
	for _, value := range []*[32]byte{&controlKey, &kernelKey, &seed} {
		if _, err := rand.Read(value[:]); err != nil {
			fail("synthetic evidence key generation failed")
		}
	}
	public := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	for name, value := range map[string][]byte{"evidence-control.key": controlKey[:], "evidence-kernel.key": kernelKey[:], "evidence-seed.key": seed[:], "evidence-public.key": public} {
		file, err := os.OpenFile(filepath.Join(root, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			fail("synthetic evidence key file creation failed")
		}
		if _, err = file.Write(value); err != nil {
			file.Close()
			fail("synthetic evidence key write failed")
		}
		if err = file.Close(); err != nil {
			fail("synthetic evidence key close failed")
		}
	}
	fmt.Println("Fresh synthetic workload identities created.")
}

func checkedConfig(raw string) *pgx.ConnConfig {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Hostname() != "postgres" || !strings.HasPrefix(strings.TrimPrefix(u.Path, "/"), "nex_result_fixture_") || len(u.Query()["sslmode"]) != 1 || u.Query().Get("sslmode") != "verify-full" || len(u.Query()["sslrootcert"]) != 1 || u.Query().Get("sslrootcert") == "" {
		fail("verified synthetic DB URL required")
	}
	cfg, err := pgx.ParseConfig(raw)
	if err != nil || cfg.TLSConfig == nil || cfg.TLSConfig.InsecureSkipVerify {
		fail("synthetic DB TLS configuration denied")
	}
	cfg.Fallbacks = nil
	return cfg
}

func prepareDatabase() {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	adminConfig := checkedConfig(os.Getenv("NEX_RESULT_TEST_ADMIN_DSN"))
	roleConfig := checkedConfig(os.Getenv("NEX_RESULT_TEST_GUARD_DSN"))
	if adminConfig.Database != roleConfig.Database || adminConfig.Host != roleConfig.Host || adminConfig.Port != roleConfig.Port {
		fail("fixture DB identities must target the same database")
	}
	poolConfig, err := pgxpool.ParseConfig(os.Getenv("NEX_RESULT_TEST_ADMIN_DSN"))
	if err != nil {
		fail("synthetic admin configuration unavailable")
	}
	poolConfig.ConnConfig = adminConfig
	admin, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		fail("synthetic admin connection unavailable")
	}
	defer admin.Close()
	role, err := pgx.ConnectConfig(ctx, roleConfig)
	if err != nil {
		fail("synthetic Guard login unavailable")
	}
	defer role.Close(context.Background())
	var dbName, adminName, guardDB, guardName string
	if admin.QueryRow(ctx, `SELECT current_database(),current_user`).Scan(&dbName, &adminName) != nil || role.QueryRow(ctx, `SELECT current_database(),current_user`).Scan(&guardDB, &guardName) != nil || dbName != guardDB || !strings.HasPrefix(dbName, "nex_result_fixture_") || !strings.HasPrefix(guardName, "nex_result_fixture_") || adminName == guardName {
		fail("non-synthetic database or role denied")
	}
	var empty, restricted, ownsDB bool
	if admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT FROM pg_tables WHERE schemaname='public')`).Scan(&empty) != nil || !empty {
		fail("fresh empty fixture DB required")
	}
	if admin.QueryRow(ctx, `SELECT NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=pg_roles.oid) FROM pg_roles WHERE rolname=$1`, guardName).Scan(&restricted) != nil || !restricted {
		fail("restricted Guard fixture login required")
	}
	if admin.QueryRow(ctx, `SELECT d.datdba=r.oid FROM pg_database d JOIN pg_roles r ON r.rolname=$1 WHERE d.datname=current_database()`, guardName).Scan(&ownsDB) != nil || ownsDB {
		fail("Guard fixture role must not own the database")
	}
	if err := migrations.Apply(ctx, admin); err != nil {
		fail("synthetic migration failed")
	}
	quoted := pgx.Identifier{guardName}.Sanitize()
	for _, q := range []string{
		`REVOKE CREATE ON SCHEMA public FROM PUBLIC`, `REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC`,
		`GRANT USAGE ON SCHEMA public TO ` + quoted,
		`GRANT SELECT ON users,delegations,resources,document_bodies,model_routes,question_catalogue,document_admissions,jobs,approvals,execution_operations,execution_manifests,audit_events,production_result_tenant_status,production_result_actor_status,production_result_sessions,production_result_identity_bindings TO ` + quoted,
		`GRANT UPDATE(lock_version) ON users,delegations,resources,document_bodies,model_routes,question_catalogue,document_admissions,production_result_tenant_status,production_result_actor_status,production_result_sessions,production_result_identity_bindings TO ` + quoted,
		`GRANT UPDATE(result_access_lock_version) ON jobs,execution_operations,execution_manifests TO ` + quoted,
		`GRANT UPDATE(status,result,completed_at,qualification_receiver_cert_sha256) ON execution_operations TO ` + quoted,
		`GRANT UPDATE(answer,provider,review_operation_id) ON jobs TO ` + quoted,
		`GRANT INSERT ON execution_operations,execution_manifests,audit_events TO ` + quoted,
		`GRANT UPDATE(integrity_reference) ON audit_events TO ` + quoted,
		`GRANT INSERT ON production_result_identity_bindings TO ` + quoted,
	} {
		if _, err := admin.Exec(ctx, q); err != nil {
			fail("synthetic role grant failed")
		}
	}
	for _, q := range []string{
		`INSERT INTO tenants(id,name) VALUES('tenant-a','synthetic')`,
		`INSERT INTO users(id,tenant_id,issuer,subject,permissions) VALUES('test-actor','tenant-a','https://fixture.invalid','test-subject',ARRAY['document.read','model.invoke'])`,
		`INSERT INTO delegations(id,tenant_id,user_id,permissions,expires_at) VALUES('test-delegation','tenant-a','test-actor',ARRAY['document.read','model.invoke'],now()+interval '5 minutes')`,
		`INSERT INTO resources(id,tenant_id,kind,classification,version,reader_ids) VALUES('test-document','tenant-a','document','internal','v1',ARRAY['test-actor']),('dev-model','tenant-a','model','public','v1',ARRAY['test-actor'])`,
		`INSERT INTO document_bodies(tenant_id,resource_id,content,content_digest) VALUES('tenant-a','test-document','synthetic','b3cc0475bb78a5026098858e9889acf666d31062d513d303314eca31d36e72f2')`,
		`INSERT INTO document_admissions(tenant_id,resource_id,version,content_digest,profile) VALUES('tenant-a','test-document','v1','b3cc0475bb78a5026098858e9889acf666d31062d513d303314eca31d36e72f2','synthetic-qualification')`,
		`INSERT INTO model_routes(tenant_id,id,approved_classifications,template_version) VALUES('tenant-a','dev-model',ARRAY['internal'],'review-template-v2')`,
		`INSERT INTO jobs(id,tenant_id,delegation_id,owner_id,state,document_id,document_version,question,question_id,question_version,execution_profile,operation_id,lease_until) VALUES('fixture-job','tenant-a','test-delegation','test-actor','running','test-document','v1','synthetic','access-review-controls','v1','synthetic-qualification','operation-v3-123',now()+interval '5 minutes')`,
		`INSERT INTO jobs(id,tenant_id,delegation_id,owner_id,state,document_id,document_version,question,question_id,question_version,execution_profile,operation_id,lease_until) VALUES('fixture-claim-job','tenant-a','test-delegation','test-actor','running','test-document','v1','What access review and export controls apply?','access-review-controls','v1','synthetic-qualification','operation-claim-123',now()+interval '5 minutes')`,
		`INSERT INTO production_result_tenant_status(tenant_id,enabled) VALUES('tenant-a',true)`,
		`INSERT INTO production_result_actor_status(tenant_id,actor_id,enabled) VALUES('tenant-a','test-actor',true)`,
		`INSERT INTO production_result_sessions(session_reference,issuer,subject,tenant_id,actor_id,delegation_id,expires_at) VALUES('test-session','https://fixture.invalid','test-subject','tenant-a','test-actor','test-delegation',now()+interval '5 minutes')`,
	} {
		if _, err := admin.Exec(ctx, q); err != nil {
			fail("synthetic authority fixture insertion failed")
		}
	}
	var vectors []struct {
		Name, Kind, Digest string
		Payload            json.RawMessage
	}
	b, err := os.ReadFile("packages/contracts/execution-vectors.json")
	if err != nil || json.Unmarshal(b, &vectors) != nil {
		fail("synthetic digest vectors unavailable")
	}
	var vector struct {
		Name, Kind, Digest string
		Payload            json.RawMessage
	}
	for _, v := range vectors {
		if v.Name == "v3-model-synthetic" {
			vector = v
		}
	}
	if vector.Kind != "model" || vector.Digest != "6a6d7815d06aecae50ee34b5be18cc89637209f665a16f72d0e245d44af12109" {
		fail("expected synthetic digest vector absent")
	}
	manifest := map[string]any{"version": 3, "source": map[string]any{"job_id": "fixture-job", "tenant_id": "tenant-a", "owner_id": "test-actor", "delegation_id": "test-delegation"}, "operation_id": "operation-v3-123", "kind": "model", "payload_digest": vector.Digest}
	contextJSON, err := json.Marshal(manifest)
	if err != nil {
		fail("synthetic manifest encoding failed")
	}
	h := sha256.New()
	h.Write([]byte("nex.execution.context.v3\x00"))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(contextJSON)))
	h.Write(size[:])
	h.Write(contextJSON)
	contextDigest := fmt.Sprintf("%x", h.Sum(nil))
	if _, err := admin.Exec(ctx, `INSERT INTO execution_operations(id,tenant_id,job_id,kind,request_digest) VALUES('operation-v3-123','tenant-a','fixture-job','model',$1)`, vector.Digest); err != nil {
		fail("synthetic operation insertion failed")
	}
	if _, err := admin.Exec(ctx, `INSERT INTO execution_manifests(operation_id,version,payload,payload_digest,context_digest,manifest_context,expires_at) VALUES('operation-v3-123',3,$1::jsonb,$2,$3,$4::jsonb,now()+interval '5 minutes')`, string(vector.Payload), vector.Digest, contextDigest, string(contextJSON)); err != nil {
		fail("synthetic manifest insertion failed")
	}
	fmt.Println("Synthetic Guard database fixture prepared.")
}
