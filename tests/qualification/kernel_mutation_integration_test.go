//go:build integration

package qualification_test

// This suite temporarily changes the disposable qualification authority rows.
// E must schedule it after browser workflows, with no concurrent metadata tests.
// Every case preserves its prepared manifest and receipt history, restores the
// source authority, and cancels its own synthetic job without inventing outcomes.
import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/5dg/nex-os/packages/contracts"
	pb "github.com/5dg/nex-os/packages/contracts/gen/guardv1"
	"github.com/5dg/nex-os/packages/trust"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type kernelMutationRPC struct {
	client pb.GuardClient
	trust  *trust.Config
}

func kernelMutationClient(t *testing.T, state string, role trust.Role) kernelMutationRPC {
	t.Helper()
	directory := filepath.Join(state, "current-pki")
	cfg, err := trust.LoadFiles(trust.Qualification, role, filepath.Join(directory, "ca.crt"), filepath.Join(directory, string(role), "tls.crt"), filepath.Join(directory, string(role), "tls.key"))
	if err != nil {
		t.Fatal("qualification role identity unavailable")
	}
	tlsConfig, err := cfg.GRPCClientTLS(trust.Guard, "guard")
	if err != nil {
		t.Fatal("qualification Guard trust unavailable")
	}
	conn, err := grpc.NewClient("127.0.0.1:55051", grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)), grpc.WithPerRPCCredentials(cfg.PerRPCCredentials(trust.Guard)))
	if err != nil {
		t.Fatal("qualification Guard client unavailable")
	}
	t.Cleanup(func() { _ = conn.Close() })
	return kernelMutationRPC{client: pb.NewGuardClient(conn), trust: cfg}
}

func (c kernelMutationRPC) checkPeer(t *testing.T, p peer.Peer) {
	t.Helper()
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || c.trust.CheckPeer(&info.State, []trust.Role{trust.Guard}) != nil {
		t.Fatal("RPC did not retain a current authenticated Guard identity")
	}
}

func kernelMutationDatabase(t *testing.T, state string) *pgx.Conn {
	t.Helper()
	ca, err := os.ReadFile(filepath.Join(state, "current-pki", "ca.crt"))
	if err != nil {
		t.Fatal("qualification database CA unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid qualification database CA")
	}
	raw, err := os.ReadFile(filepath.Join(state, "secrets", "admin-database-url"))
	if err != nil {
		t.Fatal("disposable qualification administrator credential unavailable")
	}
	cfg, err := pgx.ParseConfig(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal("invalid private qualification database configuration")
	}
	cfg.Host, cfg.Port, cfg.ConnectTimeout, cfg.Fallbacks = "postgres", 55432, 3*time.Second, nil
	cfg.TLSConfig = &tls.Config{ServerName: "postgres", RootCAs: roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	cfg.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "postgres:55432" {
			return nil, errors.New("unexpected qualification database host")
		}
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, "127.0.0.1:55432")
	}
	cfg.LookupFunc = func(_ context.Context, host string) ([]string, error) {
		if host != "postgres" {
			return nil, errors.New("unexpected qualification database DNS")
		}
		return []string{"postgres"}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal("verified disposable qualification database connection failed")
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	if _, err := conn.Exec(ctx, `SET statement_timeout='3s'; SET lock_timeout='2s'`); err != nil {
		t.Fatal("bounded qualification database session unavailable")
	}
	return conn
}

func TestQualificationSystemKernelCurrentAuthorityMutations(t *testing.T) {
	state := os.Getenv("NEX_QUAL_STATE_DIR")
	if !filepath.IsAbs(state) {
		t.Fatal("absolute NEX_QUAL_STATE_DIR naming E's disposable stack required")
	}
	db := kernelMutationDatabase(t, state)
	control := kernelMutationClient(t, state, trust.Control)
	model := kernelMutationClient(t, state, trust.Model)
	exec := func(t *testing.T, query string, args ...any) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := db.Exec(ctx, query, args...); err != nil {
			t.Fatal("bounded qualification fixture SQL failed")
		}
	}
	query := func(t *testing.T, statement string, args ...any) pgx.Row {
		t.Helper()
		// Rows are consumed synchronously with the session's 3s statement bound.
		return db.QueryRow(context.Background(), statement, args...)
	}
	// Verify that this is the synthetic fixture, never an arbitrary admitted body.
	var originalBody, originalDigest string
	if err := query(t, `SELECT content,content_digest FROM document_bodies WHERE tenant_id='tenant-a' AND resource_id='review-alice'`).Scan(&originalBody, &originalDigest); err != nil {
		t.Fatal("synthetic qualification source absent")
	}
	expected := "SYNTHETIC TRAINING RECORD — NOT CUI. Contractor tenant-a requires quarterly access reviews. Evidence exports require an independent approver. No actual customer records are present."
	sum := sha256.Sum256([]byte(expected))
	if originalBody != expected || originalDigest != hex.EncodeToString(sum[:]) {
		t.Fatal("mutation suite refuses non-fixture source bytes")
	}
	// Restore exact observed values rather than reseeding or relabeling history.
	var provider, region, modelID, endpoint, template string
	var features []string
	if err := query(t, `SELECT provider,region,model_id,effective_endpoint,features,template_version FROM model_routes WHERE tenant_id='tenant-a' AND id='dev-model'`).Scan(&provider, &region, &modelID, &endpoint, &features, &template); err != nil {
		t.Fatal("synthetic qualification route absent")
	}
	if provider != contracts.QualificationProvider || region != contracts.QualificationRegion || modelID != contracts.QualificationModelID || endpoint != contracts.QualificationEndpoint || len(features) != 0 || template != contracts.QualificationTemplate {
		t.Fatal("mutation suite requires the exact approved qualification route")
	}
	var catalogueQuestion, catalogueClass string
	var catalogueEnabled bool
	if err := query(t, `SELECT question,classification,enabled FROM question_catalogue WHERE id=$1 AND version=$2`, contracts.QualificationQuestionID, contracts.QualificationQuestionVersion).Scan(&catalogueQuestion, &catalogueClass, &catalogueEnabled); err != nil || catalogueQuestion != contracts.QualificationQuestion || catalogueClass != contracts.QualificationQuestionClassification || !catalogueEnabled {
		t.Fatal("mutation suite requires the approved enabled question catalogue")
	}
	var admissionDigest string
	var admissionLockVersion int64
	if err := query(t, `SELECT content_digest,lock_version FROM document_admissions WHERE tenant_id='tenant-a' AND resource_id='review-alice' AND version='v1' AND profile='synthetic-qualification'`).Scan(&admissionDigest, &admissionLockVersion); err != nil || admissionDigest != originalDigest {
		t.Fatal("synthetic qualification admission absent or mismatched")
	}
	newPrepared := func(t *testing.T) (string, string, *pb.PreparedOperation) {
		t.Helper()
		id := fmt.Sprintf("qual-kernel-%d", time.Now().UnixNano())
		operation := id + "-model"
		exec(t, `INSERT INTO jobs(id,tenant_id,owner_id,delegation_id,state,phase,document_id,document_version,question,question_id,question_version,execution_profile,operation_id,lease_token,lease_until) VALUES($1,'tenant-a','alice','delegation-alice','running','review','review-alice','v1',$2,$3,$4,'synthetic-qualification',$5,$6,clock_timestamp()+interval '5 minutes')`, id, contracts.QualificationQuestion, contracts.QualificationQuestionID, contracts.QualificationQuestionVersion, operation, id+"-lease")
		t.Cleanup(func() { exec(t, `UPDATE jobs SET state='cancelled',lease_until=clock_timestamp() WHERE id=$1`, id) })
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		var remote peer.Peer
		prepared, err := control.client.PrepareExecution(ctx, &pb.PrepareRequest{JobId: id, OperationId: operation}, grpc.Peer(&remote))
		if err != nil {
			t.Fatalf("positive real Guard v3 prepare failed: %s", status.Code(err))
		}
		control.checkPeer(t, remote)
		var payload contracts.Generation
		if json.Unmarshal([]byte(prepared.PayloadJson), &payload) != nil || contracts.ValidateQualificationGeneration(payload) != nil || contracts.ExecutionDigest(payload) != prepared.RequestDigest || payload.OperationID != operation {
			t.Fatal("prepared payload is not the exact canonical qualification v3 route")
		}
		return id, operation, prepared
	}
	if !t.Run("positive_model_authority_without_receiver_effect", func(t *testing.T) {
		_, operation, prepared := newPrepared(t)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		var remote peer.Peer
		grant, err := model.client.AuthorizeExecution(ctx, &pb.ExecutionRequest{OperationId: operation, RequestDigest: prepared.RequestDigest}, grpc.Peer(&remote))
		if err != nil || !grant.GetAllowed() {
			t.Fatalf("untouched authority did not grant the real Model identity: %s", status.Code(err))
		}
		model.checkPeer(t, remote)
		var operationState string
		var resultAbsent bool
		if err := query(t, `SELECT status,result IS NULL FROM execution_operations WHERE id=$1`, operation).Scan(&operationState, &resultAbsent); err != nil || operationState != "started" || !resultAbsent {
			t.Fatal("positive authorization lacks durable started/no-outcome state")
		}
		// Intentionally stop before any model receiver call. Preserve this real
		// started grant; cancellation does not invent a result or reset history.
	}) {
		t.Fatal("positive Model authority control failed; mutation negatives would be inconclusive")
	}
	type mutation struct {
		name    string
		apply   func(*testing.T, string)
		restore func(*testing.T, string)
	}
	routeRestore := func(t *testing.T, _ string) {
		exec(t, `UPDATE model_routes SET provider=$1,region=$2,model_id=$3,effective_endpoint=$4,features=$5,template_version=$6 WHERE tenant_id='tenant-a' AND id='dev-model'`, provider, region, modelID, endpoint, features, template)
	}
	catalogueRestore := func(t *testing.T, _ string) {
		exec(t, `UPDATE question_catalogue SET question=$1,classification=$2,enabled=$3 WHERE id=$4 AND version=$5`, catalogueQuestion, catalogueClass, catalogueEnabled, contracts.QualificationQuestionID, contracts.QualificationQuestionVersion)
	}
	admissionRestore := func(t *testing.T, _ string) {
		exec(t, `INSERT INTO document_admissions(tenant_id,resource_id,version,content_digest,profile,lock_version) VALUES('tenant-a','review-alice','v1',$1,'synthetic-qualification',$2) ON CONFLICT(tenant_id,resource_id,version,profile) DO UPDATE SET content_digest=excluded.content_digest,lock_version=excluded.lock_version`, admissionDigest, admissionLockVersion)
	}
	mutations := []mutation{}
	for _, field := range []string{"provider", "region", "model_id", "effective_endpoint", "template_version"} {
		field := field // Closed source-code allowlist; no external SQL identifiers.
		mutations = append(mutations, mutation{"route_" + field, func(t *testing.T, _ string) {
			exec(t, "UPDATE model_routes SET "+field+"=$1 WHERE tenant_id='tenant-a' AND id='dev-model'", "unapproved-synthetic-value")
		}, routeRestore})
	}
	mutations = append(mutations,
		mutation{"route_features", func(t *testing.T, _ string) {
			exec(t, `UPDATE model_routes SET features=ARRAY['unapproved-feature'] WHERE tenant_id='tenant-a' AND id='dev-model'`)
		}, routeRestore},
		mutation{"job_profile_downgrade", func(t *testing.T, job string) {
			exec(t, `UPDATE jobs SET execution_profile='development' WHERE id=$1`, job)
		}, func(t *testing.T, job string) {
			exec(t, `UPDATE jobs SET execution_profile='synthetic-qualification' WHERE id=$1`, job)
		}},
		mutation{"catalogue_disabled", func(t *testing.T, _ string) {
			exec(t, `UPDATE question_catalogue SET enabled=false WHERE id=$1 AND version=$2`, contracts.QualificationQuestionID, contracts.QualificationQuestionVersion)
		}, catalogueRestore},
		mutation{"catalogue_text", func(t *testing.T, _ string) {
			exec(t, `UPDATE question_catalogue SET question='Unapproved synthetic question' WHERE id=$1 AND version=$2`, contracts.QualificationQuestionID, contracts.QualificationQuestionVersion)
		}, catalogueRestore},
		mutation{"catalogue_classification", func(t *testing.T, _ string) {
			exec(t, `UPDATE question_catalogue SET classification='public' WHERE id=$1 AND version=$2`, contracts.QualificationQuestionID, contracts.QualificationQuestionVersion)
		}, catalogueRestore},
		mutation{"admission_missing", func(t *testing.T, _ string) {
			exec(t, `DELETE FROM document_admissions WHERE tenant_id='tenant-a' AND resource_id='review-alice' AND version='v1' AND profile='synthetic-qualification'`)
		}, admissionRestore},
		mutation{"admission_digest", func(t *testing.T, _ string) {
			exec(t, `UPDATE document_admissions SET content_digest=$1 WHERE tenant_id='tenant-a' AND resource_id='review-alice' AND version='v1' AND profile='synthetic-qualification'`, strings.Repeat("0", 64))
		}, admissionRestore},
		mutation{"source_bytes_and_digest", func(t *testing.T, _ string) {
			changed := originalBody + " Additional unadmitted synthetic text."
			digest := sha256.Sum256([]byte(changed))
			exec(t, `UPDATE document_bodies SET content=$1,content_digest=$2 WHERE tenant_id='tenant-a' AND resource_id='review-alice'`, changed, hex.EncodeToString(digest[:]))
		}, func(t *testing.T, _ string) {
			exec(t, `UPDATE document_bodies SET content=$1,content_digest=$2 WHERE tenant_id='tenant-a' AND resource_id='review-alice'`, originalBody, originalDigest)
		}},
	)
	for _, test := range mutations {
		if !t.Run(test.name, func(t *testing.T) {
			id, operation, prepared := newPrepared(t)
			// Register restoration before changing any shared authority row.
			t.Cleanup(func() { test.restore(t, id) })
			test.apply(t, id)
			ctx, cancelAuthorize := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancelAuthorize()
			var remote peer.Peer
			grant, err := model.client.AuthorizeExecution(ctx, &pb.ExecutionRequest{OperationId: operation, RequestDigest: prepared.RequestDigest}, grpc.Peer(&remote))
			model.checkPeer(t, remote)
			if status.Code(err) != codes.PermissionDenied || grant != nil && grant.Allowed {
				t.Fatalf("changed %s retained execution authority: status %s", test.name, status.Code(err))
			}
			var operationState, answer, protectedProvider string
			var resultAbsent, reviewAbsent bool
			var authorizationEvents int
			if err := query(t, `SELECT o.status,o.result IS NULL,j.answer,j.provider,j.review_operation_id IS NULL,(SELECT count(*) FROM audit_events WHERE job_id=j.id AND action='model.authorized') FROM execution_operations o JOIN jobs j ON j.id=o.job_id WHERE o.id=$1`, operation).Scan(&operationState, &resultAbsent, &answer, &protectedProvider, &reviewAbsent, &authorizationEvents); err != nil {
				t.Fatal("unable to inspect denied operation state")
			}
			if operationState != "pending" || !resultAbsent || answer != "" || protectedProvider != "" || !reviewAbsent || authorizationEvents != 0 {
				t.Fatal("denial changed execution/result authority or produced an authorization event")
			}
			test.restore(t, id)
			ctx, cancelRestored := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancelRestored()
			remote = peer.Peer{}
			restored, err := control.client.PrepareExecution(ctx, &pb.PrepareRequest{JobId: id, OperationId: operation}, grpc.Peer(&remote))
			if err != nil || restored.RequestDigest != prepared.RequestDigest || restored.PayloadJson != prepared.PayloadJson {
				t.Fatalf("restored authority did not reproduce the same immutable manifest: %s", status.Code(err))
			}
			control.checkPeer(t, remote)
			// No model/export receiver is invoked. Pending proves no execution
			// grant was committed; it does not measure a receiver/provider counter.
		}) {
			t.Fatal("mutation case failed; stop before changing another shared authority row")
		}
	}
}
