//go:build integration

package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
	pb "github.com/5dg/nex-os/packages/contracts/gen/guardv1"
	"github.com/5dg/nex-os/packages/evidence"
	"github.com/5dg/nex-os/packages/trust"
	"github.com/5dg/nex-os/services/control/auth"
	"github.com/5dg/nex-os/services/control/devseed"
	"github.com/5dg/nex-os/services/control/guard"
	"github.com/5dg/nex-os/services/control/migrations"
	oidcfixture "github.com/5dg/nex-os/tests/qualification/fixtures/oidc"
	"github.com/5dg/nex-os/tests/qualification/fixtures/pki"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type callerGate struct {
	entered chan struct{}
	release chan struct{}
}

type callerGuardFixture struct {
	pb.UnimplementedGuardServer
	hold atomic.Pointer[callerGate]
}

func (g *callerGuardFixture) Evaluate(ctx context.Context, _ *pb.EvaluateRequest) (*pb.EvaluateResponse, error) {
	if hold := g.hold.Load(); hold != nil {
		select {
		case hold.entered <- struct{}{}:
		default:
		}
		select {
		case <-hold.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return &pb.EvaluateResponse{Effect: pb.Effect_ALLOW, ReasonCode: "PRIVATE_FIXTURE_ALLOW", PolicyVersion: "alpha-guard-v1", PolicyDigest: guard.Digest()}, nil
}

type callerFixture struct {
	t             *testing.T
	db            *pgxpool.Pool
	admin         *pgxpool.Pool
	schema        string
	ca            *pki.Authority
	issuer        *oidcfixture.Fixture
	guard         *callerGuardFixture
	api           *httptest.Server
	worker        []byte
	done          atomic.Pointer[chan struct{}]
	exitCancelled atomic.Bool
}

func callerIdentity(t *testing.T, ca *pki.Authority, role trust.Role, expiry time.Time, server bool) (*trust.Config, pki.Identity) {
	t.Helper()
	spec := pki.Spec{Name: string(role), URIs: []string{role.URI()}, ClientAuth: true, ServerAuth: server, NotAfter: expiry}
	if server {
		spec.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	leaf, err := ca.Issue(spec)
	if err != nil {
		t.Fatal(err)
	}
	files, err := ca.WriteFiles(t.TempDir(), string(role), leaf)
	if err != nil {
		t.Fatal(err)
	}
	config, err := trust.LoadFiles(trust.Qualification, role, files.CA, files.Certificate, files.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return config, leaf
}

// This fixture tests the control HTTP admission boundary using actual verified
// mTLS, strict API JWTs, signed evidence and disposable-schema PostgreSQL. Its
// private Guard RPC fixture is not a substitute for real Rust execution tests;
// no receiver/provider is constructed or called here.
func newCallerFixture(t *testing.T) *callerFixture {
	t.Helper()
	raw := os.Getenv("NEX_TEST_DATABASE_URL")
	if raw == "" {
		t.Fatal("NEX_TEST_DATABASE_URL required")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, raw)
	if err != nil {
		t.Fatal("fixture database configuration unavailable")
	}
	schema := "caller_" + strings.ToLower(rand.Text())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatal("cannot create caller fixture schema")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Error("caller fixture schema cleanup failed")
		}
		admin.Close()
	})
	cfg, err := pgxpool.ParseConfig(raw)
	if err != nil {
		t.Fatal("invalid fixture configuration")
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.ConnConfig.RuntimeParams["application_name"] = schema
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "3000"
	cfg.ConnConfig.RuntimeParams["lock_timeout"] = "2000"
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if err := migrations.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	ca, err := pki.NewAuthority("original HTTP caller fixture")
	if err != nil {
		t.Fatal(err)
	}
	control, _ := callerIdentity(t, ca, trust.Control, time.Now().Add(10*time.Minute), true)
	issuer := oidcfixture.NewFixture(t, oidcfixture.Config{}, ca)
	if err := devseed.Seed(ctx, db, issuer.IssuerURL); err != nil {
		t.Fatal(err)
	}
	if err := devseed.SeedQualificationWorkflow(ctx, db, issuer.IssuerURL); err != nil {
		t.Fatal(err)
	}
	issuerClient, err := control.HTTPClient(trust.OIDC, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := auth.NewAccessTokenVerifier(oidc.ClientContext(ctx, issuerClient), issuer.IssuerURL, "nex-api", "nex-workspace", "nex:access")
	if err != nil {
		t.Fatal("strict fixture API verifier unavailable")
	}
	guardTrust, _ := callerIdentity(t, ca, trust.Guard, time.Now().Add(10*time.Minute), true)
	guardTLS, err := guardTrust.ServerTLS(true)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	guardServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(guardTLS)))
	guardFixture := &callerGuardFixture{}
	pb.RegisterGuardServer(guardServer, guardFixture)
	go guardServer.Serve(listener)
	t.Cleanup(guardServer.Stop)
	policy, err := guard.NewRPCWithTrust(listener.Addr().String(), nil, control)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { policy.Close() })
	writerKey, workerKey := make([]byte, 32), make([]byte, 32)
	if _, err := rand.Read(writerKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(workerKey); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := evidence.OpenJournal(filepath.Join(t.TempDir(), "journal"), private)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { journal.Close() })
	evidenceTrust, _ := callerIdentity(t, ca, trust.Evidence, time.Now().Add(10*time.Minute), true)
	signerTLS, err := evidenceTrust.ServerTLS(true)
	if err != nil {
		t.Fatal(err)
	}
	signer := httptest.NewUnstartedServer(evidence.HandlerWithPeer(journal, writerKey, make([]byte, 32), func(r *http.Request, _ string) error {
		return evidenceTrust.CheckPeer(r.TLS, []trust.Role{trust.Control})
	}))
	signer.TLS = signerTLS
	signer.StartTLS()
	t.Cleanup(signer.Close)
	writer := broker.NewClient(signer.URL+"/append/control", "evidence.append.control", writerKey)
	writer.HTTP, err = control.HTTPClient(trust.Evidence, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	f := &callerFixture{t: t, db: db, admin: admin, schema: schema, ca: ca, issuer: issuer, guard: guardFixture, worker: workerKey}
	server := &Server{DB: db, Auth: verifier, Policy: policy, Profile: trust.Qualification, Trust: control, Environment: "development", WorkerKey: workerKey, EvidenceRPC: writer, EvidencePublic: public}
	handler := server.Handler()
	f.api = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		done := f.done.Load()
		defer func() {
			f.exitCancelled.Store(r.Context().Err() != nil)
			if done != nil {
				close(*done)
			}
		}()
		handler.ServeHTTP(w, r)
	}))
	f.api.TLS, err = control.ServerTLS(true)
	if err != nil {
		t.Fatal(err)
	}
	f.api.StartTLS()
	t.Cleanup(f.api.Close)
	return f
}

func (f *callerFixture) prepareRequest(role trust.Role, expiry time.Time, method, path string, body any, ctx context.Context) (*http.Client, *http.Request) {
	f.t.Helper()
	_, leaf := callerIdentity(f.t, f.ca, role, expiry, false)
	// Native TLS validates the handshake and Control identity; intentionally do
	// not add a client-side own-expiry check that could hide the server's reply.
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.ca.Pool(), Certificates: []tls.Certificate{leaf.Certificate}, MinVersion: tls.VersionTLS13, ServerName: "127.0.0.1"}, DisableKeepAlives: true}
	f.t.Cleanup(transport.CloseIdleConnections)
	data, err := json.Marshal(body)
	if err != nil {
		f.t.Fatal(err)
	}
	r, err := http.NewRequestWithContext(ctx, method, f.api.URL+path, bytes.NewReader(data))
	if err != nil {
		f.t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	if role == trust.Workspace {
		token, err := f.issuer.MintAccessToken("alice", nil)
		if err != nil {
			f.t.Fatal("valid fixture access JWT unavailable")
		}
		r.Header.Set("Authorization", "Bearer "+token)
	} else {
		r.Header.Set("Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString(f.worker))
	}
	return &http.Client{Transport: transport, Timeout: 8 * time.Second}, r
}

func (f *callerFixture) request(role trust.Role, expiry time.Time, method, path string, body any, ctx context.Context) (*http.Response, error) {
	f.t.Helper()
	client, request := f.prepareRequest(role, expiry, method, path, body, ctx)
	return client.Do(request)
}

func callerResponseDetail(t *testing.T, response *http.Response, err error) (int, string) {
	t.Helper()
	if err != nil {
		t.Fatalf("native verified TLS request failed: %v", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 16384))
	if err != nil {
		t.Fatal("caller response unavailable")
	}
	var detail struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(raw, &detail)
	return response.StatusCode, detail.Code
}

func callerResponse(t *testing.T, response *http.Response, err error) int {
	t.Helper()
	status, _ := callerResponseDetail(t, response, err)
	return status
}

func TestQualifiedOriginalWorkspaceExpiryBeforeJobCommit(t *testing.T) {
	f := newCallerFixture(t)
	create := func() contracts.CreateJob {
		return contracts.CreateJob{DocumentID: "review-alice", DelegationID: "delegation-alice", QuestionCatalogueID: contracts.QualificationQuestionID, IdempotencyKey: "caller-" + rand.Text()}
	}
	r, err := f.request(trust.Workspace, time.Now().Add(5*time.Minute), "POST", "/v1/jobs", create(), context.Background())
	if status := callerResponse(t, r, err); status != 202 {
		t.Fatalf("valid Workspace positive control status %d", status)
	}
	hold := &callerGate{entered: make(chan struct{}, 1), release: make(chan struct{})}
	f.guard.hold.Store(hold)
	expiry := time.Now().Add(2 * time.Second).Truncate(time.Second)
	type outcome struct {
		r *http.Response
		e error
	}
	returned := make(chan outcome, 1)
	client, request := f.prepareRequest(trust.Workspace, expiry, "POST", "/v1/jobs", create(), context.Background())
	go func() {
		r, err := client.Do(request)
		returned <- outcome{r, err}
	}()
	select {
	case <-hold.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("held request never reached its real authenticated Guard RPC")
	}
	if !time.Now().Before(expiry) {
		t.Fatal("Workspace expired before the tested dependency boundary")
	}
	time.Sleep(time.Until(expiry.Add(50 * time.Millisecond)))
	close(hold.release)
	result := <-returned
	status, code := callerResponseDetail(t, result.r, result.e)
	var jobs int
	if err := f.db.QueryRow(context.Background(), `SELECT count(*) FROM jobs`).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	f.guard.hold.Store(nil)
	r, err = f.request(trust.Workspace, time.Now().Add(5*time.Minute), "POST", "/v1/jobs", create(), context.Background())
	if healthy := callerResponse(t, r, err); healthy != 202 {
		t.Fatalf("healthy Workspace after negative status %d", healthy)
	}
	if status != 403 || code != "DENIED_BY_POLICY" || jobs != 1 {
		t.Fatalf("original Workspace expired during awaited Guard: HTTP=%d code=%s committed_jobs=%d; want typed403 and only the earlier positive job", status, code, jobs)
	}
}

func TestQualifiedOriginalWorkerExpiryBeforeLeaseCommit(t *testing.T) {
	f := newCallerFixture(t)
	ctx := context.Background()
	queue := func() string {
		t.Helper()
		id := "caller-" + rand.Text()
		_, err := f.db.Exec(ctx, `INSERT INTO jobs(id,tenant_id,owner_id,delegation_id,state,phase,document_id,document_version,question,question_id,question_version,execution_profile,operation_id) VALUES($1,'tenant-a','alice','delegation-alice','queued','review','review-alice','v1',$2,$3,$4,'synthetic-qualification',$5)`, id, contracts.QualificationQuestion, contracts.QualificationQuestionID, contracts.QualificationQuestionVersion, rand.Text())
		if err != nil {
			t.Fatal("cannot queue untouched synthetic Worker fixture")
		}
		return id
	}
	queue()
	r, err := f.request(trust.Worker, time.Now().Add(5*time.Minute), "POST", "/internal/work/claim", struct{}{}, ctx)
	if status := callerResponse(t, r, err); status != 200 {
		t.Fatalf("valid Worker positive control status %d", status)
	}
	job := queue()
	// IDs/schema names are generated closed alphabet identifiers, never input.
	// This deterministic awaited dependency exists only in our disposable schema.
	statement := fmt.Sprintf(`CREATE FUNCTION %s.caller_hold() RETURNS trigger LANGUAGE plpgsql AS $fixture$ BEGIN IF NEW.id='%s' THEN PERFORM pg_sleep(2.2); END IF; RETURN NEW; END $fixture$`, f.schema, job)
	if _, err := f.db.Exec(ctx, statement); err != nil {
		t.Fatal("cannot create owned Worker dependency fixture")
	}
	if _, err := f.db.Exec(ctx, `CREATE TRIGGER caller_hold BEFORE UPDATE OF state ON jobs FOR EACH ROW EXECUTE FUNCTION caller_hold()`); err != nil {
		t.Fatal("cannot attach owned Worker dependency fixture")
	}
	expiry := time.Now().Add(2 * time.Second).Truncate(time.Second)
	client, request := f.prepareRequest(trust.Worker, expiry, "POST", "/internal/work/claim", struct{}{}, ctx)
	type outcome struct {
		r *http.Response
		e error
	}
	returned := make(chan outcome, 1)
	go func() {
		r, err := client.Do(request)
		returned <- outcome{r, err}
	}()
	observed := false
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		var sleeping int
		if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE application_name=$1 AND wait_event='PgSleep' AND state='active'`, f.schema).Scan(&sleeping); err != nil {
			t.Fatal("cannot observe real awaited Worker database dependency")
		}
		if sleeping > 0 {
			observed = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !observed || !time.Now().Before(expiry) {
		t.Fatal("Worker did not reach held database dependency while identity was valid")
	}
	result := <-returned
	status, code := callerResponseDetail(t, result.r, result.e)
	var state string
	var leaseAbsent bool
	if err := f.db.QueryRow(ctx, `SELECT state,lease_token IS NULL FROM jobs WHERE id=$1`, job).Scan(&state, &leaseAbsent); err != nil {
		t.Fatal("cannot inspect Worker lease after certificate expiry")
	}
	if _, err := f.db.Exec(ctx, `DROP TRIGGER caller_hold ON jobs`); err != nil {
		t.Fatal("cannot release owned Worker dependency fixture")
	}
	queue()
	r, err = f.request(trust.Worker, time.Now().Add(5*time.Minute), "POST", "/internal/work/claim", struct{}{}, ctx)
	if healthy := callerResponse(t, r, err); healthy != 200 {
		t.Fatalf("healthy Worker after negative status %d", healthy)
	}
	if status != 403 || code != "DENIED_BY_POLICY" || state != "queued" || !leaseAbsent {
		t.Fatalf("original Worker expired during awaited database write: HTTP=%d code=%s state=%s lease_absent=%v; want typed403 and queued job without lease", status, code, state, leaseAbsent)
	}
}

func TestQualifiedWorkspaceCancellationBeforeJobCommit(t *testing.T) {
	f := newCallerFixture(t)
	create := func() contracts.CreateJob {
		return contracts.CreateJob{DocumentID: "review-alice", DelegationID: "delegation-alice", QuestionCatalogueID: contracts.QualificationQuestionID, IdempotencyKey: "cancel-" + rand.Text()}
	}
	r, err := f.request(trust.Workspace, time.Now().Add(5*time.Minute), "POST", "/v1/jobs", create(), context.Background())
	if status := callerResponse(t, r, err); status != 202 {
		t.Fatalf("valid Workspace positive status %d", status)
	}
	hold := &callerGate{entered: make(chan struct{}, 1), release: make(chan struct{})}
	f.guard.hold.Store(hold)
	completed := make(chan struct{})
	f.done.Store(&completed)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, request := f.prepareRequest(trust.Workspace, time.Now().Add(5*time.Minute), "POST", "/v1/jobs", create(), ctx)
	returned := make(chan error, 1)
	go func() {
		response, err := client.Do(request)
		if response != nil {
			response.Body.Close()
		}
		returned <- err
	}()
	select {
	case <-hold.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation request never reached held authenticated RPC")
	}
	cancel()
	if err := <-returned; !errors.Is(err, context.Canceled) {
		t.Fatal("native HTTP client did not observe its actual cancellation")
	}
	select {
	case <-completed:
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled API request did not leave its handler")
	}
	if !f.exitCancelled.Load() {
		t.Fatal("server did not observe Workspace request cancellation")
	}
	var jobs int
	if err := f.db.QueryRow(context.Background(), `SELECT count(*) FROM jobs`).Scan(&jobs); err != nil || jobs != 1 {
		t.Fatal("cancelled pre-admission request committed a new job")
	}
	f.done.Store(nil)
	f.guard.hold.Store(nil)
	r, err = f.request(trust.Workspace, time.Now().Add(5*time.Minute), "POST", "/v1/jobs", create(), context.Background())
	if status := callerResponse(t, r, err); status != 202 {
		t.Fatalf("healthy Workspace after cancellation status %d", status)
	}
}

func TestQualifiedWorkerCancellationBeforeLeaseCommit(t *testing.T) {
	f := newCallerFixture(t)
	ctx := context.Background()
	queue := func() string {
		t.Helper()
		id := "cancel-" + rand.Text()
		_, err := f.db.Exec(ctx, `INSERT INTO jobs(id,tenant_id,owner_id,delegation_id,state,phase,document_id,document_version,question,question_id,question_version,execution_profile,operation_id) VALUES($1,'tenant-a','alice','delegation-alice','queued','review','review-alice','v1',$2,$3,$4,'synthetic-qualification',$5)`, id, contracts.QualificationQuestion, contracts.QualificationQuestionID, contracts.QualificationQuestionVersion, rand.Text())
		if err != nil {
			t.Fatal("cannot queue synthetic cancellation fixture")
		}
		return id
	}
	queue()
	r, err := f.request(trust.Worker, time.Now().Add(5*time.Minute), "POST", "/internal/work/claim", struct{}{}, ctx)
	if status := callerResponse(t, r, err); status != 200 {
		t.Fatalf("valid Worker positive status %d", status)
	}
	job := queue()
	statement := fmt.Sprintf(`CREATE FUNCTION %s.caller_hold() RETURNS trigger LANGUAGE plpgsql AS $fixture$ BEGIN IF NEW.id='%s' THEN PERFORM pg_sleep(2.2); END IF; RETURN NEW; END $fixture$`, f.schema, job)
	if _, err := f.db.Exec(ctx, statement); err != nil {
		t.Fatal("cannot create owned cancellation dependency")
	}
	if _, err := f.db.Exec(ctx, `CREATE TRIGGER caller_hold BEFORE UPDATE OF state ON jobs FOR EACH ROW EXECUTE FUNCTION caller_hold()`); err != nil {
		t.Fatal("cannot attach owned cancellation dependency")
	}
	completed := make(chan struct{})
	f.done.Store(&completed)
	requestCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	client, request := f.prepareRequest(trust.Worker, time.Now().Add(5*time.Minute), "POST", "/internal/work/claim", struct{}{}, requestCtx)
	returned := make(chan error, 1)
	go func() {
		response, err := client.Do(request)
		if response != nil {
			response.Body.Close()
		}
		returned <- err
	}()
	observed := false
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		var sleeping int
		if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE application_name=$1 AND wait_event='PgSleep' AND state='active'`, f.schema).Scan(&sleeping); err != nil {
			t.Fatal("cannot observe held Worker cancellation dependency")
		}
		if sleeping > 0 {
			observed = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !observed {
		t.Fatal("cancellation did not enter the actual database await")
	}
	cancel()
	if err := <-returned; !errors.Is(err, context.Canceled) {
		t.Fatal("native Worker client did not observe actual cancellation")
	}
	select {
	case <-completed:
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled Worker request did not leave its handler")
	}
	if !f.exitCancelled.Load() {
		t.Fatal("server did not observe Worker request cancellation")
	}
	var state string
	var leaseAbsent bool
	if err := f.db.QueryRow(ctx, `SELECT state,lease_token IS NULL FROM jobs WHERE id=$1`, job).Scan(&state, &leaseAbsent); err != nil || state != "queued" || !leaseAbsent {
		t.Fatalf("cancelled pre-commit Worker request: state=%s lease_absent=%v query_failed=%v request_context_cancelled_at_handler_return=%v", state, leaseAbsent, err != nil, f.exitCancelled.Load())
	}
	f.done.Store(nil)
	if _, err := f.db.Exec(ctx, `DROP TRIGGER caller_hold ON jobs`); err != nil {
		t.Fatal("cannot release owned cancellation dependency")
	}
	r, err = f.request(trust.Worker, time.Now().Add(5*time.Minute), "POST", "/internal/work/claim", struct{}{}, ctx)
	if status := callerResponse(t, r, err); status != 200 {
		t.Fatalf("healthy Worker after cancellation status %d", status)
	}
}
