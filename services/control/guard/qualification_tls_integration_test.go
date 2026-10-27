//go:build integration

package guard_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/5dg/nex-os/packages/contracts/gen/guardv1"
	"github.com/5dg/nex-os/packages/trust"
	"github.com/5dg/nex-os/policies"
	guardclient "github.com/5dg/nex-os/services/control/guard"
	"github.com/5dg/nex-os/tests/qualification/fixtures/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type qualProcessLog struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *qualProcessLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if b.buffer.Len() < 4096 {
		limit := 4096 - b.buffer.Len()
		if len(p) > limit {
			p = p[:limit]
		}
		b.buffer.Write(p)
	}
	return n, nil
}
func (b *qualProcessLog) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.buffer.String() }
func qualIdentity(t *testing.T, ca *pki.Authority, role trust.Role, spec pki.Spec) (*trust.Config, pki.Identity, pki.Files) {
	t.Helper()
	if len(spec.URIs) == 0 {
		spec.URIs = []string{role.URI()}
	}
	leaf, e := ca.Issue(spec)
	if e != nil {
		t.Fatal(e)
	}
	files, e := ca.WriteFiles(t.TempDir(), string(role), leaf)
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := trust.LoadFiles(trust.Qualification, role, files.CA, files.Certificate, files.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	return cfg, leaf, files
}

type qualificationKernel struct {
	decisionReplies atomic.Int32
	ca              *pki.Authority
	address         string
	calls           atomic.Int32
	delay           atomic.Bool
	entered         chan struct{}
	release         chan struct{}
}

// The process has complete qualification CONFIGURATION, but deliberately no
// reachable state/signer. Only nonempty-action Evaluate is tested here. This
// proves transport/peer/source policy boundaries, never readiness or execution.
func startQualificationKernel(t *testing.T, opaExpiry ...time.Time) *qualificationKernel {
	t.Helper()
	binary := os.Getenv("NEX_TEST_GUARD_BINARY")
	if binary == "" {
		t.Fatal("NEX_TEST_GUARD_BINARY required")
	}
	ca, e := pki.NewAuthority("Rust workload fixture")
	if e != nil {
		t.Fatal(e)
	}
	q := &qualificationKernel{ca: ca, entered: make(chan struct{}, 1), release: make(chan struct{})}
	opaSpec := pki.Spec{Name: "opa", IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ServerAuth: true}
	if len(opaExpiry) > 1 {
		t.Fatal("at most one OPA expiry fixture")
	}
	if len(opaExpiry) == 1 {
		opaSpec.NotAfter = opaExpiry[0]
	}
	opa, _, _ := qualIdentity(t, ca, trust.OPA, opaSpec)
	opaTLS, e := opa.ServerTLS(true)
	if e != nil {
		t.Fatal(e)
	}
	policy := httptest.NewUnstartedServer(opa.Middleware([]trust.Role{trust.Guard}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q.calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/policies" {
			json.NewEncoder(w).Encode(map[string]any{"result": []any{map[string]any{"raw": string(policies.Source)}}})
			return
		}
		if q.delay.Load() {
			select {
			case q.entered <- struct{}{}:
			default:
			}
			select {
			case <-q.release:
			case <-r.Context().Done():
				return
			}
		}
		if e := json.NewEncoder(w).Encode(map[string]any{"result": map[string]string{"effect": "deny", "reason_code": "QUALIFICATION_FIXTURE_DENY", "policy_version": "alpha-guard-v1"}}); e == nil {
			q.decisionReplies.Add(1)
		}
	})))
	policy.TLS = opaTLS
	policy.StartTLS()
	t.Cleanup(policy.Close)
	_, _, guardFiles := qualIdentity(t, ca, trust.Guard, pki.Spec{Name: "guard", IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ClientAuth: true, ServerAuth: true})
	directory := t.TempDir()
	public, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	writer := make([]byte, 32)
	if _, e = rand.Read(writer); e != nil {
		t.Fatal(e)
	}
	writerPath := filepath.Join(directory, "writer-key")
	publicPath := filepath.Join(directory, "writer-public")
	if e = os.WriteFile(writerPath, writer, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(publicPath, public, 0644); e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	q.address = listener.Addr().String()
	listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, binary)
	diagnostic := &qualProcessLog{}
	command.Stderr = diagnostic
	command.Stdout = diagnostic
	for _, item := range os.Environ() {
		name, _, _ := strings.Cut(item, "=")
		remove := name == "APP_ENV" || name == "NEX_PROFILE" || name == "GUARD_MODE" || strings.HasPrefix(name, "GUARD_") || strings.HasPrefix(name, "MODEL_") || strings.HasPrefix(name, "EXPORT_") || strings.HasPrefix(name, "DATABASE_") || strings.HasPrefix(name, "OPA_") || strings.HasPrefix(name, "EVIDENCE_") || strings.HasPrefix(name, "NEX_TLS_") || strings.HasPrefix(name, "NEX_DB_")
		if !remove {
			command.Env = append(command.Env, item)
		}
	}
	command.Env = append(command.Env, "APP_ENV=development", "NEX_PROFILE=synthetic-qualification", "GUARD_MODE=execution", "MODEL_PROVIDER=development", "GUARD_LISTEN_ADDR="+q.address, "OPA_URL="+policy.URL, "DATABASE_URL=postgres://fixture:fixture@postgres:5432/nex?sslmode=verify-full", "NEX_DB_CA_FILE="+guardFiles.CA, "NEX_TLS_CA_FILE="+guardFiles.CA, "NEX_TLS_CERT_FILE="+guardFiles.Certificate, "NEX_TLS_KEY_FILE="+guardFiles.PrivateKey, "EVIDENCE_URL=https://127.0.0.1:1", "EVIDENCE_KEY_FILE="+writerPath, "EVIDENCE_PUBLIC_FILE="+publicPath)
	if e = command.Start(); e != nil {
		cancel()
		t.Fatal(e)
	}
	t.Cleanup(func() { cancel(); command.Wait() })
	ready := false
	for i := 0; i < 100; i++ {
		connection, e := net.DialTimeout("tcp", q.address, 50*time.Millisecond)
		if e == nil {
			connection.Close()
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("qualification Rust listener failed to start: %s", diagnostic.String())
	}
	return q
}
func qualPB(t *testing.T, address string, cfg *tls.Config) pb.GuardClient {
	t.Helper()
	connection, e := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(cfg)), grpc.WithDisableRetry())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { connection.Close() })
	return pb.NewGuardClient(connection)
}
func qualEvaluate(ctx context.Context, client pb.GuardClient) error {
	_, e := client.Evaluate(ctx, &pb.EvaluateRequest{Action: "qualification.test"})
	return e
}

func TestQualificationRustWorkloadRoleBoundary(t *testing.T) {
	q := startQualificationKernel(t)
	control, controlLeaf, _ := qualIdentity(t, q.ca, trust.Control, pki.Spec{Name: "control", ClientAuth: true})
	c, e := guardclient.NewRPCWithTrust(q.address, nil, control)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	decision, e := c.Evaluate(ctx, guardclient.Input{Action: "qualification.test"})
	if e != nil || decision.Effect != "deny" || q.calls.Load() != 2 {
		t.Fatalf("positive control did not reach pinned authenticated policy: calls=%d error=%v", q.calls.Load(), e)
	}
	for _, role := range []trust.Role{trust.Workspace, trust.Worker, trust.Model, trust.Export} {
		t.Run("wrong RPC role "+string(role), func(t *testing.T) {
			cfg, _, _ := qualIdentity(t, q.ca, role, pki.Spec{Name: "control", ClientAuth: true})
			tlsConfig, e := cfg.GRPCClientTLS(trust.Guard, "127.0.0.1")
			if e != nil {
				t.Fatal(e)
			}
			client := qualPB(t, q.address, tlsConfig)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer control", "x-nex-peer-role", "control")
			if e = qualEvaluate(ctx, client); e == nil {
				t.Fatal("wrong peer role/metadata spoof accepted")
			}
		})
	}
	for _, name := range []string{"missing certificate", "untrusted caller CA", "expired caller", "wrong server name", "TLS 1.2"} {
		t.Run(name, func(t *testing.T) {
			config := &tls.Config{RootCAs: q.ca.Pool(), Certificates: []tls.Certificate{controlLeaf.Certificate}, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13}
			switch name {
			case "missing certificate":
				config.Certificates = nil
			case "untrusted caller CA":
				other, e := pki.NewAuthority("untrusted caller")
				if e != nil {
					t.Fatal(e)
				}
				leaf, e := other.Issue(pki.Spec{Name: "control", URIs: []string{trust.Control.URI()}, ClientAuth: true})
				if e != nil {
					t.Fatal(e)
				}
				config.Certificates = []tls.Certificate{leaf.Certificate}
			case "expired caller":
				leaf, e := q.ca.Issue(pki.Spec{Name: "control", URIs: []string{trust.Control.URI()}, ClientAuth: true, NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Hour)})
				if e != nil {
					t.Fatal(e)
				}
				config.Certificates = []tls.Certificate{leaf.Certificate}
			case "wrong server name":
				config.ServerName = "wrong.nex.test"
			case "TLS 1.2":
				config.MinVersion = tls.VersionTLS12
				config.MaxVersion = tls.VersionTLS12
			}
			client := qualPB(t, q.address, config)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if e := qualEvaluate(ctx, client); e == nil {
				t.Fatal("invalid TLS identity accepted")
			}
		})
	}
	t.Run("plaintext with legacy metadata", func(t *testing.T) {
		connection, e := grpc.NewClient(q.address, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDisableRetry())
		if e != nil {
			t.Fatal(e)
		}
		defer connection.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer control")
		if e = qualEvaluate(ctx, pb.NewGuardClient(connection)); e == nil {
			t.Fatal("plaintext qualification RPC accepted")
		}
	})
	if q.calls.Load() != 2 {
		t.Fatalf("rejected identities reached policy: calls=%d", q.calls.Load())
	}
}

func TestQualificationRustRechecksPeerAfterAwaitedPolicy(t *testing.T) {
	q := startQualificationKernel(t)
	deadline := time.Now().UTC().Truncate(time.Second).Add(2 * time.Second)
	control, _, _ := qualIdentity(t, q.ca, trust.Control, pki.Spec{Name: "control", ClientAuth: true, NotAfter: deadline})
	tlsConfig, e := control.GRPCClientTLS(trust.Guard, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	client := qualPB(t, q.address, tlsConfig)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if e = qualEvaluate(ctx, client); e != nil {
		t.Fatal("expiry positive control failed", e)
	}
	q.delay.Store(true)
	result := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		result <- qualEvaluate(ctx, client)
	}()
	select {
	case <-q.entered:
	case <-time.After(time.Second):
		t.Fatal("request never reached held authenticated policy")
	}
	time.Sleep(time.Until(deadline.Add(100 * time.Millisecond)))
	close(q.release)
	if e = <-result; e == nil {
		t.Fatal("expired peer retained authority after policy wait")
	}
	if q.calls.Load() != 4 {
		t.Fatalf("expiry test missed source/decision dependency: calls=%d", q.calls.Load())
	}
}

func TestQualificationRustRechecksPolicyServerAfterBody(t *testing.T) {
	deadline := time.Now().UTC().Truncate(time.Second).Add(2 * time.Second)
	q := startQualificationKernel(t, deadline)
	control, _, _ := qualIdentity(t, q.ca, trust.Control, pki.Spec{Name: "control", ClientAuth: true})
	tlsConfig, e := control.GRPCClientTLS(trust.Guard, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	client := qualPB(t, q.address, tlsConfig)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if e = qualEvaluate(ctx, client); e != nil {
		t.Fatal("policy server expiry positive control failed", e)
	}
	q.delay.Store(true)
	result := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		result <- qualEvaluate(ctx, client)
	}()
	select {
	case <-q.entered:
	case <-time.After(time.Second):
		t.Fatal("policy request did not enter held authenticated endpoint")
	}
	time.Sleep(time.Until(deadline.Add(100 * time.Millisecond)))
	close(q.release)
	e = <-result
	if q.decisionReplies.Load() != 2 || q.calls.Load() != 4 {
		t.Fatalf("policy response not actually served: replies=%d calls=%d", q.decisionReplies.Load(), q.calls.Load())
	}
	if e == nil {
		t.Fatal("expired OPA server retained authority after awaited response body")
	}
}
