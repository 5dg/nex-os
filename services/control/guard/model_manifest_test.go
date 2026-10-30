package guard

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
	pb "github.com/5dg/nex-os/packages/contracts/gen/guardv1"
	"github.com/5dg/nex-os/packages/trust"
	"github.com/5dg/nex-os/tests/qualification/fixtures/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type fixtureManifestGuard struct {
	pb.UnimplementedGuardServer
	operation, digest string
	capability        []byte
	denied            atomic.Bool
	block             atomic.Bool
	calls             atomic.Int32
	delayNanos        atomic.Int64
}

func (s *fixtureManifestGuard) CheckResultAccess(ctx context.Context, r *pb.ResultAccessRequest) (*pb.ExecutionResponse, error) {
	s.calls.Add(1)
	if s.block.Load() {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if delay := time.Duration(s.delayNanos.Load()); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return &pb.ExecutionResponse{Allowed: !s.denied.Load() && r.OperationId == s.operation && r.RequestDigest == s.digest && bytes.Equal(r.ServiceCapability, s.capability)}, nil
}

func TestModelManifestAuthorityRequiresAuthenticatedExactGuardBinding(t *testing.T) {
	ca, err := pki.NewAuthority("synthetic-manifest-guard")
	if err != nil {
		t.Fatal(err)
	}
	config := func(role trust.Role, expires time.Time) *trust.Config {
		t.Helper()
		leaf, e := ca.Issue(pki.Spec{Name: string(role), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"guard"}, URIs: []string{role.URI()}, ClientAuth: true, ServerAuth: true, NotAfter: expires})
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
		return cfg
	}
	model, guard, export := config(trust.Model, time.Now().Add(time.Hour)), config(trust.Guard, time.Now().Add(time.Hour)), config(trust.Export, time.Now().Add(time.Hour))
	in := contracts.Generation{ManifestVersion: 3, OperationID: "operation-123", TenantID: "tenant-a", RouteID: "route-1", Provider: "bedrock", Region: "us-gov-west-1", ModelID: "model-1", EffectiveEndpoint: "https://endpoint.example", TemplateVersion: "template-v1", QuestionCatalogueID: "question-1", QuestionCatalogueVersion: "v1", QuestionClassification: "internal", Classification: "internal", Prompt: "synthetic", MaxTokens: 8}
	want := contracts.ExecutionDigest(in)
	serverImpl := &fixtureManifestGuard{operation: in.OperationID, digest: want, capability: []byte("signed-service-fixture")}
	serve := func(cfg *trust.Config) (string, func()) {
		t.Helper()
		serverTLS, e := cfg.ServerTLS(true)
		if e != nil {
			t.Fatal(e)
		}
		listener, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		s := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
		pb.RegisterGuardServer(s, serverImpl)
		go s.Serve(listener)
		return listener.Addr().String(), func() { s.Stop(); listener.Close() }
	}
	address, stop := serve(guard)
	defer stop()
	client, err := NewRPCWithTrust(address, nil, model)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	capability := []byte("signed-service-fixture")
	a, err := client.ModelManifestAuthority(capability)
	if err != nil {
		t.Fatal(err)
	}
	capability[0] = 'x' // constructor must not retain mutable caller bytes
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if got, e := a.AuthorizedModelDigest(ctx, in); e != nil || got != want {
		t.Fatal("valid authenticated Guard attestation denied")
	}
	changed := in
	changed.OperationID = "operation-456"
	if got, e := a.AuthorizedModelDigest(ctx, changed); !errors.Is(e, broker.ErrUnknown) || got != "" {
		t.Fatal("other operation accepted")
	}
	changed = in
	changed.TenantID = "tenant-b"
	if got, e := a.AuthorizedModelDigest(ctx, changed); !errors.Is(e, broker.ErrUnknown) || got != "" {
		t.Fatal("other tenant accepted")
	}
	changed = in
	changed.Prompt = "tampered"
	if got, e := a.AuthorizedModelDigest(ctx, changed); !errors.Is(e, broker.ErrUnknown) || got != "" {
		t.Fatal("other digest accepted")
	}
	changed = in
	changed.ManifestVersion = 2
	if _, e := a.AuthorizedModelDigest(ctx, changed); !errors.Is(e, broker.ErrUnknown) {
		t.Fatal("legacy payload accepted")
	}
	changed = in
	changed.Prompt = strings.Repeat("x", 6001)
	if _, e := a.AuthorizedModelDigest(ctx, changed); !errors.Is(e, broker.ErrUnknown) {
		t.Fatal("oversized payload accepted")
	}
	changed = in
	changed.TenantID = "tenant with space"
	if _, e := a.AuthorizedModelDigest(ctx, changed); !errors.Is(e, broker.ErrUnknown) {
		t.Fatal("invalid tenant accepted")
	}
	serverImpl.denied.Store(true)
	if _, e := a.AuthorizedModelDigest(ctx, in); !errors.Is(e, broker.ErrUnknown) {
		t.Fatal("revoked authority accepted")
	}
	serverImpl.denied.Store(false)
	previous := serverImpl.calls.Load()
	cancelled, stopContext := context.WithCancel(context.Background())
	stopContext()
	if _, e := a.AuthorizedModelDigest(cancelled, in); !errors.Is(e, broker.ErrUnknown) || serverImpl.calls.Load() != previous {
		t.Fatal("cancelled request was sent")
	}
	serverImpl.block.Store(true)
	timeout, end := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer end()
	if _, e := a.AuthorizedModelDigest(timeout, in); !errors.Is(e, broker.ErrUnknown) {
		t.Fatal("expired authority request accepted")
	}
	serverImpl.block.Store(false)
	wrongRole, err := NewRPCWithTrust(address, nil, export)
	if err != nil {
		t.Fatal(err)
	}
	defer wrongRole.Close()
	if _, e := wrongRole.ModelManifestAuthority([]byte("fixture")); !errors.Is(e, broker.ErrUnknown) {
		t.Fatal("export identity accepted as model")
	}
	wrongAddress, wrongStop := serve(export)
	defer wrongStop()
	wrongPeer, err := NewRPCWithTrust(wrongAddress, nil, model)
	if err != nil {
		t.Fatal(err)
	}
	defer wrongPeer.Close()
	wrongAuthority, err := wrongPeer.ModelManifestAuthority([]byte("signed-service-fixture"))
	if err != nil {
		t.Fatal(err)
	}
	// The original caller-owned config is mutable. A sequential profile
	// downgrade must not change the credentials retained by either transport.
	model.Profile = trust.Development
	if got, e := a.AuthorizedModelDigest(ctx, in); e != nil || got != want {
		t.Fatal("valid sealed transport stopped working after caller mutation")
	}
	beforeWrongPeer := serverImpl.calls.Load()
	if _, e := wrongAuthority.AuthorizedModelDigest(ctx, in); !errors.Is(e, broker.ErrUnknown) {
		t.Fatal("mutated caller config admitted the wrong-role server")
	}
	if serverImpl.calls.Load() != beforeWrongPeer {
		t.Fatal("service capability reached wrong-role server")
	}
	model.Profile = trust.Qualification
	original := client.RPC
	client.RPC = wrongPeer.RPC
	if got, e := a.AuthorizedModelDigest(ctx, in); e != nil || got != want {
		t.Fatal("adapter did not retain its original RPC")
	}
	client.RPC = original
	shortExpiry := time.Now().Add(4 * time.Second).Truncate(time.Second)
	shortModel := config(trust.Model, shortExpiry)
	shortClient, e := NewRPCWithTrust(address, nil, shortModel)
	if e != nil {
		t.Fatal(e)
	}
	defer shortClient.Close()
	shortAuthority, e := shortClient.ModelManifestAuthority([]byte("signed-service-fixture"))
	if e != nil {
		t.Fatal(e)
	}
	expiryCtx, expiryCancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer expiryCancel()
	if _, e := shortAuthority.AuthorizedModelDigest(expiryCtx, in); e != nil {
		t.Fatal("valid short-lived identity rejected")
	}
	serverImpl.delayNanos.Store(int64(time.Until(shortExpiry) + 100*time.Millisecond))
	if _, e := shortAuthority.AuthorizedModelDigest(expiryCtx, in); !errors.Is(e, broker.ErrUnknown) {
		t.Fatal("identity accepted after expiry during Guard call")
	}
	serverImpl.delayNanos.Store(0)
	dev, err := NewRPC("127.0.0.1:1", bytes.Repeat([]byte{1}, 32), true)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	if _, e := dev.ModelManifestAuthority([]byte("fixture")); !errors.Is(e, broker.ErrUnknown) {
		t.Fatal("non-mTLS transport accepted")
	}
}
