package guard_test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/5dg/nex-os/packages/contracts/gen/guardv1"
	"github.com/5dg/nex-os/packages/trust"
	guardclient "github.com/5dg/nex-os/services/control/guard"
	"github.com/5dg/nex-os/tests/qualification/fixtures/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type lateReady struct {
	pb.UnimplementedGuardServer
	calls  atomic.Int32
	expire time.Time
}

func (f *lateReady) CheckReadiness(context.Context, *pb.ReadinessRequest) (*pb.ReadinessResponse, error) {
	if f.calls.Add(1) > 1 {
		time.Sleep(time.Until(f.expire) + 40*time.Millisecond)
	}
	return &pb.ReadinessResponse{Ready: true, Profile: string(trust.Qualification)}, nil
}
func TestRPCResponseTrustRecheckedAfterAwait(t *testing.T) {
	for _, expiring := range []trust.Role{trust.Control, trust.Guard} {
		t.Run(string(expiring), func(t *testing.T) {
			ca, e := pki.NewAuthority("response-expiry")
			if e != nil {
				t.Fatal(e)
			}
			expires := time.Now().Add(4 * time.Second).Truncate(time.Second)
			config := func(role trust.Role) *trust.Config {
				until := time.Now().Add(time.Hour)
				if role == expiring {
					until = expires
				}
				leaf, e := ca.Issue(pki.Spec{Name: string(role), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"guard"}, URIs: []string{role.URI()}, ClientAuth: true, ServerAuth: true, NotAfter: until})
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
			control := config(trust.Control)
			guard := config(trust.Guard)
			serverTLS, e := guard.ServerTLS(true)
			if e != nil {
				t.Fatal(e)
			}
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			fixture := &lateReady{expire: expires}
			server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
			pb.RegisterGuardServer(server, fixture)
			go server.Serve(listener)
			defer server.Stop()
			client, e := guardclient.NewRPCWithTrust(listener.Addr().String(), nil, control)
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if e = client.Readiness(ctx); e != nil {
				t.Fatal("positive mTLS RPC failed before expiry", e)
			}
			if e = client.Readiness(ctx); e == nil {
				t.Fatal("RPC accepted response after identity expiry")
			}
			if fixture.calls.Load() != 2 {
				t.Fatal("test did not reach awaited response", fixture.calls.Load())
			}
		})
	}
}
