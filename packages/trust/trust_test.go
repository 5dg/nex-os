package trust_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/5dg/nex-os/packages/trust"
	"github.com/5dg/nex-os/tests/qualification/fixtures/pki"
	"google.golang.org/grpc/credentials"
)

func identity(t *testing.T, ca *pki.Authority, role trust.Role, expiry time.Time) (*trust.Config, pki.Identity) {
	t.Helper()
	leaf, e := ca.Issue(pki.Spec{Name: string(role), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, URIs: []string{role.URI()}, ClientAuth: true, ServerAuth: true, NotAfter: expiry})
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
	return cfg, leaf
}
func server(t *testing.T, cfg *trust.Config, handler http.Handler) *httptest.Server {
	t.Helper()
	transport, e := cfg.ServerTLS(true)
	if e != nil {
		t.Fatal(e)
	}
	s := httptest.NewUnstartedServer(handler)
	s.TLS = transport
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}
func TestVerifiedTLSPositiveBeforeRejections(t *testing.T) {
	ca, e := pki.NewAuthority("qualified-test")
	if e != nil {
		t.Fatal(e)
	}
	guard, _ := identity(t, ca, trust.Guard, time.Time{})
	control, controlLeaf := identity(t, ca, trust.Control, time.Time{})
	var effects atomic.Int32
	endpoint := server(t, guard, guard.Middleware([]trust.Role{trust.Control}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { effects.Add(1); w.Write([]byte("accepted")) })))
	client, e := control.HTTPClient(trust.Guard, 3*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	response, e := client.Get(endpoint.URL)
	if e != nil {
		t.Fatalf("valid TLS identity rejected: %v", e)
	}
	body, e := io.ReadAll(response.Body)
	response.Body.Close()
	if e != nil || response.StatusCode != 200 || string(body) != "accepted" || effects.Load() != 1 {
		t.Fatalf("positive failed: %d %q %v", response.StatusCode, body, e)
	}
	t.Run("wrong peer role", func(t *testing.T) {
		wrong, e := control.HTTPClient(trust.Evidence, 3*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		if response, e := wrong.Get(endpoint.URL); e == nil {
			response.Body.Close()
			t.Fatal("wrong server role accepted")
		}
	})
	t.Run("wrong client role", func(t *testing.T) {
		model, _ := identity(t, ca, trust.Model, time.Time{})
		wrong, e := model.HTTPClient(trust.Guard, 3*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		response, e := wrong.Get(endpoint.URL)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		if response.StatusCode != 403 {
			t.Fatal(response.StatusCode)
		}
	})
	t.Run("wrong CA", func(t *testing.T) {
		other, e := pki.NewAuthority("other")
		if e != nil {
			t.Fatal(e)
		}
		wrong, _ := identity(t, other, trust.Control, time.Time{})
		c, e := wrong.HTTPClient(trust.Guard, 3*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		if response, e := c.Get(endpoint.URL); e == nil {
			response.Body.Close()
			t.Fatal("wrong CA accepted")
		}
	})
	t.Run("TLS12", func(t *testing.T) {
		transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, RootCAs: ca.Pool(), Certificates: []tls.Certificate{controlLeaf.Certificate}}}
		defer transport.CloseIdleConnections()
		if response, e := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Get(endpoint.URL); e == nil {
			response.Body.Close()
			t.Fatal("TLS12 accepted")
		}
	})
	t.Run("plaintext and redirects", func(t *testing.T) {
		var leaked atomic.Int32
		plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
		defer plain.Close()
		if response, e := client.Get(plain.URL); e == nil {
			response.Body.Close()
			t.Fatal("plaintext accepted")
		}
		redirect := server(t, guard, guard.Middleware([]trust.Role{trust.Control}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, plain.URL, 302) })))
		response, e := client.Get(redirect.URL)
		if e != nil {
			t.Fatal(e)
		}
		response.Body.Close()
		if response.StatusCode != 302 || leaked.Load() != 0 {
			t.Fatal("credential client followed redirect", response.StatusCode, leaked.Load())
		}
	})
	if effects.Load() != 1 {
		t.Fatal("rejected request reached effect", effects.Load())
	}
}
func TestEstablishedConnectionIdentityExpires(t *testing.T) {
	ca, e := pki.NewAuthority("expiry-test")
	if e != nil {
		t.Fatal(e)
	}
	guard, leaf := identity(t, ca, trust.Guard, time.Now().Add(3*time.Second))
	control, _ := identity(t, ca, trust.Control, time.Time{})
	endpoint := server(t, guard, guard.Middleware([]trust.Role{trust.Control}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })))
	client, e := control.HTTPClient(trust.Guard, 5*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	response, e := client.Get(endpoint.URL)
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	rpc := control.PerRPCCredentials(trust.Guard)
	requestCtx := credentials.NewContextWithRequestInfo(context.Background(), credentials.RequestInfo{AuthInfo: credentials.TLSInfo{State: *response.TLS}})
	if _, e = rpc.GetRequestMetadata(requestCtx); e != nil {
		t.Fatal("valid established identity rejected", e)
	}
	time.Sleep(time.Until(leaf.Certificate.Leaf.NotAfter) + 30*time.Millisecond)
	if _, e = rpc.GetRequestMetadata(requestCtx); e == nil {
		t.Fatal("established identity survived expiry")
	}
	if e = guard.CheckOwn(); e == nil {
		t.Fatal("own expired identity accepted")
	}
}
func TestProfilesAndMissingTrustFailClosed(t *testing.T) {
	for _, profile := range []string{"production", "optional", "synthetic-qualification "} {
		if _, e := trust.ParseProfile(profile); e == nil {
			t.Fatal(profile)
		}
	}
	if _, e := trust.LoadFiles(trust.Qualification, trust.Control, "", "", ""); e == nil {
		t.Fatal("missing trust accepted")
	}
	cfg, e := trust.LoadFiles(trust.Development, trust.Control, "", "", "")
	if e != nil {
		t.Fatal(e)
	}
	if e = cfg.CheckURL("http://localhost:8080"); e != nil {
		t.Fatal(e)
	}
}
func TestHTTPShutdownRetainsHandlersUntilDrained(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := listener.Addr().String()
	listener.Close()
	cfg, e := trust.LoadFiles(trust.Development, trust.Control, "", "", "")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- trust.ServeHTTP(ctx, address, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-release; w.Write([]byte("finished")) }), cfg, false)
	}()
	responseDone := make(chan struct{})
	go func() {
		defer close(responseDone)
		for i := 0; i < 50; i++ {
			response, e := http.Get("http://" + address)
			if e == nil {
				io.Copy(io.Discard, response.Body)
				response.Body.Close()
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	<-started
	cancel()
	select {
	case e := <-done:
		t.Fatal("custody could release before handler", e)
	case <-time.After(60 * time.Millisecond):
	}
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	<-responseDone
}
