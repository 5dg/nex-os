package qualification_test

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/5dg/nex-os/packages/trust"
	"github.com/5dg/nex-os/tests/qualification/fixtures/pki"
)

func identityConfig(t *testing.T, ca *pki.Authority, role trust.Role, spec pki.Spec) (*trust.Config, pki.Identity) {
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
	return cfg, leaf
}
func workloadServer(t *testing.T, cfg *trust.Config, allowed []trust.Role, effects *atomic.Int32) *httptest.Server {
	t.Helper()
	tlsConfig, e := cfg.ServerTLS(true)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(cfg.Middleware(allowed, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { effects.Add(1); io.WriteString(w, "ok") })))
	server.TLS = tlsConfig
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}
func callWorkload(t *testing.T, client *http.Client, endpoint string, spoof bool) (int, error) {
	t.Helper()
	request, e := http.NewRequest("POST", endpoint, strings.NewReader(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	if spoof {
		request.Header.Set("X-Nex-Peer-Role", "control")
		request.Header.Set("X-Forwarded-Client-Cert", "spiffe://nex.local/service/control")
		request.Header.Set("Authorization", "Bearer control")
	}
	response, e := client.Do(request)
	if e != nil {
		return 0, e
	}
	defer response.Body.Close()
	if _, e = io.Copy(io.Discard, response.Body); e != nil {
		return response.StatusCode, e
	}
	return response.StatusCode, nil
}

// Shared transport must prove both a valid peer and endpoint role. These are
// real HTTP/TLS boundaries, not substitutes for separate Rust/manifest tests.
func TestWorkloadCertificateDoesNotGrantOtherEndpointRoles(t *testing.T) {
	ca, e := pki.NewAuthority("workload boundary")
	if e != nil {
		t.Fatal(e)
	}
	model, _ := identityConfig(t, ca, trust.Model, pki.Spec{Name: "model", IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ClientAuth: true, ServerAuth: true})
	var effects atomic.Int32
	server := workloadServer(t, model, []trust.Role{trust.Control}, &effects)
	control, _ := identityConfig(t, ca, trust.Control, pki.Spec{Name: "control", ClientAuth: true})
	client, e := control.HTTPClient(trust.Model, 3*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if status, e := callWorkload(t, client, server.URL, false); e != nil || status != 200 || effects.Load() != 1 {
		t.Fatalf("positive authenticated control failed: HTTP=%d effects=%d err=%v", status, effects.Load(), e)
	}
	worker, _ := identityConfig(t, ca, trust.Worker, pki.Spec{Name: "control", ClientAuth: true})
	workerClient, e := worker.HTTPClient(trust.Model, 3*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if status, e := callWorkload(t, workerClient, server.URL, true); e != nil || status != 403 {
		t.Fatalf("worker impersonated control: HTTP=%d err=%v", status, e)
	}
	wrongPeer, e := control.HTTPClient(trust.Guard, 3*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if status, e := callWorkload(t, wrongPeer, server.URL, false); e == nil {
		t.Fatalf("unexpected server role accepted HTTP=%d", status)
	}
	anonymous := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.Pool(), MinVersion: tls.VersionTLS13}}}
	if status, e := callWorkload(t, anonymous, server.URL, true); e == nil {
		t.Fatalf("missing client identity accepted HTTP=%d", status)
	}
	if status, e := callWorkload(t, client, strings.Replace(server.URL, "https://", "http://", 1), false); e == nil {
		t.Fatalf("plaintext downgrade accepted HTTP=%d", status)
	}
	if effects.Load() != 1 {
		t.Fatal("denied transport/role reached effect", effects.Load())
	}
}

func TestEstablishedWorkloadConnectionsCannotOutliveCertificateValidity(t *testing.T) {
	for _, expiredSide := range []string{"caller", "server"} {
		t.Run(expiredSide, func(t *testing.T) {
			ca, e := pki.NewAuthority("expiry boundary")
			if e != nil {
				t.Fatal(e)
			}
			// Whole-second X.509 timestamps give at least two seconds for the positive
			// handshake. The second request deliberately reuses that exact connection.
			deadline := time.Now().UTC().Truncate(time.Second).Add(3 * time.Second)
			serverSpec := pki.Spec{Name: "model", IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ClientAuth: true, ServerAuth: true}
			callerSpec := pki.Spec{Name: "control", ClientAuth: true}
			if expiredSide == "server" {
				serverSpec.NotAfter = deadline
			} else {
				callerSpec.NotAfter = deadline
			}
			model, _ := identityConfig(t, ca, trust.Model, serverSpec)
			_, callerLeaf := identityConfig(t, ca, trust.Control, callerSpec)
			var effects atomic.Int32
			server := workloadServer(t, model, []trust.Role{trust.Control}, &effects)
			// A raw client intentionally does not implement the product's own expiry
			// check, proving that the receiving middleware itself rechecks each request.
			transport := &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{callerLeaf.Certificate}, RootCAs: ca.Pool(), MinVersion: tls.VersionTLS13}, MaxConnsPerHost: 1, ForceAttemptHTTP2: false}
			defer transport.CloseIdleConnections()
			client := &http.Client{Timeout: 3 * time.Second, Transport: transport}
			if status, e := callWorkload(t, client, server.URL, false); e != nil || status != 200 {
				t.Fatalf("expiry positive control failed HTTP=%d err=%v", status, e)
			}
			time.Sleep(time.Until(deadline.Add(100 * time.Millisecond)))
			reused := false
			request, e := http.NewRequest("POST", server.URL, strings.NewReader(`{}`))
			if e != nil {
				t.Fatal(e)
			}
			request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
			response, e := client.Do(request)
			if e != nil {
				t.Fatal("expected role middleware response on existing TLS connection", e)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if !reused || response.StatusCode != 403 || effects.Load() != 1 {
				t.Fatalf("expired identity reused authority: reused=%v HTTP=%d effects=%d", reused, response.StatusCode, effects.Load())
			}
		})
	}
}

func TestWorkloadHTTPResponseCannotOutliveServerIdentity(t *testing.T) {
	ca, e := pki.NewAuthority("response identity")
	if e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().UTC().Truncate(time.Second).Add(2 * time.Second)
	model, _ := identityConfig(t, ca, trust.Model, pki.Spec{Name: "model", IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ClientAuth: true, ServerAuth: true, NotAfter: deadline})
	control, _ := identityConfig(t, ca, trust.Control, pki.Spec{Name: "control", ClientAuth: true})
	tlsConfig, e := model.ServerTLS(true)
	if e != nil {
		t.Fatal(e)
	}
	release := make(chan struct{})
	served := make(chan bool, 1)
	server := httptest.NewUnstartedServer(model.Middleware([]trust.Role{trust.Control}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			served <- false
			return
		}
		_, e := io.WriteString(w, `{"result":"must not be accepted after peer expiry"}`)
		served <- e == nil
	})))
	server.TLS = tlsConfig
	server.StartTLS()
	defer server.Close()
	client, e := control.HTTPClient(trust.Model, 3*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	response, e := client.Get(server.URL)
	if e != nil || response.StatusCode != 200 {
		t.Fatal("response header positive control failed", e)
	}
	defer response.Body.Close()
	type readResult struct {
		body []byte
		err  error
	}
	result := make(chan readResult, 1)
	go func() { body, e := io.ReadAll(response.Body); result <- readResult{body, e} }()
	time.Sleep(time.Until(deadline.Add(100 * time.Millisecond)))
	close(release)
	read := <-result
	if !<-served {
		t.Fatal("upstream body was never actually served")
	}
	if !errors.Is(read.err, trust.ErrIdentity) || len(read.body) != 0 {
		t.Fatalf("expired upstream body accepted: bytes=%d error=%v", len(read.body), read.err)
	}
}
