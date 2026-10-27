package main

import (
	"crypto/tls"
	"github.com/5dg/nex-os/packages/trust"
	"github.com/5dg/nex-os/tests/qualification/fixtures/pki"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestEdgeCanonicalBoundary(t *testing.T) {
	origin, e := canonicalOrigin("https://workspace.nex.test:9443")
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	transport := roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Scheme != "http" || r.URL.Host != "127.0.0.1:3000" || r.Host != origin.Host {
			t.Error("proxy target was not fixed loopback/public host")
		}
		for _, header := range []string{"Authorization", "Forwarded", "X-Forwarded-For", "X-Client-Role", "X-Nex-Actor", "X-Remote-User"} {
			if r.Header.Get(header) != "" {
				t.Error("untrusted identity forwarded", header)
			}
		}
		if r.Header.Get("X-Forwarded-Proto") != "https" || r.Header.Get("X-Forwarded-Host") != origin.Host {
			t.Error("canonical frontend context missing")
		}
		if r.Header.Get("X-Nex-CSRF") != "session-csrf-proof" {
			t.Error("session CSRF proof lost")
		}
		if r.Header.Get("Cookie") != "session=browser-cookie" {
			t.Error("session cookie lost")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})
	h := handler(origin, transport)
	for _, test := range []struct {
		name, method, host, supplied string
		tls                          bool
		want                         int
	}{
		{"valid session request", "POST", origin.Host, origin.String(), true, 200},
		{"OIDC callback navigation", "GET", origin.Host, "", true, 200},
		{"no TLS", "GET", origin.Host, "", false, 426},
		{"host substitution", "GET", "other.nex.test:9443", "", true, 421},
		{"cross origin mutation", "POST", origin.Host, "https://other.nex.test:9443", true, 403},
		{"missing mutation origin", "POST", origin.Host, "", true, 403},
		{"proxy tunnel", "CONNECT", origin.Host, "", true, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(test.method, "/api/session", strings.NewReader("{}"))
			r.Host = test.host
			if test.tls {
				r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
			}
			if test.supplied != "" {
				r.Header.Set("Origin", test.supplied)
			}
			r.Header.Set("Authorization", "Bearer attacker")
			r.Header.Set("Forwarded", "host=attacker;proto=http")
			r.Header.Set("X-Forwarded-For", "attacker")
			r.Header.Set("X-Client-Role", "admin")
			r.Header.Set("X-Nex-Actor", "other")
			r.Header.Set("X-Remote-User", "admin")
			r.Header.Set("Cookie", "session=browser-cookie")
			r.Header.Set("X-Nex-CSRF", "session-csrf-proof")
			before := calls
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != test.want {
				t.Fatalf("got %d want %d", w.Code, test.want)
			}
			if test.want != 200 && calls != before {
				t.Fatal("rejected request reached frontend")
			}
		})
	}
}
func TestRejectsUnboundedPublicOrigins(t *testing.T) {
	for _, value := range []string{"http://workspace.nex.test", "https://user:secret@workspace.nex.test", "https://workspace.nex.test/path", "https://workspace.nex.test?route=other", "https://workspace.nex.test#fragment", ""} {
		if _, e := canonicalOrigin(value); e == nil {
			t.Errorf("accepted origin %q", value)
		}
	}
}

func TestExistingBrowserConnectionCannotOutliveFrontendIdentity(t *testing.T) {
	ca, e := pki.NewAuthority("edge expiry test")
	if e != nil {
		t.Fatal(e)
	}
	expiry := time.Now().UTC().Truncate(time.Second).Add(2 * time.Second)
	identity, e := ca.Issue(pki.Spec{Name: "edge", DNSNames: []string{"workspace.nex.test"}, URIs: []string{trust.Workspace.URI()}, ServerAuth: true, NotAfter: expiry})
	if e != nil {
		t.Fatal(e)
	}
	files, e := ca.WriteFiles(t.TempDir(), "edge", identity)
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := trust.LoadFiles(trust.Qualification, trust.Workspace, files.CA, files.Certificate, files.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	origin, e := canonicalOrigin("https://workspace.nex.test:9443")
	if e != nil {
		t.Fatal(e)
	}
	calls := atomic.Int32{}
	proxy := roundTrip(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})
	server := httptest.NewUnstartedServer(guardedHandler(cfg, origin, proxy))
	server.TLS, e = cfg.ServerTLS(false)
	if e != nil {
		t.Fatal(e)
	}
	server.StartTLS()
	defer server.Close()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.Pool(), ServerName: "workspace.nex.test", MinVersion: tls.VersionTLS13}, ForceAttemptHTTP2: false}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	request := func() (int, bool) {
		t.Helper()
		r, _ := http.NewRequest("GET", server.URL+"/api/session", nil)
		r.Host = origin.Host
		reused := atomic.Bool{}
		r = r.WithContext(httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused.Store(info.Reused) }}))
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		return response.StatusCode, reused.Load()
	}
	if status, _ := request(); status != 200 {
		t.Fatal("positive browser request failed", status)
	}
	timer := time.NewTimer(time.Until(expiry.Add(50 * time.Millisecond)))
	<-timer.C
	if status, reused := request(); !reused || status != 503 {
		t.Fatalf("expired reused connection status=%d reused=%v", status, reused)
	}
	if calls.Load() != 1 {
		t.Fatal("expired identity forwarded another request")
	}
	// A client with a still-valid test clock must not persuade the server to
	// keep serving its expired own identity on a new TLS handshake either.
	fresh := transport.Clone()
	fresh.TLSClientConfig.Time = func() time.Time { return expiry.Add(-time.Second) }
	defer fresh.CloseIdleConnections()
	r, _ := http.NewRequest("GET", server.URL+"/api/session", nil)
	r.Host = origin.Host
	if response, e := (&http.Client{Transport: fresh, Timeout: 3 * time.Second}).Do(r); e == nil {
		response.Body.Close()
		t.Fatal("new handshake accepted expired frontend identity")
	}
}
