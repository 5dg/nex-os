package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
