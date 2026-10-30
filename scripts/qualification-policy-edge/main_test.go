package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/5dg/nex-os/packages/policyedge"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func policyHandler(transport http.RoundTripper) http.Handler {
	return policyedge.Handler(transport, func(*http.Request) error { return nil })
}
func TestOnlyImmutableSourceAndDecisionRoutesReachOPA(t *testing.T) {
	calls := 0
	h := policyHandler(roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "127.0.0.1:8182" || r.URL.Scheme != "http" {
			t.Fatal("policy target not confined to loopback")
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Forwarded") != "" {
			t.Fatal("forwarded authority reached engine")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	}))
	for _, test := range []struct {
		method, path string
		want         int
	}{{"GET", "/v1/policies", 200}, {"POST", "/v1/data/nex/authz/decision", 200}, {"PUT", "/v1/policies/guard", 403}, {"DELETE", "/v1/policies/guard", 403}, {"POST", "/v1/policies", 403}, {"GET", "/v1/data/nex/authz/decision", 403}, {"POST", "/v1/data/other", 403}, {"GET", "/v1/policies?pretty=true", 403}, {"GET", "/health", 403}} {
		t.Run(test.method+test.path, func(t *testing.T) {
			r := httptest.NewRequest(test.method, test.path, strings.NewReader(`{"input":{}}`))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer forged")
			r.Header.Set("Forwarded", "host=forged")
			w := httptest.NewRecorder()
			before := calls
			h.ServeHTTP(w, r)
			if w.Code != test.want {
				t.Fatalf("%d want%d", w.Code, test.want)
			}
			if test.want != 200 && calls != before {
				t.Fatal("management endpoint reached policy engine")
			}
		})
	}
}
