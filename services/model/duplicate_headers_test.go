package model

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/5dg/nex-os/packages/broker"
)

func TestQualificationRejectsAmbiguousCapabilityHeaders(t *testing.T) {
	for _, test := range []struct {
		name, header, extra, omit string
		status                    int
	}{
		{name: "duplicate authorization", header: "Authorization", extra: "Capability invalid", status: 401},
		{name: "duplicate content type", header: "Content-Type", extra: "text/plain", status: 400},
		{name: "missing authorization", omit: "Authorization", status: 401},
		{name: "missing content type", omit: "Content-Type", status: 400},
		{name: "valid single headers", status: 200},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, generator, authority := modelFixture(t)
			body, err := json.Marshal(qualifiedGeneration())
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest("POST", "/execute", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Capability "+broker.Token(s.Key, "model.execute", body))
			if test.omit != "" {
				request.Header.Del(test.omit)
			}
			if test.header != "" {
				request.Header.Add(test.header, test.extra)
			}
			response := httptest.NewRecorder()
			s.Handler().ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("got status %d, want %d", response.Code, test.status)
			}
			if test.status != 200 && (authority.calls != 0 || authority.completions != 0 || generator.calls != 0) {
				t.Fatalf("ambiguous headers reached Guard or generator: %+v %+v", authority, generator)
			}
			if test.status == 200 && (authority.calls != 1 || authority.completions != 1 || generator.calls != 1) {
				t.Fatal("valid authenticated request did not complete")
			}
		})
	}
}
