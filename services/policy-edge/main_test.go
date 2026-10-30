package main

import (
	"context"
	"testing"
)

func TestCandidateCannotStartWithoutExplicitEnablementAndTrust(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("NEX_POLICY_EDGE_ENABLED", "")
	if err := run(context.Background()); err == nil {
		t.Fatal("implicit enablement accepted")
	}
	t.Setenv("NEX_POLICY_EDGE_ENABLED", "true")
	t.Setenv("NEX_POLICY_SERVER_CA_FILE", "")
	t.Setenv("NEX_POLICY_CLIENT_CA_FILE", "")
	t.Setenv("NEX_POLICY_CERT_FILE", "")
	t.Setenv("NEX_POLICY_KEY_FILE", "")
	t.Setenv("NEX_POLICY_GUARD_URI", "")
	if err := run(context.Background()); err == nil {
		t.Fatal("missing production trust accepted")
	}
	t.Setenv("APP_ENV", "development")
	if err := run(context.Background()); err == nil {
		t.Fatal("development profile accepted")
	}
}
