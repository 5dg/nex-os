package qualification_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/5dg/nex-os/services/control/auth"
	fixture "github.com/5dg/nex-os/tests/qualification/fixtures/oidc"
	oidcclient "github.com/coreos/go-oidc/v3/oidc"
)

// This proves the protocol-to-access-verifier boundary using a real HTTPS
// authorization-code exchange. It does not replace the separate workload-mTLS,
// database-membership or browser-session end-to-end checks.
func TestOIDCCodeFlowProducesOnlyAPIAccessAuthority(t *testing.T) {
	issuer := fixture.NewFixture(t, fixture.Config{IssuerURL: "https://issuer.nex.test:9444"})
	client := issuer.BrowserClient()
	verifierText := strings.Repeat("v", 64)
	challenge := pkceChallenge(verifierText)
	authorize := issuer.IssuerURL + "/authorize?" + url.Values{"client_id": {"nex-workspace"}, "redirect_uri": {"https://workspace.nex.test:9443/auth/callback"}, "response_type": {"code"}, "scope": {"openid profile nex:access"}, "state": {"fixture-state"}, "nonce": {"fixture-nonce"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}.Encode()
	callback, e := issuer.LoginAs(client, authorize, "alice", "fixture-alice-password")
	if e != nil {
		t.Fatal(e)
	}
	if callback.Query().Get("state") != "fixture-state" || callback.Query().Get("iss") != issuer.IssuerURL {
		t.Fatal("authorization response correlation failed")
	}
	secret, e := os.ReadFile(issuer.ClientSecretFile)
	if e != nil {
		t.Fatal(e)
	}
	request, e := http.NewRequest("POST", issuer.IssuerURL+"/token", strings.NewReader(url.Values{"grant_type": {"authorization_code"}, "code": {callback.Query().Get("code")}, "redirect_uri": {"https://workspace.nex.test:9443/auth/callback"}, "code_verifier": {verifierText}}.Encode()))
	if e != nil {
		t.Fatal(e)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("nex-workspace", string(secret))
	response, e := issuer.Client().Do(request)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	var tokens struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if response.StatusCode != 200 {
		t.Fatalf("positive code exchange HTTP=%d", response.StatusCode)
	}
	if e = json.NewDecoder(response.Body).Decode(&tokens); e != nil {
		t.Fatal(e)
	}
	ctx := oidcclient.ClientContext(context.Background(), issuer.Client())
	verifier, e := auth.NewAccessTokenVerifier(ctx, issuer.IssuerURL, "nex-api", "nex-workspace", "nex:access")
	if e != nil {
		t.Fatal(e)
	}
	apiRequest := func(token string) *http.Request {
		r := httptest.NewRequest("GET", "https://control/v1/me", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		return r
	}
	identity, e := verifier.Verify(apiRequest(tokens.AccessToken))
	if e != nil || identity.Issuer != issuer.IssuerURL || identity.Subject != "alice" {
		t.Fatal("access credential positive control failed", e)
	}
	if _, e = verifier.Verify(apiRequest(tokens.IDToken)); e == nil {
		t.Fatal("browser ID token became API credential")
	}
	wrong, e := issuer.MintAccessToken("alice", map[string]any{"aud": "different-api"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = verifier.Verify(apiRequest(wrong)); e == nil {
		t.Fatal("wrong API audience accepted")
	}
	if e = issuer.RotateSigningKey(true); e != nil {
		t.Fatal(e)
	}
	rotated, e := issuer.MintAccessToken("alice", nil)
	if e != nil {
		t.Fatal(e)
	}
	if identity, e = verifier.Verify(apiRequest(rotated)); e != nil || identity.Subject != "alice" {
		t.Fatal("published signing-key rotation did not revalidate", e)
	}
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
