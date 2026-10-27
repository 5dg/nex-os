package oidc

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

func authorization(f *Fixture, verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return f.IssuerURL + "/authorize?" + url.Values{"client_id": {"nex-workspace"}, "redirect_uri": {"https://workspace.nex.test:9443/auth/callback"}, "response_type": {"code"}, "scope": {"openid profile nex:access"}, "state": {"state-correlation"}, "nonce": {"id-nonce"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}}.Encode()
}
func tokenRequest(t *testing.T, f *Fixture, callback *url.URL, verifier, secret string, want int) map[string]any {
	t.Helper()
	request, e := http.NewRequest("POST", f.IssuerURL+"/token", strings.NewReader(url.Values{"grant_type": {"authorization_code"}, "code": {callback.Query().Get("code")}, "redirect_uri": {"https://workspace.nex.test:9443/auth/callback"}, "code_verifier": {verifier}}.Encode()))
	if e != nil {
		t.Fatal(e)
	}
	request.SetBasicAuth("nex-workspace", secret)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, e := f.Client().Do(request)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	var result map[string]any
	if e = json.NewDecoder(response.Body).Decode(&result); e != nil {
		t.Fatal(e)
	}
	if response.StatusCode != want {
		t.Fatalf("token HTTP %d want%d error=%v", response.StatusCode, want, result["error"])
	}
	return result
}
func claims(t *testing.T, f *Fixture, raw string) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatal("JWS shape")
	}
	enc := base64.RawURLEncoding
	var header, claim map[string]any
	h, e := enc.DecodeString(parts[0])
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(h, &header); e != nil {
		t.Fatal(e)
	}
	b, e := enc.DecodeString(parts[1])
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &claim); e != nil {
		t.Fatal(e)
	}
	f.Issuer.mu.Lock()
	key := f.Issuer.keys[header["kid"].(string)]
	f.Issuer.mu.Unlock()
	if key == nil {
		t.Fatal("missing published signing key")
	}
	sig, e := enc.DecodeString(parts[2])
	if e != nil {
		t.Fatal(e)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if e = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); e != nil {
		t.Fatal("real RSA signature invalid", e)
	}
	return header, claim
}
func TestCodeFlowRequiresCredentialsPKCEClientAndExactRedirect(t *testing.T) {
	f := NewFixture(t, Config{})
	client := f.BrowserClient()
	verifier := strings.Repeat("v", 64)
	callback, e := f.LoginAs(client, authorization(f, verifier), "alice", "wrong-password")
	if e == nil || callback != nil {
		t.Fatal("wrong synthetic credentials accepted")
	}
	callback, e = f.LoginAs(client, authorization(f, verifier), "alice", "fixture-alice-password")
	if e != nil {
		t.Fatal(e)
	}
	if callback.Query().Get("state") != "state-correlation" || callback.Query().Get("code") == "" || callback.Query().Get("access_token") != "" {
		t.Fatal("authorization callback leaked or lost state")
	}
	secret, e := os.ReadFile(f.ClientSecretFile)
	if e != nil {
		t.Fatal(e)
	}
	tokenRequest(t, f, callback, verifier, "wrong-secret", 401)
	tokenRequest(t, f, callback, strings.Repeat("x", 64), string(secret), 400)
	result := tokenRequest(t, f, callback, verifier, string(secret), 200)
	ah, access := claims(t, f, result["access_token"].(string))
	ih, id := claims(t, f, result["id_token"].(string))
	if ah["typ"] != "at+jwt" || access["aud"] != "nex-api" || access["client_id"] != "nex-workspace" || access["scope"] != "nex:access" || access["sub"] != "alice" {
		t.Fatal("access token contract changed")
	}
	if ih["typ"] != "JWT" || id["aud"] != "nex-workspace" || id["nonce"] != "id-nonce" || id["sub"] != "alice" {
		t.Fatal("ID token contract changed")
	}
	tokenRequest(t, f, callback, verifier, string(secret), 400)
	bad, _ := url.Parse(authorization(f, verifier))
	q := bad.Query()
	q.Set("redirect_uri", "https://attacker.test/callback")
	bad.RawQuery = q.Encode()
	response, e := f.Client().Get(bad.String())
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 400 {
		t.Fatal("unregistered redirect accepted")
	}
}
func TestHTTPSAndGoOnlyNegativeTokenHooks(t *testing.T) {
	f := NewFixture(t, Config{IssuerURL: "https://issuer.nex.test:9444"})
	response, e := f.Client().Get(f.IssuerURL + "/.well-known/openid-configuration")
	if e != nil {
		t.Fatal(e)
	}
	var discovery map[string]any
	if e = json.NewDecoder(response.Body).Decode(&discovery); e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if discovery["issuer"] != f.IssuerURL {
		t.Fatal("issuer origin changed")
	}
	untrusted := f.Client()
	untrusted.Transport.(*http.Transport).TLSClientConfig.RootCAs = x509.NewCertPool()
	response, e = untrusted.Get(f.IssuerURL + "/.well-known/openid-configuration")
	if e == nil {
		response.Body.Close()
		t.Fatal("untrusted client unexpectedly trusted fixture certificate")
	}
	var unknown x509.UnknownAuthorityError
	if !errors.As(e, &unknown) {
		t.Fatalf("expected real TLS trust rejection, got %T", e)
	}
	first, e := f.MintAccessToken("unknown-member", map[string]any{"aud": "wrong-api"})
	if e != nil {
		t.Fatal(e)
	}
	_, firstClaims := claims(t, f, first)
	if firstClaims["aud"] != "wrong-api" {
		t.Fatal("negative claims hook discarded")
	}
	if e = f.RotateSigningKey(true); e != nil {
		t.Fatal(e)
	}
	second, e := f.MintAccessToken("alice", nil)
	if e != nil {
		t.Fatal(e)
	}
	firstHeader, _ := claims(t, f, first)
	secondHeader, _ := claims(t, f, second)
	if firstHeader["kid"] == secondHeader["kid"] {
		t.Fatal("key rotation did not change key")
	}
	response, e = f.Client().Get(f.IssuerURL + "/token?subject=alice")
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	io.Copy(io.Discard, response.Body)
	if response.StatusCode == 200 {
		t.Fatal("public persona issuance endpoint exists")
	}
}
