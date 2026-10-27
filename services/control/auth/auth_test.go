package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

func TestJWTAccessProfileSeparatesCredentialsAndCurrentIdentity(t *testing.T) {
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	var issuer *httptest.Server
	issuer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/openid-configuration" {
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer.URL, "jwks_uri": issuer.URL + "/keys", "authorization_endpoint": issuer.URL + "/authorize", "token_endpoint": issuer.URL + "/token", "response_types_supported": []string{"code"}, "id_token_signing_alg_values_supported": []string{"RS256"}})
			return
		}
		enc := base64.RawURLEncoding
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "current", "use": "sig", "alg": "RS256", "n": enc.EncodeToString(key.N.Bytes()), "e": enc.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	}))
	defer issuer.Close()
	ctx := oidc.ClientContext(context.Background(), issuer.Client())
	verifier, e := NewAccessTokenVerifier(ctx, issuer.URL, "nex-api", "nex-workspace", "nex:access")
	if e != nil {
		t.Fatal(e)
	}
	sign := func(header, changes map[string]any, signer *rsa.PrivateKey) string {
		h := map[string]any{"alg": "RS256", "typ": "at+jwt", "kid": "current"}
		for k, v := range header {
			if v == nil {
				delete(h, k)
			} else {
				h[k] = v
			}
		}
		now := time.Now().Unix()
		claims := map[string]any{"iss": issuer.URL, "sub": "alice", "aud": "nex-api", "client_id": "nex-workspace", "scope": "openid nex:access", "exp": now + 300, "iat": now}
		for k, v := range changes {
			if v == nil {
				delete(claims, k)
			} else {
				claims[k] = v
			}
		}
		hb, _ := json.Marshal(h)
		cb, _ := json.Marshal(claims)
		enc := base64.RawURLEncoding
		p := enc.EncodeToString(hb) + "." + enc.EncodeToString(cb)
		sum := sha256.Sum256([]byte(p))
		signature, e := rsa.SignPKCS1v15(rand.Reader, signer, crypto.SHA256, sum[:])
		if e != nil {
			t.Fatal(e)
		}
		return p + "." + enc.EncodeToString(signature)
	}
	verify := func(token string) (Identity, error) {
		r := httptest.NewRequest("GET", "https://control/v1/me", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		return verifier.Verify(r)
	}
	t.Run("valid access profile returns only issuer and subject", func(t *testing.T) {
		id, e := verify(sign(nil, map[string]any{"tenant_id": "forged", "roles": []string{"admin"}, "permissions": []string{"shell.execute"}}, key))
		if e != nil || id != (Identity{Issuer: issuer.URL, Subject: "alice"}) {
			t.Fatalf("%+v %v", id, e)
		}
	})
	now := time.Now().Unix()
	for _, test := range []struct {
		name           string
		header, claims map[string]any
	}{
		{"browser ID token", map[string]any{"typ": "JWT"}, map[string]any{"aud": "nex-workspace"}},
		{"ID token with API audience", map[string]any{"typ": "JWT"}, nil},
		{"missing purpose", map[string]any{"typ": nil}, nil},
		{"wrong algorithm", map[string]any{"alg": "HS256"}, nil},
		{"missing key identity", map[string]any{"kid": nil}, nil},
		{"unknown critical header", map[string]any{"crit": []string{"untrusted"}}, nil},
		{"wrong issuer", nil, map[string]any{"iss": "https://other.nex.test"}},
		{"wrong audience", nil, map[string]any{"aud": "nex-workspace"}},
		{"ambiguous multiple audiences", nil, map[string]any{"aud": []string{"nex-api", "nex-workspace"}}},
		{"wrong client", nil, map[string]any{"client_id": "other"}},
		{"missing client", nil, map[string]any{"client_id": nil}},
		{"wrong scope", nil, map[string]any{"scope": "nex:access-extra"}},
		{"missing scope", nil, map[string]any{"scope": nil}},
		{"malformed scope", nil, map[string]any{"scope": "nex:access\nadmin"}},
		{"missing expiry", nil, map[string]any{"exp": nil}},
		{"missing issued time", nil, map[string]any{"iat": nil}},
		{"string issued time", nil, map[string]any{"iat": "123"}},
		{"expired", nil, map[string]any{"exp": now - 1}},
		{"long lifetime", nil, map[string]any{"exp": now + 1800}},
		{"future issue", nil, map[string]any{"iat": now + 60}},
		{"future not before", nil, map[string]any{"nbf": now + 60}},
		{"not before beyond expiry", nil, map[string]any{"nbf": now + 300}},
		{"missing subject", nil, map[string]any{"sub": nil}},
		{"blank subject", nil, map[string]any{"sub": " "}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, e := verify(sign(test.header, test.claims, key)); e == nil {
				t.Fatal("invalid token profile accepted")
			}
		})
	}
	t.Run("wrong signing key", func(t *testing.T) {
		wrong, e := rsa.GenerateKey(rand.Reader, 2048)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := verify(sign(nil, nil, wrong)); e == nil {
			t.Fatal("forged signature accepted")
		}
	})
	t.Run("ambiguous bearer headers", func(t *testing.T) {
		r := httptest.NewRequest("GET", "https://control/v1/me", nil)
		r.Header.Add("Authorization", "Bearer "+sign(nil, nil, key))
		r.Header.Add("Authorization", "Bearer "+sign(nil, nil, key))
		if _, e := verifier.Verify(r); e == nil {
			t.Fatal("duplicate bearer headers accepted")
		}
	})
	t.Run("bounded bearer", func(t *testing.T) {
		if _, e := verify(strings.Repeat("a", MaxBearerBytes+1)); e == nil {
			t.Fatal("unbounded bearer accepted")
		}
	})
}

func TestIssuerConfigurationRemainsBoundedAndHTTPS(t *testing.T) {
	if _, e := NewAccessTokenVerifier(context.Background(), "http://issuer.nex.test", "nex-api", "nex-workspace", "nex:access"); e == nil {
		t.Fatal("plaintext issuer accepted")
	}
	for _, mode := range []string{"oversized metadata", "foreign JWKS", "plaintext JWKS"} {
		t.Run(mode, func(t *testing.T) {
			var issuer *httptest.Server
			issuer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "oversized metadata" {
					w.Write([]byte(strings.Repeat("x", maxIssuerResponseBytes+1)))
					return
				}
				keys := "https://other.nex.test/keys"
				if mode == "plaintext JWKS" {
					keys = "http://issuer.nex.test/keys"
				}
				json.NewEncoder(w).Encode(map[string]any{"issuer": issuer.URL, "jwks_uri": keys})
			}))
			defer issuer.Close()
			ctx := oidc.ClientContext(context.Background(), issuer.Client())
			if _, e := NewAccessTokenVerifier(ctx, issuer.URL, "nex-api", "nex-workspace", "nex:access"); e == nil {
				t.Fatal("invalid issuer configuration accepted")
			}
		})
	}
}
