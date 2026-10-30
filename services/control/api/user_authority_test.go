package api

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/5dg/nex-os/packages/trust"
	"github.com/5dg/nex-os/services/control/auth"
	"github.com/coreos/go-oidc/v3/oidc"
)

func TestUserAuthorityStopsExpiredOriginalCredential(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer *httptest.Server
	issuer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer.URL, "jwks_uri": issuer.URL + "/keys"})
			return
		}
		enc := base64.RawURLEncoding
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "current", "use": "sig", "alg": "RS256", "n": enc.EncodeToString(key.N.Bytes()), "e": enc.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	}))
	defer issuer.Close()
	verifier, err := auth.NewAccessTokenVerifier(oidc.ClientContext(context.Background(), issuer.Client()), issuer.URL, "nex-api", "nex-workspace", "nex:access")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	exp := now + 5
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "at+jwt", "kid": "current"})
	claims, _ := json.Marshal(map[string]any{"iss": issuer.URL, "sub": "alice", "aud": "nex-api", "client_id": "nex-workspace", "scope": "nex:access", "iat": now, "exp": exp})
	enc := base64.RawURLEncoding
	payload := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(payload))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://control/v1/jobs", nil)
	r.Header.Set("Authorization", "Bearer "+payload+"."+enc.EncodeToString(signature))
	original := r.Context()
	r = r.WithContext(context.WithValue(original, requestAuthorityKey{}, requestAuthority{original: original, current: func() error { return nil }}))
	id, err := verifier.Verify(r)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Profile: trust.Qualification, Auth: verifier}
	if err = s.bindUserAuthority(r, id); err != nil {
		t.Fatal(err)
	}
	// Changing the request after binding must not replace the original bearer.
	r.Header.Set("Authorization", "Bearer replacement")
	if err = s.beforeDispatch(r.Context()); err != nil {
		t.Fatalf("original valid credential rejected: %v", err)
	}
	underlying := &admissionTx{}
	tx := requestTx{Tx: underlying, check: func() error { return s.currentRequest(r.Context()) }}
	time.Sleep(time.Until(time.Unix(exp, 0)) + 20*time.Millisecond)
	if err = tx.Commit(context.Background()); !errors.Is(err, errForbidden) || underlying.commits != 0 {
		t.Fatalf("expired credential committed: %v", err)
	}
	if err = s.beforeDispatch(r.Context()); !errors.Is(err, errForbidden) {
		t.Fatalf("expired credential permitted dispatch: %v", err)
	}
	if err = s.afterDispatch(r.Context()); !errors.Is(err, errRequestOutcomeUnavailable) {
		t.Fatalf("post-dispatch outcome was not preserved: %v", err)
	}
}
