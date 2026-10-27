package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"
)

func main() {
	if os.Getenv("APP_ENV") != "development" {
		log.Fatal("issuer is development-only")
	}
	issuer := os.Getenv("OIDC_ISSUER")
	if issuer == "" {
		log.Fatal("OIDC_ISSUER required")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	enc := base64.RawURLEncoding
	write := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		write(w, map[string]any{"issuer": issuer, "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		write(w, map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "local-dev", "use": "sig", "alg": "RS256", "n": enc.EncodeToString(key.N.Bytes()), "e": enc.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		if r.ParseForm() != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		subject := r.Form.Get("subject")
		if subject != "alice" && subject != "bob" && subject != "carol" && subject != "dave" {
			http.Error(w, "unknown synthetic user", 400)
			return
		}
		now := time.Now()
		claims, _ := json.Marshal(map[string]any{"iss": issuer, "sub": subject, "aud": "nex-local", "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix()})
		header := enc.EncodeToString([]byte(`{"alg":"RS256","kid":"local-dev","typ":"JWT"}`))
		body := header + "." + enc.EncodeToString(claims)
		digest := sha256.Sum256([]byte(body))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			http.Error(w, "signing failed", 500)
			return
		}
		write(w, map[string]any{"access_token": body + "." + enc.EncodeToString(sig), "token_type": "Bearer", "expires_in": 600, "development_only": true})
	})
	log.Print("UNAUTHENTICATED SYNTHETIC IDENTITY ISSUER: development only")
	log.Fatal((&http.Server{Addr: ":8081", Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}).ListenAndServe())
}
