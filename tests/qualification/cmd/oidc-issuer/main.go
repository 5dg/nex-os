// oidc-issuer is an explicitly synthetic qualification fixture. It must never
// serve customer identity, CUI or a production profile.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	fixture "github.com/5dg/nex-os/tests/qualification/fixtures/oidc"
)

func setting(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
func run() error {
	profile := flag.String("profile", setting("NEX_PROFILE", ""), "must be synthetic-qualification")
	listen := flag.String("listen", ":9444", "fixture HTTPS listen address")
	issuerURL := flag.String("issuer", setting("OIDC_ISSUER", "https://issuer.nex.test:9444"), "canonical HTTPS issuer origin")
	clientID := flag.String("client-id", setting("OIDC_CLIENT_ID", "nex-workspace"), "fixture confidential client")
	audience := flag.String("audience", setting("OIDC_AUDIENCE", "nex-api"), "API access-token audience")
	scope := flag.String("scope", setting("OIDC_REQUIRED_SCOPE", "nex:access"), "fixture API scope")
	secretFile := flag.String("client-secret-file", setting("OIDC_CLIENT_SECRET_FILE", ""), "fixture client-secret file")
	redirect := flag.String("redirect-uri", setting("OIDC_REDIRECT_URI", "https://workspace.nex.test:9443/auth/callback"), "exact registered HTTPS callback")
	certFile := flag.String("tls-cert", setting("NEX_TLS_CERT_FILE", ""), "fixture HTTPS certificate")
	keyFile := flag.String("tls-key", setting("NEX_TLS_KEY_FILE", ""), "fixture HTTPS private key")
	usersFile := flag.String("users-file", "", "optional bounded JSON synthetic user list")
	flag.Parse()
	if flag.NArg() != 0 || *profile != "synthetic-qualification" || os.Getenv("APP_ENV") == "production" {
		return errors.New("OIDC fixture requires explicit synthetic-qualification profile; production is forbidden")
	}
	if *secretFile == "" || *certFile == "" || *keyFile == "" {
		return errors.New("fixture secret and TLS files required")
	}
	secret, e := os.ReadFile(*secretFile)
	if e != nil {
		return errors.New("fixture client-secret file unavailable")
	}
	if len(secret) > 4096 {
		return errors.New("bounded fixture client secret required")
	}
	users := []fixture.User{{Username: "alice", Subject: "alice", Password: "fixture-alice-password"}, {Username: "bob", Subject: "bob", Password: "fixture-bob-password"}, {Username: "carol", Subject: "carol", Password: "fixture-carol-password"}, {Username: "dave", Subject: "dave", Password: "fixture-dave-password"}}
	if *usersFile != "" {
		input, e := os.Open(*usersFile)
		if e != nil {
			return errors.New("synthetic user fixture unavailable")
		}
		defer input.Close()
		info, e := input.Stat()
		if e != nil || info.Size() > 16384 {
			return errors.New("bounded synthetic user fixture required")
		}
		decoder := json.NewDecoder(io.LimitReader(input, 16385))
		decoder.DisallowUnknownFields()
		if e = decoder.Decode(&users); e != nil {
			return errors.New("invalid synthetic user fixture")
		}
		if e = decoder.Decode(&struct{}{}); e != io.EOF {
			return errors.New("single synthetic user fixture required")
		}
	}
	issuer, e := fixture.New(fixture.Config{IssuerURL: *issuerURL, ClientID: *clientID, ClientSecret: strings.TrimSpace(string(secret)), APIAudience: *audience, AccessScope: *scope, RedirectURIs: []string{*redirect}, Users: users})
	if e != nil {
		return e
	}
	certificate, e := tls.LoadX509KeyPair(*certFile, *keyFile)
	if e != nil {
		return errors.New("fixture TLS identity unavailable")
	}
	server := &http.Server{Addr: *listen, Handler: issuer.Handler(), TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13}, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	fmt.Fprintln(os.Stderr, "Synthetic qualification OIDC fixture started; no customer identity or MFA.")
	e = server.ListenAndServeTLS("", "")
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
