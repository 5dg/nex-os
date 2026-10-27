package oidc

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/5dg/nex-os/tests/qualification/fixtures/pki"
)

type Fixture struct {
	Issuer                   *Issuer
	IssuerURL                string
	CAFile, ClientSecretFile string
	Authority                *pki.Authority
	Server                   *httptest.Server
}

// NewFixture starts only a private HTTPS test server. A configured .test issuer
// is routed to its local listener by Client, preserving Host/SNI and verification.
func NewFixture(t testing.TB, config Config, authority ...*pki.Authority) *Fixture {
	t.Helper()
	var ca *pki.Authority
	var e error
	if len(authority) > 1 {
		t.Fatal("at most one fixture authority")
	}
	if len(authority) == 1 {
		ca = authority[0]
	} else {
		ca, e = pki.NewAuthority("OIDC qualification fixture")
		if e != nil {
			t.Fatal(e)
		}
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	if config.IssuerURL == "" {
		config.IssuerURL = "https://" + listener.Addr().String()
	}
	if config.ClientID == "" {
		config.ClientID = "nex-workspace"
	}
	if config.APIAudience == "" {
		config.APIAudience = "nex-api"
	}
	if config.AccessScope == "" {
		config.AccessScope = "nex:access"
	}
	if config.ClientSecret == "" {
		raw := make([]byte, 32)
		if _, e = rand.Read(raw); e != nil {
			listener.Close()
			t.Fatal(e)
		}
		config.ClientSecret = base64.RawURLEncoding.EncodeToString(raw)
	}
	if len(config.RedirectURIs) == 0 {
		config.RedirectURIs = []string{"https://workspace.nex.test:9443/auth/callback"}
	}
	if len(config.Users) == 0 {
		config.Users = []User{{Username: "alice", Subject: "alice", Password: "fixture-alice-password"}, {Username: "bob", Subject: "bob", Password: "fixture-bob-password"}, {Username: "carol", Subject: "carol", Password: "fixture-carol-password"}, {Username: "dave", Subject: "dave", Password: "fixture-dave-password"}}
	}
	issuer, e := New(config)
	if e != nil {
		listener.Close()
		t.Fatal(e)
	}
	advertised, e := url.Parse(issuer.IssuerURL())
	if e != nil {
		listener.Close()
		t.Fatal(e)
	}
	leafSpec := pki.Spec{Name: "oidc", ServerAuth: true, URIs: []string{"spiffe://nex.local/service/oidc"}, NotAfter: time.Now().Add(time.Hour)}
	if ip := net.ParseIP(advertised.Hostname()); ip != nil {
		leafSpec.IPAddresses = []net.IP{ip}
	} else {
		leafSpec.DNSNames = []string{advertised.Hostname()}
	}
	leaf, e := ca.Issue(leafSpec)
	if e != nil {
		listener.Close()
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(issuer.Handler())
	server.Listener.Close()
	server.Listener = listener
	server.TLS = &tls.Config{Certificates: []tls.Certificate{leaf.Certificate}, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	directory := t.TempDir()
	caFile := filepath.Join(directory, "ca.crt")
	if e = os.WriteFile(caFile, ca.CertificatePEM(), 0644); e != nil {
		server.Close()
		t.Fatal(e)
	}
	secretFile := filepath.Join(directory, "client-secret")
	if e = os.WriteFile(secretFile, []byte(config.ClientSecret), 0600); e != nil {
		server.Close()
		t.Fatal(e)
	}
	f := &Fixture{Issuer: issuer, IssuerURL: issuer.IssuerURL(), CAFile: caFile, ClientSecretFile: secretFile, Authority: ca, Server: server}
	t.Cleanup(f.Close)
	return f
}
func (f *Fixture) Close() { f.Server.Close() }
func (f *Fixture) Client() *http.Client {
	advertised, _ := url.Parse(f.IssuerURL)
	address := f.Server.Listener.Addr().String()
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.Authority.Pool(), MinVersion: tls.VersionTLS13}, TLSHandshakeTimeout: 3 * time.Second, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, requested string) (net.Conn, error) {
		if requested == advertised.Host {
			requested = address
		}
		return dialer.DialContext(ctx, network, requested)
	}}
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}
func (f *Fixture) BrowserClient() *http.Client {
	client := f.Client()
	client.Jar, _ = cookiejar.New(nil)
	return client
}
func (f *Fixture) MintAccessToken(subject string, overrides map[string]any) (string, error) {
	return f.Issuer.MintAccessToken(subject, overrides)
}
func (f *Fixture) MintIDToken(subject, nonce string, overrides map[string]any) (string, error) {
	return f.Issuer.MintIDToken(subject, nonce, overrides)
}
func (f *Fixture) SignToken(header, claims map[string]any, unpublished bool) (string, error) {
	return f.Issuer.SignToken(header, claims, unpublished)
}
func (f *Fixture) RotateSigningKey(retainPrevious bool) error {
	return f.Issuer.RotateSigningKey(retainPrevious)
}

var csrfPattern = regexp.MustCompile(`name="csrf" value="([A-Z2-7]+)"`)

// LoginAs exercises the fixture's credential form and returns the callback URL
// without following it. It does not choose an identity through a token endpoint.
func (f *Fixture) LoginAs(client *http.Client, authorizationURL, username, password string) (*url.URL, error) {
	if client.Jar == nil {
		return nil, errors.New("cookie jar required")
	}
	issuer, _ := url.Parse(f.IssuerURL)
	copyClient := *client
	copyClient.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if r.URL.Scheme != issuer.Scheme || r.URL.Host != issuer.Host {
			return http.ErrUseLastResponse
		}
		if len(via) >= 10 {
			return errors.New("too many fixture redirects")
		}
		return nil
	}
	response, e := copyClient.Get(authorizationURL)
	if e != nil {
		return nil, e
	}
	body, e := io.ReadAll(io.LimitReader(response.Body, 16384))
	response.Body.Close()
	if e != nil {
		return nil, e
	}
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("fixture authorize/login HTTP %d", response.StatusCode)
	}
	found := csrfPattern.FindSubmatch(body)
	if len(found) != 2 {
		return nil, errors.New("fixture login form missing correlation")
	}
	response, e = copyClient.PostForm(f.IssuerURL+"/login", url.Values{"username": {username}, "password": {password}, "csrf": {string(found[1])}})
	if e != nil {
		return nil, e
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		return nil, fmt.Errorf("fixture credential login HTTP %d", response.StatusCode)
	}
	callback, e := url.Parse(response.Header.Get("Location"))
	if e != nil || callback.Scheme != "https" || strings.HasPrefix(callback.String(), f.IssuerURL) {
		return nil, errors.New("fixture did not return external HTTPS callback")
	}
	return callback, nil
}
