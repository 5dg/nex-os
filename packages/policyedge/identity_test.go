package policyedge

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func identityFixture(t *testing.T) (*Identity, *x509.Certificate, tls.Certificate) {
	t.Helper()
	now := time.Now()
	dir := t.TempDir()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic policy CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(4 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	caFile := write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	serverPublic, serverKey, _ := ed25519.GenerateKey(rand.Reader)
	serverURI, _ := url.Parse(ServerURI)
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"opa.example.internal"}, URIs: []*url.URL{serverURI}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca, serverPublic, key)
	if err != nil {
		t.Fatal(err)
	}
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	serverFile := write("server.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}))
	keyFile := write("server.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER}))
	wrongServerURI, _ := url.Parse("spiffe://nex.local/service/model")
	for name, uris := range map[string][]*url.URL{"missing": nil, "wrong": {wrongServerURI}} {
		wrongTemplate := *serverTemplate
		wrongTemplate.URIs = uris
		wrongDER, err := x509.CreateCertificate(rand.Reader, &wrongTemplate, ca, serverPublic, key)
		if err != nil {
			t.Fatal(err)
		}
		wrongFile := write(name+"-server.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: wrongDER}))
		if _, err := LoadIdentity(caFile, caFile, wrongFile, keyFile, "spiffe://example.test/service/guard"); err == nil {
			t.Fatal("accepted " + name + " server identity")
		}
	}
	clientPub, clientKey, _ := ed25519.GenerateKey(rand.Reader)
	uri, _ := url.Parse("spiffe://example.test/service/guard")
	clientTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), URIs: []*url.URL{uri}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, ca, clientPub, key)
	if err != nil {
		t.Fatal(err)
	}
	client, err := x509.ParseCertificate(clientDER)
	if err != nil {
		t.Fatal(err)
	}
	clientKeyDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	clientPair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientKeyDER}))
	if err != nil {
		t.Fatal(err)
	}
	id, err := LoadIdentity(caFile, caFile, serverFile, keyFile, uri.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "http://example.test/guard", "spiffe://EXAMPLE.test/guard", "spiffe://example.test/", "spiffe://example.test:443/guard", "spiffe://example.test/guard?", "spiffe://example.test/guard?x=1", "spiffe://example.test/service/../guard"} {
		if _, err := LoadIdentity(caFile, caFile, serverFile, keyFile, bad); err == nil {
			t.Fatal("accepted invalid caller URI", bad)
		}
	}
	if _, err := LoadIdentity(caFile, caFile, serverFile, caFile, uri.String()); err == nil {
		t.Fatal("accepted invalid private key")
	}
	return id, client, clientPair
}

func TestIdentityRevalidatesCurrentServerAndClientCertificates(t *testing.T) {
	id, client, _ := identityFixture(t)
	r := httptest.NewRequest("GET", "https://opa.example.internal/v1/policies", nil)
	r.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{client}}
	if err := id.Check(r); err != nil {
		t.Fatal("valid peer denied", err)
	}
	cfg, err := id.ServerTLS()
	if err != nil || cfg.MinVersion != tls.VersionTLS13 || cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("TLS not fail closed", err)
	}
	wrong := *client
	badURI, _ := url.Parse("spiffe://example.test/service/model")
	wrong.URIs = []*url.URL{badURI}
	r.TLS.PeerCertificates = []*x509.Certificate{&wrong}
	if id.Check(r) == nil {
		t.Fatal("wrong peer identity accepted")
	}
	r.TLS.PeerCertificates = []*x509.Certificate{client}
	r.TLS.Version = tls.VersionTLS12
	if id.Check(r) == nil {
		t.Fatal("older TLS accepted")
	}
	r.TLS.Version = tls.VersionTLS13
	id.now = func() time.Time { return client.NotAfter.Add(time.Second) }
	if id.Check(r) == nil {
		t.Fatal("expired credential accepted on reused connection")
	}
	if _, err := id.ServerTLS(); err != nil {
		t.Fatal("valid server certificate rejected after client expiry")
	}
	id.now = func() time.Time { return id.serverChain[0].NotAfter.Add(time.Second) }
	if _, err := id.ServerTLS(); err == nil {
		t.Fatal("expired server certificate accepted")
	}
}

func TestAuthenticatedTLSRouteAndAnonymousDenial(t *testing.T) {
	id, _, clientPair := identityFixture(t)
	cfg, err := id.ServerTLS()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(Handler(fakeTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"result":[]}`))}, nil
	}), id.Check))
	server.TLS = cfg
	server.StartTLS()
	defer server.Close()
	clientTransport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: id.serverRoots, ServerName: "opa.example.internal", Certificates: []tls.Certificate{clientPair}}}
	defer clientTransport.CloseIdleConnections()
	client := &http.Client{Transport: clientTransport, Timeout: time.Second}
	response, err := client.Get(server.URL + "/v1/policies")
	if err != nil {
		t.Fatal("authenticated TLS request failed", err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("authenticated request denied", response.StatusCode)
	}
	anonymousTransport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: id.serverRoots, ServerName: "opa.example.internal"}}
	defer anonymousTransport.CloseIdleConnections()
	anonymous := &http.Client{Transport: anonymousTransport, Timeout: time.Second}
	if response, err := anonymous.Get(server.URL + "/v1/policies"); err == nil {
		response.Body.Close()
		t.Fatal("anonymous peer accepted")
	}
}
