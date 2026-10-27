//go:build integration

package qualification_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// This is a real Node HTTPS transaction through product verifiedRequest. Native
// PKIX validates the initial chain; only the intermediate expires while the
// response body is held. The leaf, root and workspace client remain valid.
func TestQualificationWorkspaceRechecksIntermediateAfterBody(t *testing.T) {
	for _, side := range []string{"peer", "own"} {
		t.Run(side, func(t *testing.T) { workspaceIntermediateExpiry(t, side) })
	}
}
func workspaceIntermediateExpiry(t *testing.T, side string) {
	rootPath, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	now := time.Now()
	expires := now.Truncate(time.Second).Add(5 * time.Second)
	serial := int64(0)
	issue := func(template *x509.Certificate, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte) {
		t.Helper()
		serial++
		template.SerialNumber = big.NewInt(serial)
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if parent == nil {
			parent = template
			parentKey = key
		}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		private, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return certificate, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	}
	root, rootKey, rootPEM, _ := issue(&x509.Certificate{Subject: pkix.Name{CommonName: "independent-chain-root"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}, nil, nil)
	inter, interKey, interPEM, _ := issue(&x509.Certificate{Subject: pkix.Name{CommonName: "short-lived-intermediate"}, NotBefore: now.Add(-time.Minute), NotAfter: expires, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}, root, rootKey)
	controlURI, _ := url.Parse("spiffe://nex.local/service/control")
	controlIssuer, controlIssuerKey := inter, interKey
	if side == "own" {
		controlIssuer, controlIssuerKey = root, rootKey
	}
	_, _, leafPEM, leafKey := issue(&x509.Certificate{Subject: pkix.Name{CommonName: "control"}, DNSNames: []string{"control"}, URIs: []*url.URL{controlURI}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, controlIssuer, controlIssuerKey)
	workspaceURI, _ := url.Parse("spiffe://nex.local/service/workspace")
	ownIssuer, ownIssuerKey := root, rootKey
	if side == "own" {
		ownIssuer, ownIssuerKey = inter, interKey
	}
	_, _, ownPEM, ownKey := issue(&x509.Certificate{Subject: pkix.Name{CommonName: "workspace"}, URIs: []*url.URL{workspaceURI}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, ownIssuer, ownIssuerKey)
	if side == "own" {
		ownPEM = append(ownPEM, interPEM...)
	} else {
		leafPEM = append(leafPEM, interPEM...)
	}
	cert, e := tls.X509KeyPair(leafPEM, leafKey)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(rootPEM)
	var reached atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		if r.URL.Path == "/held" {
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			delay := time.Until(expires.Add(100 * time.Millisecond))
			if delay > 0 {
				time.Sleep(delay)
			}
			w.Write([]byte("must not expose this body"))
			return
		}
		w.Write([]byte("positive"))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	server.StartTLS()
	defer server.Close()
	put := func(name string, content []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if os.WriteFile(path, content, 0600) != nil {
			t.Fatal("test certificate file unavailable")
		}
		return path
	}
	control, _ := url.Parse(server.URL)
	_, port, found := strings.Cut(control.Host, ":")
	if !found {
		t.Fatal("private server port missing")
	}
	if _, err := strconv.Atoi(port); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("node", filepath.Join(rootPath, "tests/qualification/workspace_chain_client.mjs"))
	cmd.Dir = rootPath
	blocked := map[string]bool{"APP_ENV": true, "NEX_PROFILE": true, "WORKSPACE_ORIGIN": true, "OIDC_ISSUER": true, "OIDC_CLIENT_ID": true, "OIDC_AUDIENCE": true, "OIDC_REQUIRED_SCOPE": true, "OIDC_REDIRECT_URI": true, "OIDC_CLIENT_SECRET_FILE": true, "NEX_TLS_CA_FILE": true, "NEX_TLS_CERT_FILE": true, "NEX_TLS_KEY_FILE": true, "CONTROL_URL": true, "NODE_TLS_REJECT_UNAUTHORIZED": true}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if !blocked[name] {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "APP_ENV=development", "NEX_PROFILE=synthetic-qualification", "WORKSPACE_ORIGIN=https://workspace.nex.test:9443", "OIDC_ISSUER=https://issuer.nex.test:9444", "OIDC_CLIENT_ID=nex-workspace", "OIDC_AUDIENCE=nex-api", "OIDC_REQUIRED_SCOPE=nex:access", "OIDC_REDIRECT_URI=https://workspace.nex.test:9443/auth/callback", "CONTROL_URL=https://control:"+port, "NEX_TLS_CA_FILE="+put("ca.crt", rootPEM), "NEX_TLS_CERT_FILE="+put("workspace.crt", ownPEM), "NEX_TLS_KEY_FILE="+put("workspace.key", ownKey), "OIDC_CLIENT_SECRET_FILE="+put("oidc-secret", []byte("synthetic-private-fixture-client-secret")))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("independent workspace intermediate-expiry test failed: %v\n%s", err, output)
	}
	if reached.Load() != 2 {
		t.Fatalf("expected two real mTLS requests, reached %d", reached.Load())
	}
	t.Log(strings.TrimSpace(string(output)))
}
