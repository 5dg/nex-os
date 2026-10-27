package trust_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/5dg/nex-os/packages/trust"
)

func TestIntermediateOwnAndPeerChains(t *testing.T) {
	rootKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"}, IsCA: true, BasicConstraintsValid: true, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageCertSign}
	rootDER, e := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if e != nil {
		t.Fatal(e)
	}
	root, e = x509.ParseCertificate(rootDER)
	if e != nil {
		t.Fatal(e)
	}
	middleKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	middle := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "middle"}, IsCA: true, BasicConstraintsValid: true, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageCertSign}
	middleDER, e := x509.CreateCertificate(rand.Reader, middle, root, &middleKey.PublicKey, rootKey)
	if e != nil {
		t.Fatal(e)
	}
	middle, e = x509.ParseCertificate(middleDER)
	if e != nil {
		t.Fatal(e)
	}
	makeConfig := func(role trust.Role, serial int64) *trust.Config {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		uri, e := url.Parse(role.URI())
		if e != nil {
			t.Fatal(e)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: string(role)}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, URIs: []*url.URL{uri}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		leafDER, e := x509.CreateCertificate(rand.Reader, leaf, middle, &key.PublicKey, middleKey)
		if e != nil {
			t.Fatal(e)
		}
		private, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			t.Fatal(e)
		}
		dir := t.TempDir()
		ca := filepath.Join(dir, "ca")
		cert := filepath.Join(dir, "cert")
		keyFile := filepath.Join(dir, "key")
		for path, body := range map[string][]byte{ca: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), cert: append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: middleDER})...), keyFile: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})} {
			if e = os.WriteFile(path, body, 0600); e != nil {
				t.Fatal(e)
			}
		}
		cfg, e := trust.LoadFiles(trust.Qualification, role, ca, cert, keyFile)
		if e != nil {
			t.Fatal("valid intermediate chain denied", e)
		}
		return cfg
	}
	control := makeConfig(trust.Control, 3)
	guard := makeConfig(trust.Guard, 4)
	endpoint := server(t, guard, guard.Middleware([]trust.Role{trust.Control}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })))
	client, e := control.HTTPClient(trust.Guard, 3*time.Second)
	if e != nil {
		t.Fatal("client intermediate own chain denied", e)
	}
	response, e := client.Get(endpoint.URL)
	if e != nil {
		t.Fatal("real intermediate mTLS failed", e)
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatal(response.StatusCode)
	}
}
