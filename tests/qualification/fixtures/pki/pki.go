// Package pki generates ephemeral test identities. It provides no production CA,
// certificate provisioning policy or validated-module assertion.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

type Authority struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	pem         []byte
}

type Spec struct {
	Name        string
	DNSNames    []string
	IPAddresses []net.IP
	URIs        []string
	ClientAuth  bool
	ServerAuth  bool
	NotBefore   time.Time
	NotAfter    time.Time
}

type Identity struct {
	Certificate    tls.Certificate
	CertificatePEM []byte
	PrivateKeyPEM  []byte
}

type Files struct{ CA, Certificate, PrivateKey string }

func serial() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159)) }

func NewAuthority(name string) (*Authority, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	id, e := serial()
	if e != nil {
		return nil, e
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: id, Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		return nil, e
	}
	certificate, e := x509.ParseCertificate(der)
	if e != nil {
		return nil, e
	}
	return &Authority{certificate: certificate, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}
func (a *Authority) CertificatePEM() []byte { return append([]byte(nil), a.pem...) }
func (a *Authority) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(a.certificate)
	return pool
}
func (a *Authority) Issue(spec Spec) (Identity, error) {
	if !spec.ClientAuth && !spec.ServerAuth {
		return Identity{}, errors.New("test leaf must declare client and/or server usage")
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return Identity{}, e
	}
	id, e := serial()
	if e != nil {
		return Identity{}, e
	}
	now := time.Now().UTC()
	if spec.NotBefore.IsZero() {
		spec.NotBefore = now.Add(-time.Minute)
	}
	if spec.NotAfter.IsZero() {
		spec.NotAfter = now.Add(10 * time.Minute)
	}
	if !spec.NotAfter.After(spec.NotBefore) {
		return Identity{}, errors.New("invalid test leaf validity interval")
	}
	template := &x509.Certificate{SerialNumber: id, Subject: pkix.Name{CommonName: spec.Name}, DNSNames: append([]string(nil), spec.DNSNames...), IPAddresses: append([]net.IP(nil), spec.IPAddresses...), NotBefore: spec.NotBefore, NotAfter: spec.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	if spec.ClientAuth {
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if spec.ServerAuth {
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	for _, raw := range spec.URIs {
		uri, e := url.Parse(raw)
		if e != nil || uri.Scheme == "" {
			return Identity{}, errors.New("absolute test identity URI required")
		}
		template.URIs = append(template.URIs, uri)
	}
	der, e := x509.CreateCertificate(rand.Reader, template, a.certificate, &key.PublicKey, a.key)
	if e != nil {
		return Identity{}, e
	}
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return Identity{}, e
	}
	result := Identity{CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})}
	result.Certificate, e = tls.X509KeyPair(result.CertificatePEM, result.PrivateKeyPEM)
	if e != nil {
		return Identity{}, e
	}
	result.Certificate.Leaf, e = x509.ParseCertificate(der)
	return result, e
}

var basename = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)

// WriteFiles stores only the public CA and the requested test leaf. The CA
// signing key remains in memory. Private leaf files are explicitly mode0600.
func (a *Authority) WriteFiles(directory, name string, identity Identity) (Files, error) {
	if !basename.MatchString(name) {
		return Files{}, errors.New("invalid test identity file name")
	}
	if e := os.MkdirAll(directory, 0700); e != nil {
		return Files{}, e
	}
	files := Files{CA: filepath.Join(directory, "ca.crt"), Certificate: filepath.Join(directory, name+".crt"), PrivateKey: filepath.Join(directory, name+".key")}
	for _, item := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{{files.CA, a.pem, 0644}, {files.Certificate, identity.CertificatePEM, 0644}, {files.PrivateKey, identity.PrivateKeyPEM, 0600}} {
		if e := os.WriteFile(item.path, item.data, item.mode); e != nil {
			return Files{}, e
		}
		if e := os.Chmod(item.path, item.mode); e != nil {
			return Files{}, e
		}
	}
	return files, nil
}
