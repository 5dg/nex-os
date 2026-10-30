package policyedge

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

var errIdentity = errors.New("current policy workload identity required")

// Guard's current transport verifier requires this exact OPA URI. Actual
// production issuance and trust-root policy remain to be established.
const ServerURI = "spiffe://nex.local/service/opa"

// Identity binds the listener's own server certificate and the single allowed
// Guard caller to separate operator-provisioned CA roots. It does not issue or
// rotate credentials, validate their provenance, or enable production profiles.
type Identity struct {
	serverCert  tls.Certificate
	serverChain []*x509.Certificate
	serverRoots *x509.CertPool
	clientRoots *x509.CertPool
	clientURI   string
	now         func() time.Time
}

func loadRoots(filename string) (*x509.CertPool, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, errIdentity
	}
	pool := x509.NewCertPool()
	count := 0
	for len(bytes.TrimSpace(b)) > 0 {
		block, rest := pem.Decode(b)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errIdentity
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errIdentity
		}
		pool.AddCert(cert)
		count++
		b = rest
	}
	if count == 0 {
		return nil, errIdentity
	}
	return pool, nil
}

// LoadIdentity rejects malformed roots, key pairs and caller URI on startup.
// Inputs must come from an operator-controlled deployment, never from a caller.
func LoadIdentity(serverCA, clientCA, certFile, keyFile, callerURI string) (*Identity, error) {
	u, err := url.Parse(callerURI)
	if err != nil || len(callerURI) > 2048 || u.Scheme != "spiffe" || u.Host == "" || u.Host != strings.ToLower(u.Host) || u.Hostname() != u.Host || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" || !strings.HasPrefix(u.Path, "/") || u.Path == "/" || path.Clean(u.Path) != u.Path || u.String() != callerURI {
		return nil, errIdentity
	}
	serverRoots, err := loadRoots(serverCA)
	if err != nil {
		return nil, errIdentity
	}
	clientRoots, err := loadRoots(clientCA)
	if err != nil {
		return nil, errIdentity
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, errIdentity
	}
	identity := &Identity{serverCert: cert, serverRoots: serverRoots, clientRoots: clientRoots, clientURI: callerURI, now: time.Now}
	for _, der := range cert.Certificate {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errIdentity
		}
		identity.serverChain = append(identity.serverChain, c)
	}
	if identity.checkServer() != nil {
		return nil, errIdentity
	}
	return identity, nil
}

func verifyChain(chain []*x509.Certificate, roots *x509.CertPool, usage x509.ExtKeyUsage, now time.Time) error {
	if len(chain) == 0 || chain[0].IsCA || roots == nil {
		return errIdentity
	}
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{usage}, CurrentTime: now})
	if err != nil {
		return errIdentity
	}
	return nil
}

func (i *Identity) checkServer() error {
	if i == nil || i.now == nil {
		return errIdentity
	}
	if len(i.serverChain) == 0 || len(i.serverChain[0].URIs) != 1 || i.serverChain[0].URIs[0].String() != ServerURI {
		return errIdentity
	}
	return verifyChain(i.serverChain, i.serverRoots, x509.ExtKeyUsageServerAuth, i.now())
}

// Check re-verifies the current certificates even on reused TLS connections.
func (i *Identity) Check(r *http.Request) error {
	if i == nil || r == nil || i.checkServer() != nil || r.TLS == nil || !r.TLS.HandshakeComplete || r.TLS.Version != tls.VersionTLS13 {
		return errIdentity
	}
	chain := r.TLS.PeerCertificates
	if verifyChain(chain, i.clientRoots, x509.ExtKeyUsageClientAuth, i.now()) != nil || len(chain[0].URIs) != 1 || chain[0].URIs[0].String() != i.clientURI {
		return errIdentity
	}
	return nil
}

func (i *Identity) ServerTLS() (*tls.Config, error) {
	if i == nil || i.checkServer() != nil {
		return nil, errIdentity
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{i.serverCert}, ClientCAs: i.clientRoots, ClientAuth: tls.RequireAndVerifyClientCert}, nil
}
