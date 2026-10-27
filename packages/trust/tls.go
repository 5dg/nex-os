package trust

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"time"
)

var ErrIdentity = errors.New("verified current service identity required")

type Config struct {
	Profile  Profile
	Role     Role
	roots    *x509.CertPool
	identity tls.Certificate
	chain    []*x509.Certificate
}

func Load(profile Profile, role Role) (*Config, error) {
	return LoadFiles(profile, role, os.Getenv("NEX_TLS_CA_FILE"), os.Getenv("NEX_TLS_CERT_FILE"), os.Getenv("NEX_TLS_KEY_FILE"))
}

// LoadFiles is explicit for ephemeral fixtures; callers must never load user
// supplied trust material. Production is rejected just like unknown profiles.
func LoadFiles(profile Profile, role Role, ca, cert, key string) (*Config, error) {
	if profile != Development && profile != Qualification || !role.Valid() {
		return nil, ErrIdentity
	}
	c := &Config{Profile: profile, Role: role}
	if profile == Development {
		return c, nil
	}
	if ca == "" || cert == "" || key == "" {
		return nil, errors.New("qualification CA,certificate,key files required")
	}
	b, e := os.ReadFile(ca)
	if e != nil {
		return nil, ErrIdentity
	}
	roots := x509.NewCertPool()
	remaining := b
	count := 0
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return nil, ErrIdentity
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			return nil, ErrIdentity
		}
		parsed, e := x509.ParseCertificate(block.Bytes)
		if e != nil || !parsed.IsCA || parsed.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, ErrIdentity
		}
		roots.AddCert(parsed)
		count++
	}
	if count == 0 {
		return nil, ErrIdentity
	}
	identity, e := tls.LoadX509KeyPair(cert, key)
	if e != nil {
		return nil, ErrIdentity
	}
	identity.Leaf, e = x509.ParseCertificate(identity.Certificate[0])
	if e != nil {
		return nil, ErrIdentity
	}
	c.roots = roots
	c.identity = identity
	for _, der := range identity.Certificate {
		parsed, e := x509.ParseCertificate(der)
		if e != nil {
			return nil, ErrIdentity
		}
		c.chain = append(c.chain, parsed)
	}
	if certificateRole(identity.Leaf) != role {
		return nil, ErrIdentity
	}
	if e = c.CheckOwn(); e != nil {
		return nil, e
	}
	return c, nil
}
func certificateRole(cert *x509.Certificate) Role {
	if cert == nil || len(cert.URIs) != 1 {
		return ""
	}
	for _, r := range []Role{Workspace, Control, Guard, Model, Export, Evidence, Worker, OPA, OIDC} {
		if cert.URIs[0].String() == r.URI() {
			return r
		}
	}
	return ""
}
func (c *Config) verify(certificates []*x509.Certificate, usage x509.ExtKeyUsage) error {
	if c == nil || c.roots == nil || len(certificates) == 0 {
		return ErrIdentity
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certificates[1:] {
		intermediates.AddCert(cert)
	}
	_, e := certificates[0].Verify(x509.VerifyOptions{Roots: c.roots, Intermediates: intermediates, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{usage}})
	if e != nil {
		return ErrIdentity
	}
	return nil
}
func (c *Config) CheckOwn() error {
	if c == nil {
		return ErrIdentity
	}
	if c.Profile == Development {
		return nil
	}
	if c.Profile != Qualification {
		return ErrIdentity
	}
	if len(c.chain) == 0 || certificateRole(c.chain[0]) != c.Role {
		return ErrIdentity
	}
	return c.verify(c.chain, x509.ExtKeyUsageAny)
}

// CheckPeer revalidates current certificate time/chain per request or RPC. It
// never accepts a forwarding header, common name, or caller-supplied role.
func (c *Config) CheckPeer(state *tls.ConnectionState, allowed []Role) error {
	return c.checkPeer(state, allowed, true, x509.ExtKeyUsageAny)
}
func (c *Config) checkPeer(state *tls.ConnectionState, allowed []Role, completed bool, usage x509.ExtKeyUsage) error {
	if c == nil {
		return ErrIdentity
	}
	if c.Profile == Development {
		return nil
	}
	if e := c.CheckOwn(); e != nil {
		return e
	}
	if state == nil || (completed && !state.HandshakeComplete) || state.Version != tls.VersionTLS13 {
		return ErrIdentity
	}
	if e := c.verify(state.PeerCertificates, usage); e != nil {
		return e
	}
	role := certificateRole(state.PeerCertificates[0])
	if !role.Valid() {
		return ErrIdentity
	}
	if len(allowed) == 0 {
		return nil
	}
	for _, r := range allowed {
		if role == r {
			return nil
		}
	}
	return ErrIdentity
}
func (c *Config) ServerTLS(requireClient bool) (*tls.Config, error) {
	if c == nil {
		return nil, ErrIdentity
	}
	if c.Profile == Development {
		return nil, nil
	}
	if e := c.CheckOwn(); e != nil {
		return nil, e
	}
	if e := c.verify(c.chain, x509.ExtKeyUsageServerAuth); e != nil {
		return nil, e
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{c.identity}, ClientCAs: c.roots}
	if requireClient {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		if e := c.CheckOwn(); e != nil {
			return nil, e
		}
		return nil, nil
	}
	cfg.VerifyConnection = func(state tls.ConnectionState) error {
		if requireClient {
			return c.checkPeer(&state, nil, false, x509.ExtKeyUsageClientAuth)
		}
		return c.CheckOwn()
	}
	return cfg, nil
}
func (c *Config) clientTLS(peer Role, serverName string) (*tls.Config, error) {
	if c == nil || c.Profile != Qualification || !peer.Valid() {
		return nil, ErrIdentity
	}
	if e := c.CheckOwn(); e != nil {
		return nil, e
	}
	if e := c.verify(c.chain, x509.ExtKeyUsageClientAuth); e != nil {
		return nil, e
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: c.roots, Certificates: []tls.Certificate{c.identity}, ServerName: serverName, VerifyConnection: func(state tls.ConnectionState) error {
		return c.checkPeer(&state, []Role{peer}, false, x509.ExtKeyUsageServerAuth)
	}}, nil
}
func (c *Config) GRPCClientTLS(peer Role, serverName string) (*tls.Config, error) {
	cfg, e := c.clientTLS(peer, serverName)
	if e == nil {
		cfg.NextProtos = []string{"h2"}
	}
	return cfg, e
}
