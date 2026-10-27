package pki

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

type BundleEntry struct {
	Name        string   `json:"name"`
	DNSNames    []string `json:"dns_names,omitempty"`
	IPAddresses []string `json:"ip_addresses,omitempty"`
	URIs        []string `json:"uris,omitempty"`
	ClientAuth  bool     `json:"client_auth"`
	ServerAuth  bool     `json:"server_auth"`
}
type BundleConfig struct {
	ValidForSeconds int           `json:"valid_for_seconds"`
	Entries         []BundleEntry `json:"entries"`
}
type BundleIdentity struct {
	BundleEntry
	CA                     string `json:"ca"`
	Certificate            string `json:"certificate"`
	PrivateKey             string `json:"private_key"`
	CertificateFingerprint string `json:"certificate_fingerprint"`
}
type BundleManifest struct {
	Version       int              `json:"version"`
	Profile       string           `json:"profile"`
	CreatedAt     time.Time        `json:"created_at"`
	CAFingerprint string           `json:"ca_fingerprint"`
	Identities    []BundleIdentity `json:"identities"`
}

func fingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// WriteBundle creates a NEW directory exclusively. Existing directories or key
// material are never overwritten. A failed generation may leave its own partial
// directory for inspection; rerun with a new directory rather than resetting it.
func WriteBundle(directory string, config BundleConfig) (BundleManifest, error) {
	if directory == "" || directory == "." || directory == string(filepath.Separator) {
		return BundleManifest{}, errors.New("new qualification PKI directory required")
	}
	if config.ValidForSeconds == 0 {
		config.ValidForSeconds = 3600
	}
	if config.ValidForSeconds < 30 || config.ValidForSeconds > 3600 || len(config.Entries) == 0 || len(config.Entries) > 32 {
		return BundleManifest{}, errors.New("bounded test PKI validity and identity count required")
	}
	seen := map[string]bool{}
	specs := make([]Spec, len(config.Entries))
	expires := time.Now().Add(time.Duration(config.ValidForSeconds) * time.Second)
	for i, entry := range config.Entries {
		if !basename.MatchString(entry.Name) || seen[entry.Name] || (!entry.ClientAuth && !entry.ServerAuth) {
			return BundleManifest{}, errors.New("unique named test identities with explicit usage required")
		}
		seen[entry.Name] = true
		spec := Spec{Name: entry.Name, DNSNames: entry.DNSNames, URIs: entry.URIs, ClientAuth: entry.ClientAuth, ServerAuth: entry.ServerAuth, NotAfter: expires}
		for _, raw := range entry.IPAddresses {
			ip := net.ParseIP(raw)
			if ip == nil {
				return BundleManifest{}, errors.New("invalid test certificate IP SAN")
			}
			spec.IPAddresses = append(spec.IPAddresses, ip)
		}
		specs[i] = spec
	}
	if e := os.MkdirAll(filepath.Dir(directory), 0700); e != nil {
		return BundleManifest{}, e
	}
	if e := os.Mkdir(directory, 0700); e != nil {
		return BundleManifest{}, fmt.Errorf("refusing existing or unavailable test PKI directory: %w", e)
	}
	ca, e := NewAuthority("Nex synthetic qualification test CA")
	if e != nil {
		return BundleManifest{}, e
	}
	manifest := BundleManifest{Version: 1, Profile: "synthetic-qualification", CreatedAt: time.Now().UTC(), CAFingerprint: fingerprint(ca.certificate.Raw), Identities: []BundleIdentity{}}
	if e = os.WriteFile(filepath.Join(directory, "ca.crt"), ca.CertificatePEM(), 0644); e != nil {
		return BundleManifest{}, e
	}
	for i, entry := range config.Entries {
		leaf, e := ca.Issue(specs[i])
		if e != nil {
			return BundleManifest{}, e
		}
		files, e := ca.WriteFiles(filepath.Join(directory, entry.Name), "tls", leaf)
		if e != nil {
			return BundleManifest{}, e
		}
		caPath, _ := filepath.Rel(directory, files.CA)
		certPath, _ := filepath.Rel(directory, files.Certificate)
		keyPath, _ := filepath.Rel(directory, files.PrivateKey)
		manifest.Identities = append(manifest.Identities, BundleIdentity{BundleEntry: entry, CA: caPath, Certificate: certPath, PrivateKey: keyPath, CertificateFingerprint: fingerprint(leaf.Certificate.Leaf.Raw)})
	}
	raw, e := json.MarshalIndent(manifest, "", "  ")
	if e != nil {
		return BundleManifest{}, e
	}
	if e = os.WriteFile(filepath.Join(directory, "manifest.json"), append(raw, '\n'), 0644); e != nil {
		return BundleManifest{}, e
	}
	return manifest, nil
}
