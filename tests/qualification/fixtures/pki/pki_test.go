package pki

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIssuedTestLeavesHaveExplicitIdentityAndUsage(t *testing.T) {
	ca, e := NewAuthority("qualification fixture CA")
	if e != nil {
		t.Fatal(e)
	}
	identity, e := ca.Issue(Spec{Name: "guard", DNSNames: []string{"guard.test"}, URIs: []string{"spiffe://nex.local/service/guard"}, ServerAuth: true})
	if e != nil {
		t.Fatal(e)
	}
	leaf := identity.Certificate.Leaf
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), DNSName: "guard.test", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e != nil {
		t.Fatal(e)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://nex.local/service/guard" || leaf.IsCA {
		t.Fatal("leaf identity or constraints changed")
	}
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), DNSName: "different.test", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e == nil {
		t.Fatal("wrong server name accepted")
	}
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e == nil {
		t.Fatal("server-only leaf accepted as client")
	}
	other, e := NewAuthority("untrusted fixture CA")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: other.Pool(), DNSName: "guard.test", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e == nil {
		t.Fatal("untrusted CA accepted")
	}
	expired, e := ca.Issue(Spec{Name: "expired", ClientAuth: true, NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = expired.Certificate.Leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e == nil {
		t.Fatal("expired leaf accepted")
	}
}
func TestPrivateFixtureFilesRemainPrivate(t *testing.T) {
	ca, e := NewAuthority("fixture")
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := ca.Issue(Spec{Name: "control", ClientAuth: true})
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	files, e := ca.WriteFiles(dir, "control", leaf)
	if e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(files.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("private leaf permissions", info.Mode())
	}
	if _, e = ca.WriteFiles(dir, "../escape", leaf); e == nil {
		t.Fatal("fixture path escaped directory")
	}
	if _, e = ca.Issue(Spec{Name: "ambiguous"}); e == nil {
		t.Fatal("leaf without explicit usage accepted")
	}
}

func TestBundleRefusesOverwritingAndContainsOnlyPublicManifest(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "new-pki")
	config := BundleConfig{ValidForSeconds: 600, Entries: []BundleEntry{{Name: "workspace-client", URIs: []string{"spiffe://nex.local/service/workspace"}, ClientAuth: true}, {Name: "workspace-server", DNSNames: []string{"workspace.nex.test"}, URIs: []string{"spiffe://nex.local/service/workspace"}, ServerAuth: true}}}
	manifest, e := WriteBundle(directory, config)
	if e != nil {
		t.Fatal(e)
	}
	if manifest.Profile != "synthetic-qualification" || len(manifest.Identities) != 2 {
		t.Fatal("bundle identity contract changed")
	}
	raw, e := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, []byte("PRIVATE KEY")) {
		t.Fatal("manifest contains private material")
	}
	original, e := os.ReadFile(filepath.Join(directory, "workspace-client", "tls.key"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = WriteBundle(directory, config); e == nil {
		t.Fatal("existing bundle overwritten")
	}
	current, e := os.ReadFile(filepath.Join(directory, "workspace-client", "tls.key"))
	if e != nil || !bytes.Equal(original, current) {
		t.Fatal("refused generation changed existing key")
	}
}
