package main

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/5dg/nex-os/packages/trust"
	"github.com/5dg/nex-os/tests/qualification/fixtures/pki"
)

func TestQualificationDatabaseRequiresVerifiedBoundedMinimalIdentity(t *testing.T) {
	ca, e := pki.NewAuthority("database-test")
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "db-ca.crt")
	if e = os.WriteFile(path, ca.CertificatePEM(), 0600); e != nil {
		t.Fatal(e)
	}
	t.Setenv("NEX_DB_CA_FILE", path)
	valid := "postgres://nex_control:synthetic@postgres/nex?sslmode=verify-full"
	cfg, e := poolConfig(valid, trust.Qualification, "serve")
	if e != nil {
		t.Fatal("valid profile rejected", e)
	}
	if cfg.ConnConfig.TLSConfig == nil || cfg.ConnConfig.TLSConfig.InsecureSkipVerify || cfg.ConnConfig.TLSConfig.RootCAs == nil || cfg.ConnConfig.TLSConfig.ServerName != "postgres" || cfg.ConnConfig.TLSConfig.MinVersion != tls.VersionTLS13 || len(cfg.ConnConfig.Fallbacks) != 0 || cfg.ConnConfig.ConnectTimeout != 3*time.Second || cfg.MaxConns != 4 || cfg.ConnConfig.RuntimeParams["lock_timeout"] != "2000" {
		t.Fatal("qualification DB configuration weakened")
	}
	for _, bad := range []string{"postgres://nex_control:synthetic@localhost/nex?sslmode=verify-full", "postgres://nex_control:synthetic@unexpected/nex?sslmode=verify-full", "postgres://nex_control:synthetic@postgres/nex?sslmode=disable", "postgres://nex_control:synthetic@postgres/nex?sslmode=require", "postgres://nex_control:synthetic@postgres/nex?sslmode=prefer", "postgres://nex_control:synthetic@postgres/nex?sslmode=verify-full&sslmode=disable", "postgres://nex:synthetic@postgres/nex?sslmode=verify-full"} {
		if _, e = poolConfig(bad, trust.Qualification, "serve"); e == nil {
			t.Fatal("database downgrade accepted", bad)
		}
	}
	if _, e = poolConfig("postgres://nex:synthetic@postgres/nex?sslmode=verify-full", trust.Qualification, "migrate"); e != nil {
		t.Fatal("explicit trusted bootstrap administrator rejected", e)
	}
	t.Setenv("NEX_DB_CA_FILE", "")
	if _, e = poolConfig(valid, trust.Qualification, "serve"); e == nil {
		t.Fatal("database CA fallback accepted")
	}
}
