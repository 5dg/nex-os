package main

import (
	"bytes"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/5dg/nex-os/packages/trust"
	"github.com/5dg/nex-os/services/control/api"
	"github.com/5dg/nex-os/tests/qualification/fixtures/pki"
)

func TestHistoryCursorKeyRequiresPrivateOwnedRegularFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "cursor.key")
	valid := bytes.Repeat([]byte{0x53}, 32)
	if err := configureHistoryCursorKey(&api.Server{}, path); err == nil {
		t.Fatal("missing key accepted")
	}
	if err := os.WriteFile(path, valid, 0600); err != nil {
		t.Fatal(err)
	}
	if err := configureHistoryCursorKey(&api.Server{}, path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	if err := configureHistoryCursorKey(&api.Server{}, path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := configureHistoryCursorKey(&api.Server{}, link); err == nil {
		t.Fatal("symlink key accepted")
	}
	if err := configureHistoryCursorKey(&api.Server{}, dir); err == nil {
		t.Fatal("directory key accepted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := configureHistoryCursorKey(&api.Server{}, path); err == nil {
		t.Fatal("public key permissions accepted")
	}
	for _, mode := range []os.FileMode{0000, 0200} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := configureHistoryCursorKey(&api.Server{}, path); err == nil {
			t.Fatalf("owner-unreadable key mode %04o accepted", mode)
		}
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{make([]byte, 31), make([]byte, 32), make([]byte, 33)} {
		if err := os.WriteFile(path, bad, 0600); err != nil {
			t.Fatal(err)
		}
		if err := configureHistoryCursorKey(&api.Server{}, path); err == nil {
			t.Fatal("malformed key accepted")
		}
	}
	if os.Geteuid() == 0 {
		if err := os.WriteFile(path, valid, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 65534, -1); err != nil {
			t.Fatal(err)
		}
		if err := configureHistoryCursorKey(&api.Server{}, path); err == nil {
			t.Fatal("wrong owner accepted")
		}
	}
}

func TestHistoryCursorKeyringEnvironmentRequiresBothPrivateDistinctFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private-ring")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	current, previous := filepath.Join(dir, "current"), filepath.Join(dir, "previous")
	if err := os.WriteFile(current, bytes.Repeat([]byte{0x13}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(previous, bytes.Repeat([]byte{0x24}, 32), 0400); err != nil {
		t.Fatal(err)
	}
	old, wasSet := os.LookupEnv("NEX_HISTORY_CURSOR_KEY_FILE")
	if err := os.Unsetenv("NEX_HISTORY_CURSOR_KEY_FILE"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if wasSet {
			_ = os.Setenv("NEX_HISTORY_CURSOR_KEY_FILE", old)
		} else {
			_ = os.Unsetenv("NEX_HISTORY_CURSOR_KEY_FILE")
		}
	})
	t.Setenv("NEX_HISTORY_CURSOR_PREVIOUS_KEY_FILE", previous)
	if err := configureHistoryCursorEnvironment(&api.Server{}); err == nil {
		t.Fatal("previous key without current accepted")
	}
	t.Setenv("NEX_HISTORY_CURSOR_KEY_FILE", current)
	if err := configureHistoryCursorEnvironment(&api.Server{}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NEX_HISTORY_CURSOR_PREVIOUS_KEY_FILE", current)
	if err := configureHistoryCursorEnvironment(&api.Server{}); err == nil {
		t.Fatal("duplicate keys accepted")
	}
	t.Setenv("NEX_HISTORY_CURSOR_PREVIOUS_KEY_FILE", "")
	if err := configureHistoryCursorEnvironment(&api.Server{}); err == nil {
		t.Fatal("empty previous key path accepted")
	}
	if err := os.Chmod(previous, 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NEX_HISTORY_CURSOR_PREVIOUS_KEY_FILE", previous)
	if err := configureHistoryCursorEnvironment(&api.Server{}); err == nil {
		t.Fatal("public previous key accepted")
	}
	if err := os.Chmod(previous, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(previous, bytes.Repeat([]byte{0x24}, 31), 0600); err != nil {
		t.Fatal(err)
	}
	if err := configureHistoryCursorEnvironment(&api.Server{}); err == nil {
		t.Fatal("short previous key accepted")
	}
}

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
