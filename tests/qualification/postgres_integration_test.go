//go:build integration

package qualification_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/5dg/nex-os/tests/qualification/fixtures/pki"
	"github.com/jackc/pgx/v5"
)

// This observes actual PG connection-time verification and provisioned runtime
// privileges. It does not claim per-query revalidation of established PG TLS.
func TestQualificationSystemPostgresTLSAndRoles(t *testing.T) {
	state := os.Getenv("NEX_QUAL_STATE_DIR")
	if !filepath.IsAbs(state) {
		t.Fatal("absolute NEX_QUAL_STATE_DIR required")
	}
	ca, e := os.ReadFile(filepath.Join(state, "current-pki", "ca.crt"))
	if e != nil {
		t.Fatal("qualification database CA unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid qualification database CA")
	}
	makeConfig := func(role string) *pgx.ConnConfig {
		t.Helper()
		raw, e := os.ReadFile(filepath.Join(state, "secrets", role+"-database-url"))
		if e != nil {
			t.Fatal("qualification runtime database credential unavailable")
		}
		cfg, e := pgx.ParseConfig(strings.TrimSpace(string(raw)))
		if e != nil {
			t.Fatal("invalid private database configuration")
		}
		cfg.Host = "postgres"
		cfg.Port = 55432
		cfg.ConnectTimeout = 3 * time.Second
		cfg.Fallbacks = nil
		cfg.TLSConfig = &tls.Config{ServerName: "postgres", RootCAs: roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
		cfg.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "postgres:55432" {
				return nil, errors.New("unexpected database host")
			}
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, "127.0.0.1:55432")
		}
		cfg.LookupFunc = func(ctx context.Context, host string) ([]string, error) {
			if host != "postgres" {
				return nil, errors.New("unexpected database DNS")
			}
			return []string{"postgres"}, nil
		}
		return cfg
	}
	for _, role := range []string{"control", "guard"} {
		t.Run(role, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			conn, e := pgx.ConnectConfig(ctx, makeConfig(role))
			if e != nil {
				t.Fatal("positive verified database connection failed")
			}
			defer conn.Close(context.Background())
			var user, version string
			var super, createDB, createRole, encrypted bool
			e = conn.QueryRow(ctx, `SELECT current_user,r.rolsuper,r.rolcreatedb,r.rolcreaterole,s.ssl,s.version FROM pg_roles r JOIN pg_stat_ssl s ON s.pid=pg_backend_pid() WHERE r.rolname=current_user`).Scan(&user, &super, &createDB, &createRole, &encrypted, &version)
			if e != nil || user != "nex_"+role || super || createDB || createRole || !encrypted || version != "TLSv1.3" {
				t.Fatal("actual runtime database role/TLS exceeds qualification contract")
			}
			var changesRoute, changesAdmission, changesIdentity bool
			e = conn.QueryRow(ctx, `SELECT has_column_privilege(current_user,'model_routes','effective_endpoint','UPDATE'),has_column_privilege(current_user,'document_admissions','content_digest','UPDATE'),has_column_privilege(current_user,'users','subject','UPDATE')`).Scan(&changesRoute, &changesAdmission, &changesIdentity)
			if e != nil || changesRoute || changesAdmission || changesIdentity {
				t.Fatal("runtime role can mutate protected route/admission/identity")
			}
			var updateResult, insertResult, updateAnswer, updateReview bool
			e = conn.QueryRow(ctx, `SELECT has_column_privilege(current_user,'execution_operations','result','UPDATE'),has_column_privilege(current_user,'execution_operations','result','INSERT'),has_column_privilege(current_user,'jobs','answer','UPDATE'),has_column_privilege(current_user,'jobs','review_operation_id','UPDATE')`).Scan(&updateResult, &insertResult, &updateAnswer, &updateReview)
			if e != nil {
				t.Fatal("protected result privilege query failed")
			}
			want := role == "guard"
			if updateResult != want || insertResult != want || updateAnswer != want || updateReview != want {
				t.Fatal("protected result write authority differs from runtime role contract")
			}
		})
	}
	other, e := pki.NewAuthority("untrusted database fixture root")
	if e != nil {
		t.Fatal(e)
	}
	for _, test := range []struct {
		name   string
		mutate func(*pgx.ConnConfig)
	}{{"wrong CA", func(c *pgx.ConnConfig) { c.TLSConfig.RootCAs = other.Pool() }}, {"wrong DNS", func(c *pgx.ConnConfig) { c.TLSConfig.ServerName = "not-postgres" }}, {"plaintext", func(c *pgx.ConnConfig) { c.TLSConfig = nil }}} {
		t.Run(test.name, func(t *testing.T) {
			cfg := makeConfig("control")
			test.mutate(cfg)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := pgx.ConnectConfig(ctx, cfg)
			if err == nil {
				conn.Close(context.Background())
				t.Fatal("database negative unexpectedly connected")
			}
			if test.name == "wrong CA" {
				var untrusted x509.UnknownAuthorityError
				if !errors.As(err, &untrusted) {
					t.Fatal("database wrong-CA failure was not verified trust rejection")
				}
			}
			if test.name == "wrong DNS" {
				var mismatch x509.HostnameError
				if !errors.As(err, &mismatch) {
					t.Fatal("database wrong-name failure was not verified DNS rejection")
				}
			}
		})
	}
}
