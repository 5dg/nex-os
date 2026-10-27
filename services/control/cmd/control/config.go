package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"os"
	"time"

	"github.com/5dg/nex-os/packages/trust"
	"github.com/jackc/pgx/v5/pgxpool"
)

func poolConfig(raw string, profile trust.Profile, command string) (*pgxpool.Config, error) {
	cfg, e := pgxpool.ParseConfig(raw)
	if e != nil {
		return nil, errors.New("database configuration invalid")
	}
	if profile != trust.Qualification {
		return cfg, nil
	}
	parsed, e := url.Parse(raw)
	if e != nil || parsed.Hostname() != "postgres" || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		return nil, errors.New("qualification database URI requires postgres host")
	}
	modes := parsed.Query()["sslmode"]
	if len(modes) != 1 || modes[0] != "verify-full" || cfg.ConnConfig.TLSConfig == nil {
		return nil, errors.New("qualification database requires verify-full TLS")
	}
	if command == "serve" && cfg.ConnConfig.User != "nex_control" {
		return nil, errors.New("restricted control database role required")
	}
	caFile := os.Getenv("NEX_DB_CA_FILE")
	if caFile == "" {
		return nil, errors.New("explicit database CA required")
	}
	ca, e := os.ReadFile(caFile)
	if e != nil {
		return nil, errors.New("database trust unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("database CA invalid")
	}
	cfg.ConnConfig.TLSConfig.RootCAs = roots
	cfg.ConnConfig.TLSConfig.ServerName = parsed.Hostname()
	cfg.ConnConfig.TLSConfig.InsecureSkipVerify = false
	cfg.ConnConfig.TLSConfig.MinVersion = tls.VersionTLS13
	cfg.ConnConfig.TLSConfig.MaxVersion = tls.VersionTLS13
	cfg.ConnConfig.Fallbacks = nil
	cfg.ConnConfig.ConnectTimeout = 3 * time.Second
	cfg.MaxConns = 4
	cfg.MinConns = 0
	cfg.MaxConnLifetime = 10 * time.Minute
	cfg.MaxConnIdleTime = 30 * time.Second
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "3000"
	cfg.ConnConfig.RuntimeParams["lock_timeout"] = "2000"
	cfg.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "10000"
	return cfg, nil
}
