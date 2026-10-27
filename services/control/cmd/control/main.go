package main

import (
	"context"
	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/services/control/api"
	"github.com/5dg/nex-os/services/control/auth"
	"github.com/5dg/nex-os/services/control/devseed"
	"github.com/5dg/nex-os/services/control/guard"
	"github.com/5dg/nex-os/services/control/migrations"
	"github.com/5dg/nex-os/services/model"
	"github.com/jackc/pgx/v5/pgxpool"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func required(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("%s required", k)
	}
	return v
}
func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	database := os.Getenv("DATABASE_URL")
	if file := os.Getenv("DATABASE_URL_FILE"); file != "" {
		value, e := os.ReadFile(file)
		if e != nil {
			log.Fatal("database identity unavailable")
		}
		database = strings.TrimSpace(string(value))
	}
	if database == "" {
		log.Fatal("database configuration required")
	}
	db, err := pgxpool.New(ctx, database)
	if err != nil {
		log.Fatal("database configuration invalid")
	}
	defer db.Close()
	command := "serve"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	if command == "migrate" {
		if err = migrations.Apply(ctx, db); err != nil {
			log.Fatal(err)
		}
		log.Print("Migrations applied")
		return
	}
	if command == "seed" {
		if os.Getenv("APP_ENV") != "development" {
			log.Fatal("seed is development-only")
		}
		if err = devseed.Seed(ctx, db, required("OIDC_ISSUER")); err != nil {
			log.Fatal(err)
		}
		if err = devseed.SeedWorkflow(ctx, db, required("OIDC_ISSUER")); err != nil {
			log.Fatal(err)
		}
		if directory := os.Getenv("LOCAL_DATABASE_KEYS"); directory != "" {
			if err = devseed.LocalRoles(ctx, db, directory); err != nil {
				log.Fatal(err)
			}
		}
		log.Print("Synthetic seed applied")
		return
	}
	if command != "serve" {
		log.Fatal("unknown command")
	}
	env := required("APP_ENV")
	adapter, err := model.New(env, required("MODEL_PROVIDER"))
	if err != nil {
		log.Fatal(err)
	}
	issuer := required("OIDC_ISSUER")
	u, err := url.Parse(issuer)
	if err != nil || (env == "production" && u.Scheme != "https") {
		log.Fatal("invalid issuer scheme")
	}
	policyURL := required("OPA_URL")
	u, err = url.Parse(policyURL)
	if err != nil || u.Host == "" {
		log.Fatal("invalid OPA URL")
	}
	var verifier *auth.Verifier
	for i := 0; i < 30; i++ {
		c, done := context.WithTimeout(ctx, 3*time.Second)
		verifier, err = auth.New(c, issuer, required("OIDC_AUDIENCE"))
		done()
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
	if err != nil {
		log.Fatal("OIDC discovery unavailable")
	}
	guardKey, e := broker.Key(required("GUARD_KEY_FILE"))
	if e != nil {
		log.Fatal(e)
	}
	policy, e := guard.NewRPC(required("GUARD_GRPC_ADDR"), guardKey, env == "development")
	if e != nil {
		log.Fatal(e)
	}
	defer policy.Close()
	s := &api.Server{DB: db, Auth: verifier, Policy: policy, Model: adapter, Environment: env}
	if os.Getenv("MODEL_URL") != "" {
		modelKey, e := broker.Key(required("MODEL_KEY_FILE"))
		if e != nil {
			log.Fatal(e)
		}
		exportKey, e := broker.Key(required("EXPORT_KEY_FILE"))
		if e != nil {
			log.Fatal(e)
		}
		s.WorkerKey, e = broker.Key(required("WORKER_KEY_FILE"))
		if e != nil {
			log.Fatal(e)
		}
		s.ModelRPC = broker.NewClient(required("MODEL_URL")+"/execute", "model.execute", modelKey)
		s.ToolRPC = broker.NewClient(required("EXPORT_URL")+"/execute", "export.execute", exportKey)
	}
	if os.Getenv("EVIDENCE_URL") != "" {
		key, e := broker.Key(required("EVIDENCE_KEY_FILE"))
		if e != nil {
			log.Fatal(e)
		}
		s.EvidencePublic, e = broker.Key(required("EVIDENCE_PUBLIC_FILE"))
		if e != nil {
			log.Fatal(e)
		}
		s.EvidenceRPC = broker.NewClient(required("EVIDENCE_URL")+"/append/control", "evidence.append.control", key)
	}
	srv := &http.Server{Addr: required("LISTEN_ADDR"), Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 65 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	go func() {
		<-ctx.Done()
		c, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		srv.Shutdown(c)
	}()
	log.Print("control service started; synthetic-data foundation")
	if err = srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
