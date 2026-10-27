package main

import (
	"context"
	"log"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/trust"
	"github.com/5dg/nex-os/services/control/api"
	"github.com/5dg/nex-os/services/control/auth"
	"github.com/5dg/nex-os/services/control/devseed"
	"github.com/5dg/nex-os/services/control/guard"
	"github.com/5dg/nex-os/services/control/migrations"
	"github.com/5dg/nex-os/services/model"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5/pgxpool"
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
	profile, e := trust.FromEnv()
	if e != nil {
		log.Fatal(e)
	}
	command := "serve"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	if command != "serve" && command != "seed" && command != "migrate" {
		log.Fatal("unknown command")
	}
	raw := os.Getenv("DATABASE_URL")
	if file := os.Getenv("DATABASE_URL_FILE"); file != "" {
		b, e := os.ReadFile(file)
		if e != nil {
			log.Fatal("database identity unavailable")
		}
		raw = strings.TrimSpace(string(b))
	}
	if raw == "" {
		log.Fatal("database configuration required")
	}
	cfg, e := poolConfig(raw, profile, command)
	if e != nil {
		log.Fatal(e)
	}
	db, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		log.Fatal("database configuration invalid")
	}
	defer db.Close()
	if command == "migrate" {
		if e = migrations.Apply(ctx, db); e != nil {
			log.Fatal(e)
		}
		log.Print("Migrations applied")
		return
	}
	if command == "seed" {
		if os.Getenv("APP_ENV") != "development" {
			log.Fatal("seed is development-only")
		}
		if e = devseed.Seed(ctx, db, required("OIDC_ISSUER")); e != nil {
			log.Fatal(e)
		}
		if profile == trust.Qualification {
			e = devseed.SeedQualificationWorkflow(ctx, db, required("OIDC_ISSUER"))
		} else {
			e = devseed.SeedWorkflow(ctx, db, required("OIDC_ISSUER"))
		}
		if e != nil {
			log.Fatal(e)
		}
		if directory := os.Getenv("LOCAL_DATABASE_KEYS"); directory != "" {
			if e = devseed.LocalRoles(ctx, db, directory); e != nil {
				log.Fatal(e)
			}
		}
		log.Print("Synthetic seed applied")
		return
	}
	environment := required("APP_ENV")
	if environment != "development" {
		log.Fatal("only explicit synthetic profiles may start")
	}
	if profile == trust.Qualification && required("MODEL_PROVIDER") != "development" {
		log.Fatal("qualification forbids live providers")
	}
	adapter, e := model.New(environment, required("MODEL_PROVIDER"))
	if e != nil {
		log.Fatal(e)
	}
	identity, e := trust.Load(profile, trust.Control)
	if e != nil {
		log.Fatal(e)
	}
	issuer := required("OIDC_ISSUER")
	parsed, e := url.Parse(issuer)
	if e != nil || parsed.Host == "" {
		log.Fatal("invalid issuer")
	}
	discoveryContext := ctx
	if profile == trust.Qualification {
		if e = identity.CheckURL(issuer); e != nil {
			log.Fatal(e)
		}
		client, e := identity.HTTPClient(trust.OIDC, 5*time.Second)
		if e != nil {
			log.Fatal(e)
		}
		discoveryContext = oidc.ClientContext(ctx, client)
	}
	var verifier *auth.Verifier
	attempts := 30
	if profile == trust.Qualification {
		attempts = 3
	}
	for i := 0; i < attempts; i++ {
		probe, stop := context.WithTimeout(discoveryContext, 3*time.Second)
		if profile == trust.Qualification {
			verifier, e = auth.NewAccessTokenVerifier(probe, issuer, required("OIDC_AUDIENCE"), required("OIDC_CLIENT_ID"), required("OIDC_REQUIRED_SCOPE"))
		} else {
			verifier, e = auth.New(probe, issuer, required("OIDC_AUDIENCE"))
		}
		stop()
		if e == nil {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
	if e != nil {
		log.Fatal("OIDC discovery unavailable")
	}
	var legacyGuardKey []byte
	if profile == trust.Development {
		legacyGuardKey, e = broker.Key(required("GUARD_KEY_FILE"))
		if e != nil {
			log.Fatal(e)
		}
	}
	policy, e := guard.NewRPCWithTrust(required("GUARD_GRPC_ADDR"), legacyGuardKey, identity)
	if e != nil {
		log.Fatal(e)
	}
	defer policy.Close()
	server := &api.Server{DB: db, Auth: verifier, Policy: policy, Model: adapter, Environment: environment, Profile: profile, Trust: identity}
	if profile == trust.Qualification || os.Getenv("MODEL_URL") != "" {
		modelKey, e := broker.Key(required("MODEL_KEY_FILE"))
		if e != nil {
			log.Fatal(e)
		}
		exportKey, e := broker.Key(required("EXPORT_KEY_FILE"))
		if e != nil {
			log.Fatal(e)
		}
		server.WorkerKey, e = broker.Key(required("WORKER_KEY_FILE"))
		if e != nil {
			log.Fatal(e)
		}
		modelURL := required("MODEL_URL")
		exportURL := required("EXPORT_URL")
		if e = identity.CheckURL(modelURL); e != nil {
			log.Fatal(e)
		}
		if e = identity.CheckURL(exportURL); e != nil {
			log.Fatal(e)
		}
		server.ModelRPC = broker.NewClient(strings.TrimRight(modelURL, "/")+"/execute", "model.execute", modelKey)
		server.ToolRPC = broker.NewClient(strings.TrimRight(exportURL, "/")+"/execute", "export.execute", exportKey)
		if profile == trust.Qualification {
			server.ModelRPC.HTTP, e = identity.HTTPClient(trust.Model, 45*time.Second)
			if e != nil {
				log.Fatal(e)
			}
			server.ToolRPC.HTTP, e = identity.HTTPClient(trust.Export, 10*time.Second)
			if e != nil {
				log.Fatal(e)
			}
		}
	}
	if profile == trust.Qualification || os.Getenv("EVIDENCE_URL") != "" {
		key, e := broker.Key(required("EVIDENCE_KEY_FILE"))
		if e != nil {
			log.Fatal(e)
		}
		server.EvidencePublic, e = broker.Key(required("EVIDENCE_PUBLIC_FILE"))
		if e != nil {
			log.Fatal(e)
		}
		evidenceURL := required("EVIDENCE_URL")
		if e = identity.CheckURL(evidenceURL); e != nil {
			log.Fatal(e)
		}
		server.EvidenceRPC = broker.NewClient(strings.TrimRight(evidenceURL, "/")+"/append/control", "evidence.append.control", key)
		if profile == trust.Qualification {
			server.EvidenceRPC.HTTP, e = identity.HTTPClient(trust.Evidence, 5*time.Second)
			if e != nil {
				log.Fatal(e)
			}
		}
	}
	log.Print("control service starting; synthetic profile ", profile)
	if e = trust.ServeHTTP(ctx, required("LISTEN_ADDR"), server.Handler(), identity, profile == trust.Qualification); e != nil {
		log.Fatal(e)
	}
}
