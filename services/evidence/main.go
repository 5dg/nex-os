package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/evidence"
	"github.com/5dg/nex-os/packages/trust"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if (len(os.Args) == 4 || len(os.Args) == 5) && os.Args[1] == "verify" {
		public, e := broker.Key(os.Args[3])
		if e != nil {
			log.Fatal(e)
		}
		var checkpoint *evidence.Proof
		if len(os.Args) == 5 {
			b, e := os.ReadFile(os.Args[4])
			if e != nil {
				log.Fatal(e)
			}
			var saved struct {
				Checkpoint evidence.Proof `json:"checkpoint"`
			}
			if e = json.Unmarshal(b, &saved); e != nil {
				log.Fatal(e)
			}
			checkpoint = &saved.Checkpoint
		}
		entries, e := evidence.Verify(os.Args[2], ed25519.PublicKey(public), checkpoint)
		if e != nil {
			log.Fatal(e)
		}
		if len(entries) == 0 {
			log.Fatal("no evidence entries verified")
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{"events": len(entries), "checkpoint": entries[len(entries)-1].Proof})
		return
	}
	if len(os.Args) == 4 && os.Args[1] == "public-key" {
		seed, e := broker.Key(os.Args[2])
		if e != nil {
			log.Fatal(e)
		}
		public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		if e = os.WriteFile(os.Args[3], public, 0644); e != nil {
			log.Fatal(e)
		}
		return
	}

	if os.Getenv("APP_ENV") != "development" {
		log.Fatal("local evidence custody is development-only")
	}
	key, e := broker.Key(os.Getenv("EVIDENCE_KEY_FILE"))
	if e != nil {
		log.Fatal(e)
	}
	seed, e := broker.Key(os.Getenv("SIGNING_SEED_FILE"))
	if e != nil {
		log.Fatal(e)
	}
	profile, e := trust.FromEnv()
	if e != nil {
		log.Fatal(e)
	}
	cfg, e := trust.Load(profile, trust.Evidence)
	if e != nil {
		log.Fatal(e)
	}
	journal, e := evidence.OpenJournal(os.Getenv("EVIDENCE_DIR"), ed25519.NewKeyFromSeed(seed))
	if e != nil {
		log.Fatal(e)
	}
	defer journal.Close()
	kernelKey, e := broker.Key(os.Getenv("KERNEL_EVIDENCE_KEY_FILE"))
	if e != nil {
		log.Fatal(e)
	}
	var peer func(*http.Request, string) error
	if profile == trust.Qualification {
		peer = func(r *http.Request, producer string) error {
			if e := r.Context().Err(); e != nil {
				return e
			}
			roles := []trust.Role{trust.Control, trust.Guard}
			if producer == "control" {
				roles = []trust.Role{trust.Control}
			}
			if producer == "kernel" {
				roles = []trust.Role{trust.Guard}
			}
			return cfg.CheckPeer(r.TLS, roles)
		}
	}
	mux := evidence.HandlerWithPeer(journal, key, kernelKey, peer)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Print("local evidence writer started; independent production anchoring remains required; profile=", profile)
	if e = trust.ServeHTTP(ctx, ":8084", mux, cfg, true); e != nil {
		log.Fatal(e)
	}

}
