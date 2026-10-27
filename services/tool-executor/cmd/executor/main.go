package main

import (
	"context"
	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/trust"
	"github.com/5dg/nex-os/services/control/guard"
	executor "github.com/5dg/nex-os/services/tool-executor"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if os.Getenv("APP_ENV") != "development" {
		log.Fatal("local synthetic export storage is development-only")
	}
	profile, e := trust.FromEnv()
	if e != nil {
		log.Fatal(e)
	}
	cfg, e := trust.Load(profile, trust.Export)
	if e != nil {
		log.Fatal(e)
	}
	key, e := broker.Key(os.Getenv("EXPORT_KEY_FILE"))
	if e != nil {
		log.Fatal(e)
	}
	var guardKey []byte
	if profile == trust.Development {
		guardKey, e = broker.Key(os.Getenv("EXPORT_GUARD_KEY_FILE"))
		if e != nil {
			log.Fatal(e)
		}
	}
	authority, e := guard.NewRPCWithTrust(os.Getenv("GUARD_GRPC_ADDR"), guardKey, cfg)
	if e != nil {
		log.Fatal(e)
	}
	defer authority.Close()
	receipts, e := broker.OpenReceiptStore(os.Getenv("RECEIPTS_DIR"), "export")
	if e != nil {
		log.Fatal(e)
	}
	defer receipts.Close()
	peer := func(r *http.Request) error {
		if e := r.Context().Err(); e != nil {
			return e
		}
		return cfg.CheckPeer(r.TLS, []trust.Role{trust.Control})
	}
	service := &executor.Service{Key: key, Receipts: receipts, Validate: authority, Profile: string(profile), PeerCheck: peer}
	log.Print("controlled synthetic export executor started; profile=", profile)
	if e = trust.ServeHTTP(ctx, ":8083", service.Handler(), cfg, true); e != nil {
		log.Fatal(e)
	}
}
