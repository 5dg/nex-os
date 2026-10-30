// qualification-policy-edge confines the one OPA engine to its network namespace
// and authenticates only the Guard workload for pinned-source/decision requests.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/5dg/nex-os/packages/policyedge"
	"github.com/5dg/nex-os/packages/trust"
)

func main() {
	profile, e := trust.FromEnv()
	if e != nil || profile != trust.Qualification {
		log.Fatal("policy edge requires explicit synthetic qualification profile")
	}
	cfg, e := trust.Load(profile, trust.OPA)
	if e != nil {
		log.Fatal("policy TLS identity unavailable")
	}
	transport := policyedge.LoopbackTransport()
	h := policyedge.Bounded(policyedge.Handler(transport, func(r *http.Request) error { return cfg.CheckPeer(r.TLS, []trust.Role{trust.Guard}) }))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	address := os.Getenv("LISTEN_ADDR")
	if address == "" {
		address = ":8181"
	}
	if e = trust.ServeHTTP(ctx, address, h, cfg, true); e != nil {
		log.Fatal("qualification policy edge stopped")
	}
}
