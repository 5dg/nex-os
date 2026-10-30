// policy-edge is a candidate production mTLS boundary for a task-local OPA.
// Deploying it requires independently approved certificate issuance, exact
// Guard identity, a scanned immutable OPA image and task-level isolation.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/5dg/nex-os/packages/policyedge"
)

func run(ctx context.Context) error {
	if os.Getenv("APP_ENV") != "production" || os.Getenv("NEX_POLICY_EDGE_ENABLED") != "true" {
		return errors.New("policy edge requires explicit production candidate enablement")
	}
	id, err := policyedge.LoadIdentity(os.Getenv("NEX_POLICY_SERVER_CA_FILE"), os.Getenv("NEX_POLICY_CLIENT_CA_FILE"), os.Getenv("NEX_POLICY_CERT_FILE"), os.Getenv("NEX_POLICY_KEY_FILE"), os.Getenv("NEX_POLICY_GUARD_URI"))
	if err != nil {
		return errors.New("policy edge trust configuration unavailable")
	}
	tlsConfig, err := id.ServerTLS()
	if err != nil {
		return errors.New("policy edge TLS unavailable")
	}
	address := os.Getenv("NEX_POLICY_LISTEN_ADDR")
	if address == "" {
		return errors.New("policy edge listen address required")
	}
	transport := policyedge.LoopbackTransport()
	defer transport.CloseIdleConnections()
	handler := policyedge.Bounded(policyedge.Handler(transport, id.Check))
	server := &http.Server{Addr: address, TLSConfig: tlsConfig, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16 * 1024,
		Handler: handler}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServeTLS("", "") }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("policy edge listener failed")
	case <-ctx.Done():
		drain, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(drain); err != nil {
			_ = server.Close()
			<-done
			return errors.New("policy edge shutdown incomplete")
		}
		<-done
		return nil
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
