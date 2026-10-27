// qualification-policy-edge confines the one OPA engine to its network namespace
// and authenticates only the Guard workload for pinned-source/decision requests.
package main

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/5dg/nex-os/packages/trust"
)

func policyHandler(transport http.RoundTripper) http.Handler {
	upstream := &url.URL{Scheme: "http", Host: "127.0.0.1:8182"}
	proxy := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) {
		r.SetURL(upstream)
		r.Out.Host = upstream.Host
		for key := range r.Out.Header {
			if strings.EqualFold(key, "Authorization") || strings.EqualFold(key, "Forwarded") || strings.HasPrefix(strings.ToLower(key), "x-forwarded-") {
				r.Out.Header.Del(key)
			}
		}
	}, Transport: transport, ErrorLog: log.New(io.Discard, "", 0), ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "policy dependency unavailable", 503)
	}}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		permitted := r.Method == http.MethodGet && r.URL.Path == "/v1/policies" || r.Method == http.MethodPost && r.URL.Path == "/v1/data/nex/authz/decision"
		if !permitted || r.URL.RawQuery != "" || r.URL.RawPath != "" || r.URL.IsAbs() {
			http.Error(w, "policy endpoint denied", 403)
			return
		}
		if r.Method == http.MethodPost && strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
			http.Error(w, "JSON decision input required", 415)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
		proxy.ServeHTTP(w, r)
	})
}
func main() {
	profile, e := trust.FromEnv()
	if e != nil || profile != trust.Qualification {
		log.Fatal("policy edge requires explicit synthetic qualification profile")
	}
	cfg, e := trust.Load(profile, trust.OPA)
	if e != nil {
		log.Fatal("policy TLS identity unavailable")
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, ResponseHeaderTimeout: 3 * time.Second, IdleConnTimeout: 10 * time.Second}
	h := cfg.Middleware([]trust.Role{trust.Guard}, policyHandler(transport))
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
