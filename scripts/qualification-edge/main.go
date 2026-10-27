// qualification-edge terminates browser HTTPS in the frontend network namespace.
// Its only plaintext hop is the fixed loopback Next.js process in that namespace.
package main

import (
	"context"
	"errors"
	"flag"
	"github.com/5dg/nex-os/packages/trust"
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
)

var frontendUpstream = &url.URL{Scheme: "http", Host: "127.0.0.1:3000"}

func canonicalOrigin(value string) (*url.URL, error) {
	u, e := url.Parse(value)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("canonical HTTPS public origin required")
	}
	return u, nil
}
func untrustedIdentityHeader(name string) bool {
	name = strings.ToLower(name)
	return name == "authorization" || name == "proxy-authorization" || name == "forwarded" || name == "remote-user" || strings.HasPrefix(name, "x-forwarded-") || strings.HasPrefix(name, "x-client-") || strings.HasPrefix(name, "x-auth-") || strings.HasPrefix(name, "x-user-") || strings.HasPrefix(name, "x-tenant-") || strings.HasPrefix(name, "x-role") || strings.HasPrefix(name, "x-remote-") || strings.HasPrefix(name, "x-ssl-") || strings.HasPrefix(name, "ssl-client-") || strings.HasPrefix(name, "x-nex-")
}
func handler(origin *url.URL, transport http.RoundTripper) http.Handler {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(p *httputil.ProxyRequest) {
			p.SetURL(frontendUpstream)
			p.Out.Host = origin.Host
			for name := range p.Out.Header {
				if untrustedIdentityHeader(name) {
					p.Out.Header.Del(name)
				}
			}
			// These values come only from fixed configuration, after incoming values
			// were removed. The browser's forwarded identity never becomes authority.
			p.Out.Header.Set("X-Forwarded-Proto", "https")
			p.Out.Header.Set("X-Forwarded-Host", origin.Host)
		}, Transport: transport, ErrorLog: log.New(io.Discard, "", 0),
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "frontend unavailable", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Strict-Transport-Security", "max-age=300")
		if r.TLS == nil {
			http.Error(w, "HTTPS required", http.StatusUpgradeRequired)
			return
		}
		if !strings.EqualFold(r.Host, origin.Host) {
			http.Error(w, "canonical host required", http.StatusMisdirectedRequest)
			return
		}
		if r.URL.IsAbs() || r.Method == http.MethodConnect || r.Method == http.MethodTrace {
			http.Error(w, "unsupported request", http.StatusBadRequest)
			return
		}
		unsafe := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
		supplied := r.Header.Get("Origin")
		if supplied != "" && supplied != origin.String() || unsafe && supplied != origin.String() {
			http.Error(w, "origin denied", http.StatusForbidden)
			return
		}
		if r.ContentLength > 128*1024 {
			http.Error(w, "bounded request required", 413)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
		proxy.ServeHTTP(w, r)
	})
}
func main() {
	originValue := flag.String("origin", os.Getenv("WORKSPACE_ORIGIN"), "canonical browser HTTPS origin")
	listen := flag.String("listen", ":9443", "HTTPS listen address")
	qualification := flag.Bool("synthetic-qualification", false, "explicitly acknowledge the synthetic qualification boundary")
	flag.Parse()
	profile, e := trust.FromEnv()
	if !*qualification || e != nil || profile != trust.Qualification || os.Getenv("APP_ENV") != "development" {
		log.Fatal("synthetic qualification acknowledgement required; no production mode")
	}
	origin, e := canonicalOrigin(*originValue)
	if e != nil {
		log.Fatal(e)
	}
	cfg, e := trust.Load(profile, trust.Workspace)
	if e != nil {
		log.Fatal("frontend TLS identity unavailable")
	}
	tlsConfig, e := cfg.ServerTLS(false)
	if e != nil || len(tlsConfig.Certificates) != 1 || tlsConfig.Certificates[0].Leaf.VerifyHostname(origin.Hostname()) != nil {
		log.Fatal("frontend certificate does not match canonical public origin")
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, ResponseHeaderTimeout: 30 * time.Second, IdleConnTimeout: 30 * time.Second, MaxIdleConns: 10}
	frontend := handler(origin, transport)
	guarded := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.CheckOwn() != nil {
			http.Error(w, "frontend identity unavailable", 503)
			return
		}
		frontend.ServeHTTP(w, r)
	})
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if e = trust.ServeHTTP(ctx, *listen, guarded, cfg, false); e != nil {
		log.Fatal("qualification frontend stopped")
	}
}
