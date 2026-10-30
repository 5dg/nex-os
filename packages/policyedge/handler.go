// Package policyedge limits access to the local policy engine. Authentication
// and TLS termination must wrap Handler; this handler alone is not a boundary.
package policyedge

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"time"
)

const maxRequest = 128 * 1024
const maxResponse = 256 * 1024

// Bounded limits concurrent buffered policy requests for every deployment of
// Handler, including the synthetic qualification edge.
func Bounded(next http.Handler) http.Handler {
	admission := make(chan struct{}, 32)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case admission <- struct{}{}:
			defer func() { <-admission }()
			next.ServeHTTP(w, r)
		default:
			http.Error(w, "policy edge capacity unavailable", http.StatusServiceUnavailable)
		}
	})
}

// LoopbackTransport never consults proxy environment and dials only the OPA
// port in the current network namespace, even if a request URL is tampered with.
func LoopbackTransport() *http.Transport {
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "127.0.0.1:8182" {
				return nil, errors.New("policy upstream must be task loopback")
			}
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", "127.0.0.1:8182")
		},
		ResponseHeaderTimeout:  3 * time.Second,
		MaxResponseHeaderBytes: 16 * 1024,
		IdleConnTimeout:        10 * time.Second,
		MaxConnsPerHost:        16,
		DisableCompression:     true,
	}
}

// Handler forwards only the pinned-policy source and decision APIs, buffering
// and limiting both directions before any response is delivered. verify is
// invoked before and after the upstream call to prevent stale peer credentials
// from receiving a decision after an awaited response.
func Handler(transport http.RoundTripper, verify func(*http.Request) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if verify == nil || verify(r) != nil {
			http.Error(w, "service identity required", http.StatusForbidden)
			return
		}
		permitted := r.Method == http.MethodGet && r.URL.Path == "/v1/policies" || r.Method == http.MethodPost && r.URL.Path == "/v1/data/nex/authz/decision"
		if !permitted || r.URL.RawQuery != "" || r.URL.RawPath != "" || r.URL.IsAbs() || r.URL.Fragment != "" {
			http.Error(w, "policy endpoint denied", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost {
			mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || mediaType != "application/json" {
				http.Error(w, "JSON decision input required", http.StatusUnsupportedMediaType)
				return
			}
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxRequest+1))
		if err != nil || len(body) > maxRequest {
			http.Error(w, "policy request too large or unreadable", http.StatusRequestEntityTooLarge)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		out := &http.Request{Method: r.Method, URL: &url.URL{Scheme: "http", Host: "127.0.0.1:8182", Path: r.URL.Path}, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Host: "127.0.0.1:8182"}
		out = out.WithContext(ctx)
		if r.Method == http.MethodPost {
			out.Header.Set("Content-Type", "application/json")
		}
		if verify(r) != nil {
			http.Error(w, "service identity required", http.StatusForbidden)
			return
		}
		response, err := transport.RoundTrip(out)
		if err != nil {
			http.Error(w, "policy dependency unavailable", http.StatusServiceUnavailable)
			return
		}
		defer response.Body.Close()
		result, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
		if err != nil || len(result) > maxResponse || verify(r) != nil {
			http.Error(w, "policy dependency unavailable", http.StatusServiceUnavailable)
			return
		}
		// Pass only content type, not engine headers, redirects, cookies or policy metadata.
		if contentType := response.Header.Get("Content-Type"); contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(response.StatusCode)
		_, _ = w.Write(result)
	})
}
