// Command receiver-readiness exercises actual receiver authentication from the
// control network namespace. It is a qualification fixture, never a product
// endpoint or a way to execute jobs. E owns the Docker invocation and F reviews
// the live results and independent receipt/journal/database snapshots.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/trust"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type result struct {
	Profile                  string          `json:"profile"`
	Checks                   map[string]bool `json:"checks"`
	OperationEndpointsCalled bool            `json:"operation_endpoints_called"`
	HTTPRequests             map[string]int  `json:"http_requests"`
}

type readyTransport struct {
	next               http.RoundTripper
	name               string
	status             atomic.Int32
	mu                 sync.Mutex
	requests           map[string]int
	operationAttempted bool
}

func (t *readyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.status.Store(0)
	t.mu.Lock()
	t.requests[t.name+" "+r.Method+" "+r.URL.EscapedPath()]++
	if r.Method != "POST" || r.URL.Path != "/readyz" || r.URL.RawPath != "" || r.URL.RawQuery != "" {
		t.operationAttempted = true
		t.mu.Unlock()
		return nil, errors.New("probe may only request receiver readiness")
	}
	t.mu.Unlock()
	response, e := t.next.RoundTrip(r)
	if response != nil {
		t.status.Store(int32(response.StatusCode))
	}
	return response, e
}
func (t *readyTransport) copyResults(out *result) {
	t.mu.Lock()
	defer t.mu.Unlock()
	out.OperationEndpointsCalled = out.OperationEndpointsCalled || t.operationAttempted
	for path, count := range t.requests {
		out.HTTPRequests[path] = count
	}
}
func run(ctx context.Context) (result, error) {
	out := result{Profile: string(trust.Qualification), Checks: map[string]bool{}, OperationEndpointsCalled: false, HTTPRequests: map[string]int{}}
	profile, e := trust.FromEnv()
	if e != nil || profile != trust.Qualification || os.Getenv("APP_ENV") != "development" {
		return out, errors.New("qualification profile and development environment required")
	}
	cfg, e := trust.Load(profile, trust.Control)
	if e != nil {
		return out, errors.New("valid control qualification identity required")
	}
	for _, receiver := range []struct {
		name, urlVar, keyVar string
		role                 trust.Role
	}{{"model", "MODEL_URL", "MODEL_KEY_FILE", trust.Model}, {"export", "EXPORT_URL", "EXPORT_KEY_FILE", trust.Export}} {
		base := strings.TrimRight(os.Getenv(receiver.urlVar), "/")
		if cfg.CheckURL(base) != nil {
			return out, fmt.Errorf("%s endpoint configuration invalid", receiver.name)
		}
		key, e := broker.Key(os.Getenv(receiver.keyVar))
		if e != nil {
			return out, fmt.Errorf("%s credential configuration invalid", receiver.name)
		}
		httpClient, e := cfg.HTTPClient(receiver.role, 10*time.Second)
		if e != nil {
			return out, errors.New("qualified receiver client unavailable")
		}
		audit := &readyTransport{next: httpClient.Transport, name: receiver.name, requests: map[string]int{}}
		httpClient.Transport = audit
		client := broker.NewClient(base+"/execute", receiver.name+".execute", key)
		client.HTTP = httpClient
		positive := client.Readiness(ctx, string(profile)) == nil
		out.Checks[receiver.name+"_positive"] = positive
		if !positive {
			return out, fmt.Errorf("%s correct-identity readiness failed", receiver.name)
		}
		wrong := *client
		wrong.Key = append([]byte(nil), key...)
		wrong.Key[0] ^= 1
		wrongError := wrong.Readiness(ctx, string(profile))
		out.Checks[receiver.name+"_wrong_key_denied"] = wrongError != nil && audit.status.Load() == 401
		nonce := make([]byte, 32)
		if _, e = rand.Read(nonce); e != nil {
			return out, errors.New("qualification nonce unavailable")
		}
		parsed, e := url.Parse(client.URL)
		if e != nil {
			return out, errors.New("invalid fixed receiver URL")
		}
		parsed.Path = "/readyz"
		parsed.RawPath = ""
		for _, audience := range []string{receiver.name + ".execute", receiver.name + ".status"} {
			scoped := *client
			scoped.URL = parsed.String()
			scoped.Audience = audience
			probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
			var proof broker.ReadinessResponse
			denied := scoped.Call(probeCtx, broker.ReadinessRequest{Nonce: hex.EncodeToString(nonce)}, &proof) != nil && audit.status.Load() == 401
			cancel()
			suffix := "execute"
			if strings.HasSuffix(audience, ".status") {
				suffix = "status"
			}
			out.Checks[receiver.name+"_"+suffix+"_scope_denied"] = denied
		}
		malformed := *client
		malformed.URL = parsed.String()
		malformed.Audience = receiver.name + ".ready"
		probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		var proof broker.ReadinessResponse
		out.Checks[receiver.name+"_invalid_nonce_denied"] = malformed.Call(probeCtx, broker.ReadinessRequest{Nonce: "not-a-canonical-nonce"}, &proof) != nil && audit.status.Load() == 400
		cancel()
		out.Checks[receiver.name+"_healthy_after_negatives"] = client.Readiness(ctx, string(profile)) == nil && audit.status.Load() == 200
		audit.copyResults(&out)
		if out.OperationEndpointsCalled {
			return out, errors.New("probe attempted non-readiness path")
		}
		for name, passed := range out.Checks {
			if !passed {
				return out, fmt.Errorf("qualification check failed: %s", name)
			}
		}
	}
	return out, nil
}
func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, e := run(ctx)
	if e != nil {
		_ = json.NewEncoder(os.Stdout).Encode(out)
		fmt.Fprintln(os.Stderr, e.Error())
		os.Exit(1)
	}
	if e = json.NewEncoder(os.Stdout).Encode(out); e != nil {
		os.Exit(1)
	}
}
