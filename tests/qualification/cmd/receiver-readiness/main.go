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
	"net/url"
	"os"
	"strings"
	"time"
)

type result struct {
	Profile                  string          `json:"profile"`
	Checks                   map[string]bool `json:"checks"`
	OperationEndpointsCalled bool            `json:"operation_endpoints_called"`
}

func run(ctx context.Context) (result, error) {
	out := result{Profile: string(trust.Qualification), Checks: map[string]bool{}, OperationEndpointsCalled: false}
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
		out.Checks[receiver.name+"_wrong_key_denied"] = wrong.Readiness(ctx, string(profile)) != nil
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
			denied := scoped.Call(probeCtx, broker.ReadinessRequest{Nonce: hex.EncodeToString(nonce)}, &proof) != nil
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
		out.Checks[receiver.name+"_invalid_nonce_denied"] = malformed.Call(probeCtx, broker.ReadinessRequest{Nonce: "not-a-canonical-nonce"}, &proof) != nil
		cancel()
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
