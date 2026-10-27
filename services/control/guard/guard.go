package guard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/5dg/nex-os/packages/contracts"
	"github.com/5dg/nex-os/packages/trust"
	"github.com/5dg/nex-os/policies"
	"io"
	"net/http"
	"time"
)

type Actor struct {
	ID          string   `json:"id"`
	TenantID    string   `json:"tenant_id"`
	Permissions []string `json:"permissions"`
}
type Resource struct {
	TenantID                string   `json:"tenant_id"`
	Kind                    string   `json:"kind"`
	Classification          string   `json:"classification"`
	ReaderIDs               []string `json:"reader_ids"`
	ApprovedClassifications []string `json:"approved_classifications"`
}
type Input struct {
	Actor                 Actor    `json:"actor"`
	Resource              Resource `json:"resource"`
	Action                string   `json:"action"`
	DelegationValid       bool     `json:"delegation_valid"`
	DelegationPermissions []string `json:"delegation_permissions"`
	DataClassification    string   `json:"data_classification"`
}

type Client struct {
	URL  string
	HTTP *http.Client
	RPC  *RPC
}

// New is retained for direct OPA contract tests. Runtime uses NewRPC exclusively.
func New(url string) *Client { return &Client{URL: url, HTTP: &http.Client{Timeout: 3 * time.Second}} }
func Digest() string         { return fmt.Sprintf("sha256:%x", sha256.Sum256(policies.Source)) }

func (c *Client) Health(ctx context.Context) error {
	if c.RPC != nil && c.RPC.trust != nil && c.RPC.trust.Profile == trust.Qualification {
		return c.Readiness(ctx)
	}
	d, err := c.Evaluate(ctx, Input{Actor: Actor{Permissions: []string{}}, Resource: Resource{ReaderIDs: []string{}}, DelegationPermissions: []string{}})
	if err != nil {
		return err
	}
	if d.Effect != "deny" {
		return errors.New("default-deny readiness check failed")
	}
	return nil
}

// Verify the policy loaded by OPA matches the source whose digest we record.
// OPA's administrative API must remain inaccessible to untrusted workers.
func (c *Client) Evaluate(ctx context.Context, in Input) (contracts.Decision, error) {
	if c.RPC != nil {
		return c.RPC.evaluate(ctx, in)
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", c.URL+"/v1/policies", nil)
	r, err := c.HTTP.Do(req)
	if err != nil {
		return contracts.Decision{}, err
	}
	var module struct {
		Result []struct {
			Raw string `json:"raw"`
		} `json:"result"`
	}
	err = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&module)
	r.Body.Close()
	if err != nil || r.StatusCode != 200 || len(module.Result) != 1 || !bytes.Equal([]byte(module.Result[0].Raw), policies.Source) {
		return contracts.Decision{}, errors.New("policy source mismatch")
	}
	b, _ := json.Marshal(map[string]any{"input": in})
	req, _ = http.NewRequestWithContext(ctx, "POST", c.URL+"/v1/data/nex/authz/decision", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	r, err = c.HTTP.Do(req)
	if err != nil {
		return contracts.Decision{}, err
	}
	defer r.Body.Close()
	var out struct {
		Result *struct {
			Effect  string `json:"effect"`
			Reason  string `json:"reason_code"`
			Version string `json:"policy_version"`
		} `json:"result"`
	}
	if r.StatusCode != 200 {
		return contracts.Decision{}, errors.New("policy evaluation failed")
	}
	if err = json.NewDecoder(io.LimitReader(r.Body, 65536)).Decode(&out); err != nil {
		return contracts.Decision{}, err
	}
	if out.Result == nil || out.Result.Version != "alpha-guard-v1" || out.Result.Reason == "" {
		return contracts.Decision{}, errors.New("invalid policy decision")
	}
	switch out.Result.Effect {
	case "allow", "deny", "require_approval":
	default:
		return contracts.Decision{}, errors.New("invalid policy effect")
	}
	return contracts.Decision{Effect: out.Result.Effect, Reason: out.Result.Reason, PolicyVersion: out.Result.Version, PolicyDigest: Digest()}, nil
}
