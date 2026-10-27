package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"time"
)

type ReadinessRequest struct {
	Nonce string `json:"nonce"`
}
type ReadinessResponse struct {
	Nonce   string `json:"nonce"`
	Profile string `json:"profile"`
	Ready   bool   `json:"ready"`
}

func ValidNonce(value string) bool {
	b, e := hex.DecodeString(value)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == value
}

// Readiness proves an authenticated receiver accepted its configured body-scope
// key and verified dependencies. It neither authorizes nor runs an operation.
func (c *Client) Readiness(ctx context.Context, profile string) error {
	if c == nil || c.HTTP == nil || len(c.Key) != 32 || profile != "synthetic-qualification" {
		return errors.New("receiver readiness configuration required")
	}
	u, e := url.Parse(c.URL)
	if e != nil || u.Host == "" || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("invalid receiver endpoint")
	}
	scoped := *c
	switch c.Audience {
	case "model.execute":
		scoped.Audience = "model.ready"
	case "export.execute":
		scoped.Audience = "export.ready"
	default:
		return errors.New("receiver execute client required")
	}
	u.Path = "/readyz"
	u.RawPath = ""
	scoped.URL = u.String()
	nonce := make([]byte, 32)
	if _, e = rand.Read(nonce); e != nil {
		return errors.New("receiver readiness nonce unavailable")
	}
	in := ReadinessRequest{Nonce: hex.EncodeToString(nonce)}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var out ReadinessResponse
	if e = scoped.Call(ctx, in, &out); e != nil {
		return errors.New("receiver credential or dependency readiness failed")
	}
	if !out.Ready || out.Nonce != in.Nonce || out.Profile != profile {
		return errors.New("receiver readiness identity/profile mismatch")
	}
	return nil
}
