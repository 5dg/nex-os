package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const MaxBearerBytes = 8192
const maxIssuerResponseBytes = 128 * 1024

type Identity struct{ Issuer, Subject string }
type Verifier struct {
	verifier      *oidc.IDTokenVerifier
	issuer        string
	audience      string
	clientID      string
	scope         string
	accessProfile bool
}

// New is the explicitly synthetic development verifier. Qualification callers
// must use NewAccessTokenVerifier; an ID token is not an API access credential.
func New(ctx context.Context, issuer, audience string) (*Verifier, error) {
	return newVerifier(ctx, issuer, audience, "", "", false)
}

// NewAccessTokenVerifier implements the single documented JWT access-token
// profile. Tenant membership and permissions are deliberately not returned from
// claims: the control API resolves those facts from its current database.
func NewAccessTokenVerifier(ctx context.Context, issuer, audience, clientID, requiredScope string) (*Verifier, error) {
	u, e := url.Parse(issuer)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || audience == "" || clientID == "" || !validScope(requiredScope) || strings.Contains(requiredScope, " ") {
		return nil, errors.New("valid explicit HTTPS access-token profile required")
	}
	return newVerifier(ctx, issuer, audience, clientID, requiredScope, true)
}

func newVerifier(ctx context.Context, issuer, audience, clientID, scope string, access bool) (*Verifier, error) {
	client := http.DefaultClient
	if configured, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok && configured != nil {
		client = configured
	}
	bounded := *client
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	bounded.Transport = boundedTransport{transport}
	if bounded.Timeout <= 0 || bounded.Timeout > 5*time.Second {
		bounded.Timeout = 5 * time.Second
	}
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("OIDC redirects are not permitted") }
	ctx = oidc.ClientContext(ctx, &bounded)
	p, e := oidc.NewProvider(ctx, issuer)
	if e != nil {
		return nil, e
	}
	if access {
		var metadata struct {
			JWKS string `json:"jwks_uri"`
		}
		if e = p.Claims(&metadata); e != nil {
			return nil, e
		}
		keys, e := url.Parse(metadata.JWKS)
		authority, _ := url.Parse(issuer)
		if e != nil || keys.Scheme != "https" || keys.Host != authority.Host || keys.User != nil || keys.RawQuery != "" || keys.Fragment != "" {
			return nil, errors.New("issuer JWKS must use its declared HTTPS origin")
		}
	}
	return &Verifier{verifier: p.Verifier(&oidc.Config{ClientID: audience, SupportedSigningAlgs: []string{"RS256"}}), issuer: issuer, audience: audience, clientID: clientID, scope: scope, accessProfile: access}, nil
}

func (v *Verifier) Verify(r *http.Request) (Identity, error) {
	unauthorized := func() (Identity, error) { return Identity{}, errors.New("valid API bearer credential required") }
	if len(r.Header.Values("Authorization")) != 1 {
		return unauthorized()
	}
	value := r.Header.Get("Authorization")
	if len(value) > MaxBearerBytes+7 {
		return unauthorized()
	}
	parts := strings.Fields(value)
	if len(parts) != 2 || parts[0] != "Bearer" || len(parts[1]) > MaxBearerBytes {
		return unauthorized()
	}
	if v.accessProfile {
		jwt := strings.Split(parts[1], ".")
		if len(jwt) != 3 || len(jwt[0]) > 2048 {
			return unauthorized()
		}
		header, e := base64.RawURLEncoding.DecodeString(jwt[0])
		if e != nil {
			return unauthorized()
		}
		var h struct {
			Typ  string   `json:"typ"`
			Alg  string   `json:"alg"`
			Kid  string   `json:"kid"`
			Crit []string `json:"crit"`
		}
		if json.Unmarshal(header, &h) != nil || h.Typ != "at+jwt" || h.Alg != "RS256" || h.Kid == "" || len(h.Kid) > 128 || len(h.Crit) != 0 {
			return unauthorized()
		}
	}
	token, e := v.verifier.Verify(r.Context(), parts[1])
	if e != nil {
		return unauthorized()
	}
	if token.Subject == "" || len(token.Subject) > 256 || strings.TrimSpace(token.Subject) != token.Subject || (v.accessProfile && !validSubject(token.Subject)) {
		return unauthorized()
	}
	if v.accessProfile {
		if token.Issuer != v.issuer || len(token.Audience) != 1 || token.Audience[0] != v.audience {
			return unauthorized()
		}
		var raw map[string]json.RawMessage
		if token.Claims(&raw) != nil {
			return unauthorized()
		}
		number := func(name string) (int64, bool) {
			b, ok := raw[name]
			if !ok {
				return 0, false
			}
			n, e := strconv.ParseInt(string(b), 10, 64)
			return n, e == nil
		}
		exp, okExp := number("exp")
		iat, okIat := number("iat")
		now := time.Now().Unix()
		if !okExp || !okIat || iat <= 0 || exp <= now || exp <= iat || exp-iat > 900 || iat > now+30 {
			return unauthorized()
		}
		if _, present := raw["nbf"]; present {
			nbf, ok := number("nbf")
			if !ok || nbf > now+30 || nbf >= exp {
				return unauthorized()
			}
		}
		var clientID, scope string
		if json.Unmarshal(raw["client_id"], &clientID) != nil || clientID != v.clientID || json.Unmarshal(raw["scope"], &scope) != nil || !validScope(scope) {
			return unauthorized()
		}
		permitted := false
		for _, word := range strings.Split(scope, " ") {
			if word == v.scope {
				permitted = true
			}
		}
		if !permitted {
			return unauthorized()
		}
	}
	return Identity{Issuer: v.issuer, Subject: token.Subject}, nil
}

// OIDC subjects are at most 255 ASCII characters. Require visible characters
// so the same identity cannot carry control or whitespace into authorization,
// logs, or the workspace's more restrictive identity policy.
func validSubject(subject string) bool {
	if len(subject) == 0 || len(subject) > 255 {
		return false
	}
	for _, c := range subject {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

func validScope(scope string) bool {
	if scope == "" || len(scope) > 1024 || strings.HasPrefix(scope, " ") || strings.HasSuffix(scope, " ") || strings.Contains(scope, "  ") {
		return false
	}
	for _, c := range scope {
		if c == ' ' {
			continue
		}
		if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

type boundedTransport struct{ http.RoundTripper }

func (t boundedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, e := t.RoundTripper.RoundTrip(r)
	if e != nil {
		return nil, e
	}
	if response.ContentLength > maxIssuerResponseBytes {
		response.Body.Close()
		return nil, errors.New("issuer response exceeds limit")
	}
	response.Body = &boundedBody{source: response.Body, remaining: maxIssuerResponseBytes}
	return response, nil
}

type boundedBody struct {
	source    io.ReadCloser
	remaining int
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if len(p) > b.remaining+1 {
		p = p[:b.remaining+1]
	}
	n, e := b.source.Read(p)
	b.remaining -= n
	if b.remaining < 0 {
		return n, errors.New("issuer response exceeds limit")
	}
	return n, e
}
func (b *boundedBody) Close() error { return b.source.Close() }
