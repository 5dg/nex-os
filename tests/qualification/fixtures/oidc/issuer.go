// Package oidc implements a bounded HTTPS OIDC fixture for synthetic qualification
// tests. It is not a production identity provider, lifecycle or MFA service.
package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type User struct{ Username, Subject, Password string }
type Config struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	APIAudience  string
	AccessScope  string
	RedirectURIs []string
	Users        []User
	TokenTTL     time.Duration
}
type signingKey struct {
	id  string
	key *rsa.PrivateKey
}
type transaction struct {
	client, redirect, scope, state, nonce, challenge, csrf, subject string
	expires                                                         time.Time
}
type Issuer struct {
	config    Config
	mu        sync.Mutex
	keys      map[string]*rsa.PrivateKey
	active    signingKey
	redirects map[string]bool
	users     map[string]User
	pending   map[string]transaction
	codes     map[string]transaction
}

func New(config Config) (*Issuer, error) {
	u, e := url.Parse(config.IssuerURL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("fixture issuer requires an HTTPS origin")
	}
	config.IssuerURL = strings.TrimSuffix(config.IssuerURL, "/")
	if config.ClientID == "" || config.APIAudience == "" || config.ClientID == config.APIAudience || len(config.ClientSecret) < 32 || config.AccessScope == "" || strings.ContainsAny(config.AccessScope, " \t\r\n") {
		return nil, errors.New("distinct client/API identity, scoped access and confidential client secret required")
	}
	if config.TokenTTL == 0 {
		config.TokenTTL = 2 * time.Minute
	}
	if config.TokenTTL < time.Second || config.TokenTTL > 5*time.Minute {
		return nil, errors.New("bounded fixture token lifetime required")
	}
	f := &Issuer{config: config, keys: map[string]*rsa.PrivateKey{}, redirects: map[string]bool{}, users: map[string]User{}, pending: map[string]transaction{}, codes: map[string]transaction{}}
	if e = f.SetRedirectURIs(config.RedirectURIs); e != nil {
		return nil, e
	}
	for _, user := range config.Users {
		if user.Username == "" || user.Subject == "" || user.Password == "" || f.users[user.Username].Username != "" {
			return nil, errors.New("unique synthetic credentials required")
		}
		f.users[user.Username] = user
	}
	if len(f.users) == 0 {
		return nil, errors.New("synthetic users required")
	}
	if e = f.RotateSigningKey(false); e != nil {
		return nil, e
	}
	return f, nil
}
func (f *Issuer) IssuerURL() string { return f.config.IssuerURL }
func (f *Issuer) SetRedirectURIs(uris []string) error {
	next := map[string]bool{}
	for _, raw := range uris {
		u, e := url.Parse(raw)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return errors.New("exact HTTPS fixture redirect required")
		}
		next[raw] = true
	}
	if len(next) == 0 {
		return errors.New("at least one exact redirect required")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.redirects = next
	return nil
}
func (f *Issuer) RotateSigningKey(retainPrevious bool) error {
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		return e
	}
	id := rand.Text()
	f.mu.Lock()
	defer f.mu.Unlock()
	if !retainPrevious {
		f.keys = map[string]*rsa.PrivateKey{}
	}
	f.keys[id] = key
	f.active = signingKey{id, key}
	return nil
}

// SignToken is a Go-only test hook for invalid claim/type/key cases. It has no
// HTTP equivalent and must never be exposed as a persona token endpoint.
func (f *Issuer) SignToken(header, claims map[string]any, unpublishedKey bool) (string, error) {
	f.mu.Lock()
	key := f.active
	f.mu.Unlock()
	if unpublishedKey {
		var e error
		key.key, e = rsa.GenerateKey(rand.Reader, 2048)
		if e != nil {
			return "", e
		}
		key.id = rand.Text()
	}
	h := map[string]any{"alg": "RS256", "kid": key.id, "typ": "at+jwt"}
	for k, v := range header {
		h[k] = v
	}
	rawHeader, e := json.Marshal(h)
	if e != nil {
		return "", e
	}
	rawClaims, e := json.Marshal(claims)
	if e != nil {
		return "", e
	}
	enc := base64.RawURLEncoding
	body := enc.EncodeToString(rawHeader) + "." + enc.EncodeToString(rawClaims)
	digest := sha256.Sum256([]byte(body))
	signature, e := rsa.SignPKCS1v15(rand.Reader, key.key, crypto.SHA256, digest[:])
	if e != nil {
		return "", e
	}
	return body + "." + enc.EncodeToString(signature), nil
}
func (f *Issuer) MintAccessToken(subject string, overrides map[string]any) (string, error) {
	now := time.Now()
	claims := map[string]any{"iss": f.config.IssuerURL, "sub": subject, "aud": f.config.APIAudience, "client_id": f.config.ClientID, "scope": f.config.AccessScope, "iat": now.Unix(), "exp": now.Add(f.config.TokenTTL).Unix(), "jti": rand.Text()}
	for k, v := range overrides {
		claims[k] = v
	}
	return f.SignToken(nil, claims, false)
}
func (f *Issuer) MintIDToken(subject, nonce string, overrides map[string]any) (string, error) {
	now := time.Now()
	claims := map[string]any{"iss": f.config.IssuerURL, "sub": subject, "aud": f.config.ClientID, "nonce": nonce, "iat": now.Unix(), "auth_time": now.Unix(), "exp": now.Add(f.config.TokenTTL).Unix()}
	for k, v := range overrides {
		claims[k] = v
	}
	return f.SignToken(map[string]any{"typ": "JWT"}, claims, false)
}
func (f *Issuer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("GET /jwks", f.jwks)
	mux.HandleFunc("GET /authorize", f.authorize)
	mux.HandleFunc("GET /login", f.loginPage)
	mux.HandleFunc("POST /login", f.login)
	mux.HandleFunc("POST /token", f.token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.TLS == nil {
			http.Error(w, "fixture requires HTTPS", http.StatusBadRequest)
			return
		}
		mux.ServeHTTP(w, r)
	})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}
func oauthError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}
func (f *Issuer) discovery(w http.ResponseWriter, r *http.Request) {
	base := f.config.IssuerURL
	writeJSON(w, 200, map[string]any{"issuer": base, "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token", "jwks_uri": base + "/jwks", "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic"}, "code_challenge_methods_supported": []string{"S256"}, "scopes_supported": []string{"openid", "profile", f.config.AccessScope}, "authorization_response_iss_parameter_supported": true})
}
func (f *Issuer) jwks(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	ids := make([]string, 0, len(f.keys))
	for id := range f.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	keys := []any{}
	for _, id := range ids {
		key := f.keys[id]
		enc := base64.RawURLEncoding
		keys = append(keys, map[string]any{"kty": "RSA", "kid": id, "use": "sig", "alg": "RS256", "n": enc.EncodeToString(key.N.Bytes()), "e": enc.EncodeToString(big.NewInt(int64(key.E)).Bytes())})
	}
	f.mu.Unlock()
	writeJSON(w, 200, map[string]any{"keys": keys})
}
func (f *Issuer) prune(now time.Time) {
	for id, txn := range f.pending {
		if !now.Before(txn.expires) {
			delete(f.pending, id)
		}
	}
	for id, txn := range f.codes {
		if !now.Before(txn.expires) {
			delete(f.codes, id)
		}
	}
}
func (f *Issuer) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	client, redirect, scope, state, nonce, challenge := q.Get("client_id"), q.Get("redirect_uri"), q.Get("scope"), q.Get("state"), q.Get("nonce"), q.Get("code_challenge")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prune(time.Now())
	if client != f.config.ClientID || !f.redirects[redirect] || q.Get("response_type") != "code" || state == "" || nonce == "" || q.Get("code_challenge_method") != "S256" {
		oauthError(w, 400, "invalid_request")
		return
	}
	decoded, e := base64.RawURLEncoding.DecodeString(challenge)
	if e != nil || len(decoded) != 32 {
		oauthError(w, 400, "invalid_request")
		return
	}
	requested := map[string]bool{}
	for _, item := range strings.Fields(scope) {
		if item != "openid" && item != "profile" && item != f.config.AccessScope {
			oauthError(w, 400, "invalid_scope")
			return
		}
		requested[item] = true
	}
	if !requested["openid"] || !requested[f.config.AccessScope] {
		oauthError(w, 400, "invalid_scope")
		return
	}
	if len(f.pending) >= 128 || len(f.codes) >= 128 {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	id := rand.Text()
	f.pending[id] = transaction{client: client, redirect: redirect, scope: scope, state: state, nonce: nonce, challenge: challenge, csrf: rand.Text(), expires: time.Now().Add(2 * time.Minute)}
	http.SetCookie(w, &http.Cookie{Name: "__Host-nex_fixture_login", Value: id, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 120})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

var loginTemplate = template.Must(template.New("login").Parse(`<!doctype html><html><body><h1>Synthetic qualification identity fixture</h1><p>No customer identity or MFA is provided.</p><form method="post" action="/login"><input type="hidden" name="csrf" value="{{.}}"><label>Username<input name="username" autocomplete="username"></label><label>Password<input type="password" name="password" autocomplete="current-password"></label><button>Sign in</button></form></body></html>`))

func (f *Issuer) pendingFor(r *http.Request) (string, transaction, bool) {
	cookie, e := r.Cookie("__Host-nex_fixture_login")
	if e != nil {
		return "", transaction{}, false
	}
	txn, ok := f.pending[cookie.Value]
	return cookie.Value, txn, ok && time.Now().Before(txn.expires)
}
func (f *Issuer) loginPage(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, txn, ok := f.pendingFor(r)
	if !ok {
		http.Error(w, "authorization transaction required", 400)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	loginTemplate.Execute(w, txn.csrf)
}
func (f *Issuer) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if e := r.ParseForm(); e != nil {
		oauthError(w, 400, "invalid_request")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	id, txn, ok := f.pendingFor(r)
	if !ok || subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(txn.csrf)) != 1 {
		oauthError(w, 400, "invalid_request")
		return
	}
	user, ok := f.users[r.PostForm.Get("username")]
	if !ok || subtle.ConstantTimeCompare([]byte(r.PostForm.Get("password")), []byte(user.Password)) != 1 {
		oauthError(w, 401, "access_denied")
		return
	}
	delete(f.pending, id)
	txn.subject = user.Subject
	txn.expires = time.Now().Add(time.Minute)
	code := rand.Text()
	f.codes[code] = txn
	http.SetCookie(w, &http.Cookie{Name: "__Host-nex_fixture_login", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	redirect, _ := url.Parse(txn.redirect)
	q := redirect.Query()
	q.Set("code", code)
	q.Set("iss", f.config.IssuerURL)
	q.Set("state", txn.state)
	redirect.RawQuery = q.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusSeeOther)
}
func verifierValid(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for _, r := range v {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("-._~", r)) {
			return false
		}
	}
	return true
}
func (f *Issuer) token(w http.ResponseWriter, r *http.Request) {
	client, secret, ok := r.BasicAuth()
	if ok {
		var e error
		client, e = url.QueryUnescape(client)
		if e != nil {
			ok = false
		}
		secret, e = url.QueryUnescape(secret)
		if e != nil {
			ok = false
		}
	}
	if !ok || client != f.config.ClientID || subtle.ConstantTimeCompare([]byte(secret), []byte(f.config.ClientSecret)) != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="qualification"`)
		oauthError(w, 401, "invalid_client")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if e := r.ParseForm(); e != nil {
		oauthError(w, 400, "invalid_request")
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		oauthError(w, 400, "unsupported_grant_type")
		return
	}
	f.mu.Lock()
	f.prune(time.Now())
	txn, ok := f.codes[r.PostForm.Get("code")]
	verifier := r.PostForm.Get("code_verifier")
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if !ok || txn.client != client || txn.redirect != r.PostForm.Get("redirect_uri") || !verifierValid(verifier) || subtle.ConstantTimeCompare([]byte(challenge), []byte(txn.challenge)) != 1 {
		f.mu.Unlock()
		oauthError(w, 400, "invalid_grant")
		return
	}
	delete(f.codes, r.PostForm.Get("code"))
	f.mu.Unlock()
	access, e := f.MintAccessToken(txn.subject, nil)
	if e != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	id, e := f.MintIDToken(txn.subject, txn.nonce, nil)
	if e != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"access_token": access, "id_token": id, "token_type": "Bearer", "expires_in": int(f.config.TokenTTL.Seconds()), "scope": f.config.AccessScope})
}
