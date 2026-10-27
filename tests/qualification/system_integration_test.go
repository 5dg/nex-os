//go:build integration

package qualification_test

// This suite consumes E's isolated qualification stack. It never starts Docker,
// changes SQL, fabricates a completed review, or invokes a cloud provider.
import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/5dg/nex-os/packages/contracts"
	"github.com/5dg/nex-os/packages/evidence"
)

type systemBrowser struct {
	t                              *testing.T
	client                         *http.Client
	origin, issuer, csrf, callback string
	sessionCookie                  bool
}

type observedTransport struct {
	base    http.RoundTripper
	observe func(*http.Response)
}

func (o observedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	p, e := o.base.RoundTrip(r)
	if e == nil {
		o.observe(p)
	}
	return p, e
}

func systemClient(t *testing.T, identity string) *http.Client {
	t.Helper()
	state := os.Getenv("NEX_QUAL_STATE_DIR")
	if !filepath.IsAbs(state) {
		t.Fatal("NEX_QUAL_STATE_DIR must name E's existing absolute isolated qualification state")
	}
	ca, e := os.ReadFile(filepath.Join(state, "current-pki", "ca.crt"))
	if e != nil {
		t.Fatal("qualification CA unavailable")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("invalid qualification CA")
	}
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	if identity != "" {
		cert, e := tls.LoadX509KeyPair(filepath.Join(state, "current-pki", identity, "tls.crt"), filepath.Join(state, "current-pki", identity, "tls.key"))
		if e != nil {
			t.Fatal("qualification workload identity unavailable")
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	dial := &net.Dialer{Timeout: 3 * time.Second}
	tr := &http.Transport{TLSClientConfig: cfg, TLSHandshakeTimeout: 3 * time.Second, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		switch host {
		case "workspace.nex.test", "issuer.nex.test", "control", "opa", "guard":
		default:
			return nil, fmt.Errorf("qualification harness refuses undeclared host")
		}
		return dial.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
	}}
	t.Cleanup(tr.CloseIdleConnections)
	jar, _ := cookiejar.New(nil)
	return &http.Client{Transport: tr, Jar: jar, Timeout: 20 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		// Model a browser navigation after the fixture's credential-form 303.
		// Go otherwise copies the POST Origin onto the redirected GET callback.
		if r.Method == http.MethodGet {
			r.Header.Del("Origin")
		}
		if len(via) > 10 {
			return fmt.Errorf("too many qualification redirects")
		}
		if r.URL.Scheme != "https" || (r.URL.Hostname() != "workspace.nex.test" && r.URL.Hostname() != "issuer.nex.test") {
			return fmt.Errorf("unapproved qualification redirect")
		}
		return nil
	}}
}

func newSystemBrowser(t *testing.T) *systemBrowser {
	b := &systemBrowser{t: t, client: systemClient(t, ""), origin: "https://workspace.nex.test:9443", issuer: "https://issuer.nex.test:9444"}
	b.client.Transport = observedTransport{base: b.client.Transport, observe: func(r *http.Response) {
		for _, c := range r.Cookies() {
			if c.Name == "__Host-nex_session" && c.MaxAge >= 0 {
				if !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" || c.SameSite != http.SameSiteLaxMode {
					t.Error("session cookie lacks required security attributes")
				}
				b.sessionCookie = true
			}
		}
	}}
	baseRedirect := b.client.CheckRedirect
	b.client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if r.URL.Host == "workspace.nex.test:9443" && r.URL.Path == "/auth/callback" {
			b.callback = r.URL.String()
		}
		return baseRedirect(r, via)
	}
	return b
}

func (b *systemBrowser) request(method, path string, body any, origin, csrf string) (int, []byte) {
	b.t.Helper()
	var data io.Reader
	if body != nil {
		encoded, e := json.Marshal(body)
		if e != nil {
			b.t.Fatal(e)
		}
		data = bytes.NewReader(encoded)
	}
	req, e := http.NewRequest(method, b.origin+path, data)
	if e != nil {
		b.t.Fatal("invalid harness request")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if csrf != "" {
		req.Header.Set("X-Nex-CSRF", csrf)
	}
	r, e := b.client.Do(req)
	if e != nil {
		b.t.Fatalf("qualification %s %s transport failed", method, path)
	}
	defer r.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if e != nil {
		b.t.Fatal("qualification response body unavailable")
	}
	return r.StatusCode, raw
}
func (b *systemBrowser) workflow(input map[string]any, status int, out any) {
	b.t.Helper()
	code, raw := b.request("POST", "/api/workflow", input, b.origin, b.csrf)
	if code != status {
		var failure struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(raw, &failure)
		b.t.Fatalf("workflow %v: status %d want %d (code %s)", input["operation"], code, status, failure.Code)
	}
	if out != nil && json.Unmarshal(raw, out) != nil {
		b.t.Fatal("workflow response is not expected JSON")
	}
}
func (b *systemBrowser) login(subject string) {
	b.t.Helper()
	r, e := b.client.Get(b.origin + "/auth/login")
	if e != nil {
		b.t.Fatal("login redirect transport failed")
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 16384))
	r.Body.Close()
	if r.StatusCode != 200 || r.Request.URL.Host != "issuer.nex.test:9444" {
		b.t.Fatalf("login did not reach synthetic credential form: %d", r.StatusCode)
	}
	match := regexp.MustCompile(`name="csrf" value="([A-Z2-7]+)"`).FindSubmatch(raw)
	if len(match) != 2 {
		b.t.Fatal("fixture credential CSRF field absent")
	}
	form := url.Values{"csrf": {string(match[1])}, "username": {subject}, "password": {"fixture-" + subject + "-password"}}
	req, _ := http.NewRequest("POST", b.issuer+"/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", b.issuer)
	r, e = b.client.Do(req)
	if e != nil {
		b.t.Fatal("credential callback transport failed")
	}
	io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
	r.Body.Close()
	if r.StatusCode != 200 || r.Request.URL.Path != "/workflow" {
		b.t.Fatalf("authenticated callback did not reach workflow: %d path %s", r.StatusCode, r.Request.URL.Path)
	}
	code, raw := b.request("GET", "/api/session", nil, "", "")
	if code != 200 {
		b.t.Fatalf("session unavailable after callback: %d", code)
	}
	var s map[string]any
	if json.Unmarshal(raw, &s) != nil || s["subject"] != subject || s["authenticated"] != true {
		b.t.Fatal("session identity differs from credential login")
	}
	for _, key := range []string{"access_token", "id_token", "refresh_token", "token"} {
		if _, exists := s[key]; exists {
			b.t.Fatal("session endpoint exposed provider token")
		}
	}
	b.csrf, _ = s["csrf_token"].(string)
	if b.csrf == "" || !b.sessionCookie || b.callback == "" {
		b.t.Fatal("authenticated session preconditions missing")
	}
}

// TestQualificationSystem proves actual browser protocol, user/workload bounds,
// and Rust-authorized review/export against the existing synthetic stack.
func TestQualificationSystem(t *testing.T) {
	alice := newSystemBrowser(t)
	if code, _ := alice.request("GET", "/api/session", nil, "", ""); code != 401 {
		t.Fatalf("anonymous session status %d", code)
	}
	for _, path := range []string{"/api/demo", "/laboratory"} {
		method := "GET"
		if path == "/api/demo" {
			method = "POST"
		}
		if code, _ := alice.request(method, path, nil, alice.origin, ""); code != 404 {
			t.Fatalf("qualification laboratory %s status %d", path, code)
		}
	}
	alice.login("alice")
	if code, _ := alice.request("POST", "/api/workflow", map[string]any{"operation": "documents"}, "", alice.csrf); code != 403 {
		t.Fatalf("missing origin status %d", code)
	}
	if code, _ := alice.request("POST", "/api/workflow", map[string]any{"operation": "documents"}, alice.origin, ""); code != 403 {
		t.Fatalf("missing CSRF status %d", code)
	}
	if code, _ := alice.request("POST", "/api/workflow", map[string]any{"operation": "documents"}, "https://untrusted.example", alice.csrf); code != 403 {
		t.Fatalf("wrong origin status %d", code)
	}
	for _, key := range []string{"subject", "tenant_id", "role", "delegation_id", "question"} {
		alice.workflow(map[string]any{"operation": "documents", key: "forged"}, 400, nil)
	}
	var docs []struct {
		ID string `json:"id"`
	}
	alice.workflow(map[string]any{"operation": "documents"}, 200, &docs)
	seen := false
	for _, d := range docs {
		if d.ID == "review-bob" {
			t.Fatal("cross-tenant document visible")
		}
		seen = seen || d.ID == "review-alice"
	}
	if !seen {
		t.Fatal("Alice synthetic review source absent")
	}
	create := func(document string) map[string]any {
		return map[string]any{"operation": "create", "document_id": document, "question_catalogue_id": "access-review-controls", "idempotency_key": fmt.Sprintf("qual-%s-%d", document, time.Now().UnixNano())}
	}
	alice.workflow(create("review-bob"), 403, nil)
	var job contracts.ReviewJob
	alice.workflow(create("review-alice"), 202, &job)
	if job.ID == "" {
		t.Fatal("created job lacks identity")
	}
	poll := func(phase string) contracts.ReviewJob {
		t.Helper()
		until := time.Now().Add(75 * time.Second)
		for time.Now().Before(until) {
			var current contracts.ReviewJob
			alice.workflow(map[string]any{"operation": "job", "id": job.ID}, 200, &current)
			if current.State == "failed" || current.State == "denied" || current.State == "unknown" {
				t.Fatalf("actual Rust workflow failed phase %s: state %s code %s", phase, current.State, current.ErrorCode)
			}
			if current.State == "completed" && ((phase == "review" && current.Answer != "") || (phase == "export" && current.ExportID != "")) {
				return current
			}
			time.Sleep(250 * time.Millisecond)
		}
		t.Fatalf("actual Rust workflow timed out in %s", phase)
		return contracts.ReviewJob{}
	}
	review := poll("review")
	if review.Provider != "development" || review.Citation != "review-alice@v1" {
		t.Fatalf("review lacks expected protected provenance provider=%s citation=%s", review.Provider, review.Citation)
	}
	var requested contracts.ApprovalView
	alice.workflow(map[string]any{"operation": "export", "id": job.ID}, 201, &requested)
	job.ApprovalID = requested.ID
	if job.ApprovalID == "" {
		t.Fatal("export request lacks approval")
	}
	carol := newSystemBrowser(t)
	carol.login("carol")
	var approvals []contracts.ApprovalView
	carol.workflow(map[string]any{"operation": "approvals"}, 200, &approvals)
	var approval contracts.ApprovalView
	for _, a := range approvals {
		if a.ID == job.ApprovalID {
			approval = a
		}
	}
	if approval.ID == "" || approval.RequestDigest == "" || approval.ExportPreview != review.Answer+"\n\nSource: review-alice@v1" {
		t.Fatal("approver lacks exact protected review/export preview")
	}
	decision := map[string]any{"operation": "decide", "id": approval.ID, "approve": true, "request_digest": approval.RequestDigest}
	alice.workflow(decision, 403, nil)
	carol.workflow(decision, 200, nil)
	finished := poll("export")
	if finished.ExportID == "" {
		t.Fatal("approved export lacks protected artifact")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{8,100}$`).MatchString(finished.ExportID) {
		t.Fatal("protected artifact ID is not a safe receipt basename")
	}
	artifact, err := os.ReadFile(filepath.Join(os.Getenv("NEX_QUAL_STATE_DIR"), "export-receipts", finished.ExportID+".state"))
	if err != nil {
		t.Fatal("durable synthetic export artifact unavailable")
	}
	var receipt struct {
		Status string `json:"state"`
		Result struct {
			ArtifactID    string `json:"artifact_id"`
			ContentDigest string `json:"content_digest"`
			Content       string `json:"content"`
		} `json:"result"`
	}
	if json.Unmarshal(artifact, &receipt) != nil {
		t.Fatal("durable export receipt malformed")
	}
	sum := sha256.Sum256([]byte(approval.ExportPreview))
	if receipt.Status != "completed" || receipt.Result.ArtifactID != finished.ExportID || receipt.Result.Content != approval.ExportPreview || receipt.Result.ContentDigest != hex.EncodeToString(sum[:]) {
		t.Fatal("durable export bytes/digest differ from exact approver preview")
	}
	var events []struct {
		evidence.Event
		Proof    evidence.Proof `json:"integrity_reference"`
		Verified bool           `json:"integrity_verified"`
	}
	alice.workflow(map[string]any{"operation": "events", "id": job.ID}, 200, &events)
	if len(events) == 0 {
		t.Fatal("workflow lacks signed evidence")
	}
	kernel := false
	public, err := os.ReadFile(filepath.Join(os.Getenv("NEX_QUAL_STATE_DIR"), "evidence-public"))
	if err != nil || len(public) != ed25519.PublicKeySize {
		t.Fatal("pinned evidence verification public key unavailable")
	}
	for _, e := range events {
		if !e.Verified || !evidence.VerifyEvent(ed25519.PublicKey(public), e.Proof, e.Event) {
			t.Fatalf("workflow event signature invalid: %s", e.Action)
		}
		kernel = kernel || e.Producer == "kernel"
	}
	if !kernel {
		t.Fatal("workflow lacks actual Rust-produced signed evidence")
	}
	// Role check uses valid certificates from the same CA and no user token.
	for _, role := range []string{"workspace-client", "worker"} {
		c := systemClient(t, role)
		r, e := c.Get("https://control:18080/v1/status")
		if e != nil {
			t.Fatalf("control status TLS failed for %s: %v", role, e)
		}
		io.Copy(io.Discard, io.LimitReader(r.Body, 4096))
		r.Body.Close()
		want := 200
		if role == "worker" {
			want = 403
		}
		if r.StatusCode != want {
			t.Fatalf("control status role %s status %d want %d", role, r.StatusCode, want)
		}
	}
	code, _ := alice.request("POST", "/auth/logout", map[string]any{}, alice.origin, alice.csrf)
	if code != 200 && code != 204 {
		t.Fatalf("logout status %d", code)
	}
	if code, _ := alice.request("GET", "/api/session", nil, "", ""); code != 401 {
		t.Fatalf("logged-out session status %d", code)
	}
}

// A second real authorization-code flow obtains credentials in server memory,
// allowing the live API token-purpose boundary to be tested independently of
// the BFF. No fixture key or public identity-vending endpoint is used.
func TestQualificationSystemAPITokenBoundary(t *testing.T) {
	b := newSystemBrowser(t)
	const verifier = "qualification-direct-api-verifier-with-more-than-43-characters"
	const redirect = "https://workspace.nex.test:9443/auth/callback"
	authorize := b.issuer + "/authorize?" + url.Values{"client_id": {"nex-workspace"}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {"openid profile nex:access"}, "state": {"independent-api-correlation"}, "nonce": {"independent-api-nonce"}, "code_challenge": {pkceChallenge(verifier)}, "code_challenge_method": {"S256"}}.Encode()
	b.client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if r.URL.Scheme != "https" {
			return fmt.Errorf("non-HTTPS redirect")
		}
		if r.URL.Host == "workspace.nex.test:9443" && r.URL.Path == "/auth/callback" {
			return http.ErrUseLastResponse
		}
		if r.URL.Host != "issuer.nex.test:9444" || len(via) > 10 {
			return fmt.Errorf("unexpected issuer redirect")
		}
		return nil
	}
	r, e := b.client.Get(authorize)
	if e != nil {
		t.Fatal("direct authorization transport failed")
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 16384))
	r.Body.Close()
	match := regexp.MustCompile(`name="csrf" value="([A-Z2-7]+)"`).FindSubmatch(raw)
	if r.StatusCode != 200 || len(match) != 2 {
		t.Fatal("direct authorization credential form absent")
	}
	form := url.Values{"csrf": {string(match[1])}, "username": {"alice"}, "password": {"fixture-alice-password"}}
	req, _ := http.NewRequest("POST", b.issuer+"/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", b.issuer)
	r, e = b.client.Do(req)
	if e != nil {
		t.Fatal("direct login transport failed")
	}
	io.Copy(io.Discard, io.LimitReader(r.Body, 16384))
	r.Body.Close()
	callback, e := r.Location()
	if e != nil || callback.Query().Get("state") != "independent-api-correlation" || callback.Query().Get("iss") != b.issuer || callback.Query().Get("code") == "" {
		t.Fatal("direct authorization correlation failed")
	}
	secret, e := os.ReadFile(filepath.Join(os.Getenv("NEX_QUAL_STATE_DIR"), "secrets", "oidc-client-secret"))
	if e != nil {
		t.Fatal("synthetic confidential-client secret unavailable")
	}
	exchange := func() *http.Response {
		t.Helper()
		request, _ := http.NewRequest("POST", b.issuer+"/token", strings.NewReader(url.Values{"grant_type": {"authorization_code"}, "code": {callback.Query().Get("code")}, "redirect_uri": {redirect}, "code_verifier": {verifier}}.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.SetBasicAuth("nex-workspace", strings.TrimSpace(string(secret)))
		response, err := b.client.Do(request)
		if err != nil {
			t.Fatal("direct token exchange transport failed")
		}
		return response
	}
	r = exchange()
	var tokens struct {
		Access string `json:"access_token"`
		ID     string `json:"id_token"`
	}
	e = json.NewDecoder(io.LimitReader(r.Body, 16384)).Decode(&tokens)
	r.Body.Close()
	if r.StatusCode != 200 || e != nil || tokens.Access == "" || tokens.ID == "" {
		t.Fatal("positive code exchange failed")
	}
	r = exchange()
	io.Copy(io.Discard, io.LimitReader(r.Body, 4096))
	r.Body.Close()
	if r.StatusCode != 400 {
		t.Fatalf("one-use authorization code replay status %d", r.StatusCode)
	}
	for _, tc := range []struct {
		name, role, token string
		want              int
	}{{"positive access", "workspace-client", tokens.Access, 200}, {"browser ID token", "workspace-client", tokens.ID, 401}, {"missing user token", "workspace-client", "", 401}, {"wrong workload with valid user token", "worker", tokens.Access, 403}} {
		t.Run(tc.name, func(t *testing.T) {
			client := systemClient(t, tc.role)
			request, _ := http.NewRequest("GET", "https://control:18080/v1/me", nil)
			if tc.token != "" {
				request.Header.Set("Authorization", "Bearer "+tc.token)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal("live API transport failed")
			}
			defer response.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(response.Body, 16384))
			if response.StatusCode != tc.want {
				t.Fatalf("live API status %d want %d", response.StatusCode, tc.want)
			}
			if tc.want == 200 {
				var identity contracts.IdentityView
				if json.Unmarshal(body, &identity) != nil || identity.Subject != "alice" || identity.Issuer != b.issuer || identity.UserID != "alice" {
					t.Fatal("live API identity was not server-resolved Alice")
				}
			}
		})
	}
	client := systemClient(t, "workspace-client")
	for _, path := range []string{"/v1/models/invoke", "/v1/actions/authorize"} {
		request, _ := http.NewRequest("POST", "https://control:18080"+path, strings.NewReader(`{}`))
		request.Header.Set("Authorization", "Bearer "+tokens.Access)
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("laboratory route transport failed")
		}
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		response.Body.Close()
		if response.StatusCode != 404 {
			t.Fatalf("qualified laboratory route %s status %d", path, response.StatusCode)
		}
	}
}
