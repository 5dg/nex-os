package model

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Fixture-only independent SigV4 verification for the exact synthetic STS and
// Bedrock requests. The rotating credential provider uses different secrets.
func verifyFixtureSignature(r *http.Request, body []byte, secret, region, service string) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") || r.URL.RawQuery != "" {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(auth, "AWS4-HMAC-SHA256 "), ", ")
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "Credential=") || !strings.HasPrefix(parts[1], "SignedHeaders=") || !strings.HasPrefix(parts[2], "Signature=") {
		return false
	}
	credential := strings.Split(strings.TrimPrefix(parts[0], "Credential="), "/")
	date := r.Header.Get("X-Amz-Date")
	if len(credential) != 5 || len(date) != 16 || credential[1] != date[:8] || credential[2] != region || credential[3] != service || credential[4] != "aws4_request" {
		return false
	}
	signed := strings.TrimPrefix(parts[1], "SignedHeaders=")
	headers := strings.Split(signed, ";")
	sorted := append([]string(nil), headers...)
	sort.Strings(sorted)
	if strings.Join(sorted, ";") != signed {
		return false
	}
	var canonicalHeaders strings.Builder
	for _, name := range headers {
		if name == "" {
			return false
		}
		value := ""
		if name == "host" {
			value = r.Host
		} else if name == "content-length" {
			if r.ContentLength <= 0 {
				return false
			}
			value = strconv.FormatInt(r.ContentLength, 10)
		} else {
			values := r.Header.Values(name)
			if len(values) == 0 {
				return false
			}
			for i := range values {
				values[i] = strings.Join(strings.Fields(values[i]), " ")
			}
			value = strings.Join(values, ",")
		}
		canonicalHeaders.WriteString(name + ":" + strings.Join(strings.Fields(value), " ") + "\n")
	}
	// The SDK escapes an already escaped URI path once more for non-S3 SigV4.
	var path strings.Builder
	for _, b := range []byte(r.URL.EscapedPath()) {
		if b == '/' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.' || b == '~' {
			path.WriteByte(b)
		} else {
			fmt.Fprintf(&path, "%%%02X", b)
		}
	}
	if path.Len() == 0 {
		path.WriteByte('/')
	}
	payload := sha256.Sum256(body)
	canonical := r.Method + "\n" + path.String() + "\n\n" + canonicalHeaders.String() + "\n" + signed + "\n" + hex.EncodeToString(payload[:])
	hash := sha256.Sum256([]byte(canonical))
	scope := strings.Join(credential[1:], "/")
	message := "AWS4-HMAC-SHA256\n" + date + "\n" + scope + "\n" + hex.EncodeToString(hash[:])
	mac := func(key []byte, value string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(value))
		return h.Sum(nil)
	}
	kDate := mac([]byte("AWS4"+secret), credential[1])
	kRegion := mac(kDate, region)
	kService := mac(kRegion, service)
	kSigning := mac(kService, "aws4_request")
	expected := mac(kSigning, message)
	received, err := hex.DecodeString(strings.TrimPrefix(parts[2], "Signature="))
	return err == nil && hmac.Equal(expected, received)
}

type modelAccountFixture struct {
	mu                                    sync.Mutex
	stsCalls, modelCalls, credentialReads int
	accessKeys, sessionTokens             []string
	account, role, arnOverride            string
	stsStatus, modelStatus                int
	malformed                             bool
	expires                               time.Time
}

func newModelAccountFixture(t *testing.T) (*AccountBoundBedrock, *modelAccountFixture) {
	t.Helper()
	_, _, modelPolicy := productionBindingFixture()
	bedURL, _ := url.Parse(modelPolicy.EffectiveEndpoint)
	stsParams := (sts.EndpointParameters{Region: aws.String(modelPolicy.Region), UseFIPS: aws.Bool(true), UseDualStack: aws.Bool(false), UseGlobalEndpoint: aws.Bool(false)}).WithDefaults()
	resolved, err := sts.NewDefaultEndpointResolverV2().ResolveEndpoint(context.Background(), stsParams)
	if err != nil {
		t.Fatal(err)
	}
	stsURL := resolved.URI
	bedCert, bedRoot, _ := fixtureCertificate(t, bedURL.Hostname())
	stsCert, stsRoot, _ := fixtureCertificate(t, stsURL.Hostname())
	roots := x509.NewCertPool()
	roots.AddCert(bedRoot)
	roots.AddCert(stsRoot)
	f := &modelAccountFixture{account: "123456789012", role: "nex-model"}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		auth := r.Header.Get("Authorization")
		start := strings.Index(auth, "Credential=")
		if start < 0 {
			http.Error(w, "missing synthetic signature", 400)
			return
		}
		key := auth[start+len("Credential="):]
		end := strings.Index(key, "/")
		if end < 0 {
			http.Error(w, "invalid synthetic signature", 400)
			return
		}
		accessKey := key[:end]
		f.accessKeys = append(f.accessKeys, accessKey)
		f.sessionTokens = append(f.sessionTokens, r.Header.Get("X-Amz-Security-Token"))
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "synthetic body unavailable", 400)
			return
		}
		secret := ""
		if accessKey == "FIXTUREFIRST" {
			secret = "synthetic-secret-first"
		} else if accessKey == "FIXTURESECOND" {
			secret = "synthetic-secret-second"
		}
		if r.Host == stsURL.Host {
			f.stsCalls++
			if secret == "" || !verifyFixtureSignature(r, body, secret, modelPolicy.Region, "sts") {
				http.Error(w, "incorrect STS signing", 400)
				return
			}
			if f.stsStatus != 0 {
				w.Header().Set("Location", "https://unapproved.invalid/")
				w.WriteHeader(f.stsStatus)
				return
			}
			if f.malformed {
				w.Header().Set("Content-Type", "text/xml")
				io.WriteString(w, "<invalid>")
				return
			}
			if !strings.Contains(string(body), "Action=GetCallerIdentity") {
				http.Error(w, "incorrect STS action", 400)
				return
			}
			arn := f.arnOverride
			if arn == "" {
				arn = fmt.Sprintf("arn:aws-us-gov:sts::%s:assumed-role/%s/synthetic-session", f.account, f.role)
			}
			w.Header().Set("Content-Type", "text/xml")
			fmt.Fprintf(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Account>%s</Account><Arn>%s</Arn><UserId>synthetic</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`, f.account, arn)
			return
		}
		if r.Host == bedURL.Host {
			f.modelCalls++
			if f.modelStatus != 0 {
				w.Header().Set("Location", "https://unapproved.invalid/")
				w.WriteHeader(f.modelStatus)
				return
			}
			if secret == "" || !verifyFixtureSignature(r, body, secret, modelPolicy.Region, "bedrock") {
				http.Error(w, "incorrect model signing", 400)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"output":{"message":{"role":"assistant","content":[{"text":"synthetic provider response"}]}},"stopReason":"end_turn"}`)
			return
		}
		http.Error(w, "unexpected synthetic host", 400)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName == stsURL.Hostname() {
			return &stsCert, nil
		}
		if hello.ServerName == bedURL.Hostname() {
			return &bedCert, nil
		}
		return nil, fmt.Errorf("unexpected fixture TLS name")
	}}
	server.StartTLS()
	t.Cleanup(server.Close)
	httpClient := awshttp.NewBuildableClient().WithTimeout(2 * time.Second).WithReadTimeout(500 * time.Millisecond).WithTransportOptions(func(tr *http.Transport) {
		tr.Proxy = nil
		tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		}
	})
	credentials := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.credentialReads++
		key, secret, token := "FIXTUREFIRST", "synthetic-secret-first", "fixture-session-first"
		if f.credentialReads > 1 {
			key, secret, token = "FIXTURESECOND", "synthetic-secret-second", "fixture-session-second"
		}
		c := aws.Credentials{AccessKeyID: key, SecretAccessKey: secret, SessionToken: token}
		if !f.expires.IsZero() {
			c.CanExpire = true
			c.Expires = f.expires
		}
		return c, nil
	})
	cfg := aws.Config{Region: modelPolicy.Region, Credentials: credentials, HTTPClient: httpClient}
	resolver, err := approvedBedrockEndpoint(context.Background(), modelPolicy.Region, modelPolicy.EffectiveEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	transport, timeout, err := configuredBedrockTransport(httpClient, bedURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	client := bedrockruntime.NewFromConfig(cfg, func(o *bedrockruntime.Options) {
		o.EndpointResolverV2 = resolver
		o.EndpointOptions.UseFIPSEndpoint = aws.FIPSEndpointStateEnabled
		o.EndpointOptions.UseDualStackEndpoint = aws.DualStackEndpointStateDisabled
		o.Retryer = aws.NopRetryer{}
		o.RetryMaxAttempts = 1
		o.HTTPClient = bedrockHTTPClient(bedURL.Host, transport, timeout)
	})
	base := testBedrock(client, modelPolicy.Region, modelPolicy.ModelID, modelPolicy.EffectiveEndpoint)
	bound, err := newAccountBoundBedrock(context.Background(), base, BedrockAccountPolicy{AccountID: f.account, CallerRoleName: f.role, STSEndpoint: stsURL.String(), RequestTimeout: time.Second}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return bound, f
}

func TestAccountBoundBedrockPinsSameCredentialSnapshot(t *testing.T) {
	bound, f := newModelAccountFixture(t)
	httpClient, ok := bound.sts.Options().HTTPClient.(*http.Client)
	if !ok || httpClient.Timeout != 2*time.Second {
		t.Fatal("STS client lost SDK timeout")
	}
	guard, ok := httpClient.Transport.(bedrockBoundTransport)
	if !ok {
		t.Fatal("STS destination guard missing")
	}
	transport, ok := guard.next.(*http.Transport)
	if !ok || transport.DialContext == nil || transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("STS trust or configured dialer lost")
	}
	in, _, _ := productionBindingFixture()
	out, err := bound.Generate(context.Background(), in)
	if err != nil || out.Text != "synthetic provider response" {
		t.Fatalf("bound synthetic request failed: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.credentialReads != 1 || f.stsCalls != 1 || f.modelCalls != 1 || len(f.accessKeys) != 2 || f.accessKeys[0] != "FIXTUREFIRST" || f.accessKeys[1] != "FIXTUREFIRST" || len(f.sessionTokens) != 2 || f.sessionTokens[0] != "fixture-session-first" || f.sessionTokens[1] != "fixture-session-first" {
		t.Fatal("STS and model did not share one captured credential")
	}
}

func TestAccountBoundBedrockRejectsWrongSTSTLSIdentity(t *testing.T) {
	bound, _ := newModelAccountFixture(t)
	client := awshttp.NewBuildableClient().WithTransportOptions(func(tr *http.Transport) { tr.TLSClientConfig = &tls.Config{ServerName: "wrong.example.invalid"} })
	bedrockClient := bound.base.route.client.(*bedrockruntime.Client)
	cfg := aws.Config{Region: bound.base.route.region, Credentials: bedrockClient.Options().Credentials, HTTPClient: client}
	if _, err := newAccountBoundBedrock(context.Background(), bound.base, bound.policy, cfg); err == nil {
		t.Fatal("mismatched STS TLS server name accepted")
	}
}

func TestAccountBoundBedrockRejectsWrongIdentityExpiryAndRedirect(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*modelAccountFixture)
	}{
		{"account", func(f *modelAccountFixture) { f.account = "999999999999" }},
		{"role", func(f *modelAccountFixture) { f.role = "wrong-role" }},
		{"arn", func(f *modelAccountFixture) {
			f.arnOverride = "arn:aws:sts::123456789012:assumed-role/nex-model/synthetic-session"
		}},
		{"expiry", func(f *modelAccountFixture) { f.expires = time.Now().Add(2 * time.Second) }},
		{"expired", func(f *modelAccountFixture) { f.expires = time.Now().Add(-time.Second) }},
		{"malformed", func(f *modelAccountFixture) { f.malformed = true }},
		{"redirect", func(f *modelAccountFixture) { f.stsStatus = http.StatusTemporaryRedirect }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bound, f := newModelAccountFixture(t)
			f.mu.Lock()
			tc.mutate(f)
			f.mu.Unlock()
			in, _, _ := productionBindingFixture()
			if _, err := bound.Generate(context.Background(), in); err == nil {
				t.Fatal("unsafe model identity accepted")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			expectedSTS := 1
			if tc.name == "expiry" || tc.name == "expired" {
				expectedSTS = 0
			}
			if f.modelCalls != 0 || f.stsCalls != expectedSTS {
				t.Fatal("identity failure reached model, skipped identity check, or retried")
			}
		})
	}
}

func TestAccountBoundBedrockModelRedirectIsNotFollowedOrRetried(t *testing.T) {
	bound, f := newModelAccountFixture(t)
	f.mu.Lock()
	f.modelStatus = http.StatusTemporaryRedirect
	f.mu.Unlock()
	in, _, _ := productionBindingFixture()
	if _, err := bound.Generate(context.Background(), in); err == nil {
		t.Fatal("redirect accepted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stsCalls != 1 || f.modelCalls != 1 || len(f.accessKeys) != 2 {
		t.Fatal("redirect followed or request repeated")
	}
}

func TestAccountBoundBedrockRejectsEndpointAndRouteMismatch(t *testing.T) {
	bound, f := newModelAccountFixture(t)
	in, _, _ := productionBindingFixture()
	in.Region = "us-gov-east-1"
	if _, err := bound.Generate(context.Background(), in); err == nil {
		t.Fatal("mismatched route accepted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stsCalls != 0 || f.modelCalls != 0 {
		t.Fatal("invalid route made an AWS request")
	}
	if _, err := approvedModelSTS(context.Background(), "us-gov-west-1", "https://sts.us-gov-east-1.amazonaws.com", false); err == nil {
		t.Fatal("cross-region STS accepted")
	}
	// The AWS SDK resolves GovCloud STS FIPS and standard requests to the
	// same DNS name. Pin and test the FIPS parameter itself instead of
	// inferring the selected policy from the shared hostname.
	fipsResolver, err := approvedModelSTS(context.Background(), "us-gov-west-1", "https://sts.us-gov-west-1.amazonaws.com", true)
	if err != nil {
		t.Fatal("SDK-resolved GovCloud STS FIPS endpoint rejected")
	}
	params := (sts.EndpointParameters{Region: aws.String("us-gov-west-1"), UseFIPS: aws.Bool(true), UseDualStack: aws.Bool(false), UseGlobalEndpoint: aws.Bool(false)}).WithDefaults()
	if _, err := fipsResolver.ResolveEndpoint(context.Background(), params); err != nil {
		t.Fatal("approved FIPS parameters rejected")
	}
	params.UseFIPS = aws.Bool(false)
	if _, err := fipsResolver.ResolveEndpoint(context.Background(), params); err == nil {
		t.Fatal("changed FIPS parameter accepted on aliased hostname")
	}
	params.UseFIPS = aws.Bool(true)
	params.UseDualStack = aws.Bool(true)
	if _, err := fipsResolver.ResolveEndpoint(context.Background(), params); err == nil {
		t.Fatal("dual-stack STS override accepted")
	}
	params.UseDualStack = aws.Bool(false)
	params.UseGlobalEndpoint = aws.Bool(true)
	if _, err := fipsResolver.ResolveEndpoint(context.Background(), params); err == nil {
		t.Fatal("global STS override accepted")
	}
}
