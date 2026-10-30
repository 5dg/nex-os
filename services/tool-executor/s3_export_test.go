package executor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type fakeReceiptStore struct {
	result  json.RawMessage
	started bool
}

func (f *fakeReceiptStore) DoAuthorized(ctx context.Context, id, digest string, access broker.ReceiptAccess, authorize func(context.Context) error, effect func(context.Context) (any, error)) (json.RawMessage, error) {
	if access(ctx, id, digest) != nil {
		return nil, broker.ErrUnknown
	}
	if f.result != nil {
		return append(json.RawMessage(nil), f.result...), nil
	}
	if f.started || authorize(ctx) != nil {
		return nil, broker.ErrUnknown
	}
	f.started = true
	value, err := effect(ctx)
	if err != nil {
		return nil, broker.ErrUnknown
	}
	f.result, err = json.Marshal(value)
	return f.result, err
}
func (f *fakeReceiptStore) Inspect(ctx context.Context, id, digest string, access broker.ReceiptAccess) (json.RawMessage, error) {
	if access(ctx, id, digest) != nil || f.result == nil {
		return nil, broker.ErrUnknown
	}
	return append(json.RawMessage(nil), f.result...), nil
}

type s3Fixture struct {
	mu            sync.Mutex
	server        *httptest.Server
	policy        S3ExportPolicy
	requests      []string
	accessKeys    []string
	written       []byte
	metadata      map[string]string
	version       string
	putStatus     int
	versioning    string
	badRead       bool
	callerAccount string
	callerRole    string
}

func s3TestCertificate(t *testing.T, hostnames ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic S3 test"}, DNSNames: hostnames,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(parsed)
	return cert, pool
}

func newS3Fixture(t *testing.T) (*S3ExportStore, *s3Fixture) {
	t.Helper()
	policy := S3ExportPolicy{Partition: "aws-us-gov", AccountID: "123456789012", Region: "us-gov-west-1", Bucket: "nex-test-exports",
		KMSKeyARN:     "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/12345678-1234-1234-1234-123456789012",
		DestinationID: "approved-export", Prefix: "nex/exports/", CallerRoleName: "nex-export", RequestTimeout: 3 * time.Second}
	params := (s3.EndpointParameters{Bucket: aws.String(policy.Bucket), Region: aws.String(policy.Region), UseFIPS: aws.Bool(false), UseDualStack: aws.Bool(false)}).WithDefaults()
	endpoint, err := s3.NewDefaultEndpointResolverV2().ResolveEndpoint(context.Background(), params)
	if err != nil {
		t.Fatal(err)
	}
	policy.Endpoint = endpoint.URI.String()
	stsParams := (sts.EndpointParameters{Region: aws.String(policy.Region), UseFIPS: aws.Bool(false), UseDualStack: aws.Bool(false), UseGlobalEndpoint: aws.Bool(false)}).WithDefaults()
	stsEndpoint, err := sts.NewDefaultEndpointResolverV2().ResolveEndpoint(context.Background(), stsParams)
	if err != nil {
		t.Fatal(err)
	}
	policy.STSEndpoint = stsEndpoint.URI.String()
	parsed, err := url.Parse(policy.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	stsParsed, err := url.Parse(policy.STSEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	cert, roots := s3TestCertificate(t, parsed.Hostname(), stsParsed.Hostname())
	f := &s3Fixture{policy: policy, version: "synthetic-version-123", versioning: "Enabled"}
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(f.handle))
	f.server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	client := awshttp.NewBuildableClient().WithTransportOptions(func(tr *http.Transport) {
		// This is an isolated loopback test server, not an outbound service.
		tr.Proxy = nil
		tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, f.server.Listener.Addr().String())
		}
	})
	cfg := aws.Config{Region: policy.Region, Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("TESTACCESSKEY", "synthetic-secret", "")), HTTPClient: client}
	store, err := newS3ExportStore(context.Background(), policy, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return store, f
}

func (f *s3Fixture) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
	auth := r.Header.Get("Authorization")
	if start := strings.Index(auth, "Credential="); start >= 0 {
		value := auth[start+len("Credential="):]
		if end := strings.Index(value, "/"); end >= 0 {
			f.accessKeys = append(f.accessKeys, value[:end])
		}
	}
	if r.Host == strings.TrimPrefix(f.policy.STSEndpoint, "https://") {
		if r.Method != http.MethodPost || !strings.Contains(r.Header.Get("Authorization"), "/"+f.policy.Region+"/sts/aws4_request") {
			http.Error(w, "identity binding rejected", 400)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || !strings.Contains(string(body), "Action=GetCallerIdentity") {
			http.Error(w, "identity request rejected", 400)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		account, role := f.callerAccount, f.callerRole
		if account == "" {
			account = f.policy.AccountID
		}
		if role == "" {
			role = f.policy.CallerRoleName
		}
		fmt.Fprintf(w, "<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><GetCallerIdentityResult><Account>%s</Account><Arn>arn:%s:sts::%s:assumed-role/%s/synthetic-session</Arn><UserId>synthetic</UserId></GetCallerIdentityResult><ResponseMetadata><RequestId>synthetic</RequestId></ResponseMetadata></GetCallerIdentityResponse>", account, f.policy.Partition, account, role)
		return
	}
	if r.Host != strings.TrimPrefix(f.policy.Endpoint, "https://") || r.Header.Get("X-Amz-Expected-Bucket-Owner") != f.policy.AccountID ||
		!strings.Contains(r.Header.Get("Authorization"), "/"+f.policy.Region+"/s3/aws4_request") {
		http.Error(w, "binding rejected", 400)
		return
	}
	if r.Method == http.MethodGet && r.URL.Query().Has("versioning") {
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprintf(w, "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>%s</Status></VersioningConfiguration>", f.versioning)
		return
	}
	if r.Method == http.MethodPut {
		if f.putStatus != 0 {
			w.Header().Set("Location", "https://unapproved.invalid/")
			w.WriteHeader(f.putStatus)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", 400)
			return
		}
		h := sha256.Sum256(body)
		if r.Header.Get("If-None-Match") != "*" || r.Header.Get("X-Amz-Server-Side-Encryption") != "aws:kms" ||
			r.Header.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id") != f.policy.KMSKeyARN || r.Header.Get("X-Amz-Checksum-Sha256") != base64.StdEncoding.EncodeToString(h[:]) {
			http.Error(w, "write protections missing", 400)
			return
		}
		f.written = append([]byte(nil), body...)
		f.metadata = map[string]string{"nex-execution-sha256": r.Header.Get("X-Amz-Meta-Nex-Execution-Sha256"), "nex-content-sha256": r.Header.Get("X-Amz-Meta-Nex-Content-Sha256")}
		w.Header().Set("X-Amz-Version-Id", f.version)
		w.Header().Set("X-Amz-Server-Side-Encryption", "aws:kms")
		w.Header().Set("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", f.policy.KMSKeyARN)
		w.Header().Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(h[:]))
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method == http.MethodGet && r.URL.Query().Get("versionId") == f.version {
		w.Header().Set("X-Amz-Version-Id", f.version)
		w.Header().Set("X-Amz-Server-Side-Encryption", "aws:kms")
		w.Header().Set("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", f.policy.KMSKeyARN)
		for key, value := range f.metadata {
			w.Header().Set("X-Amz-Meta-"+key, value)
		}
		if f.badRead {
			_, _ = w.Write([]byte("tampered"))
			return
		}
		_, _ = w.Write(f.written)
		return
	}
	http.Error(w, "unexpected request", 400)
}

func fixtureExport() contracts.Export {
	return contracts.Export{ManifestVersion: 3, OperationID: "operation-123", TenantID: "tenant-a", DestinationID: "approved-export", Content: "approved synthetic content", RequestDigest: "guard-binding"}
}

func TestManagedExportUsesSignedExactRouteAndNeverRepeatsEffect(t *testing.T) {
	store, f := newS3Fixture(t)
	in := fixtureExport()
	digest := contracts.ExecutionDigest(in)
	receipts := &fakeReceiptStore{}
	accesses, grants := 0, 0
	access := func(context.Context, string, string) error { accesses++; return nil }
	authorize := func(context.Context) error { grants++; return nil }
	result, err := store.execute(context.Background(), in, digest, receipts, access, authorize)
	if err != nil || result.ArtifactID != in.OperationID || grants != 1 || accesses != 2 {
		t.Fatalf("execute failed: %#v %v grants=%d access=%d", result, err, grants, accesses)
	}
	replay, err := store.execute(context.Background(), in, digest, receipts, access, authorize)
	if err != nil || replay != result || grants != 1 {
		t.Fatalf("replay failed: %#v %v grants=%d", replay, err, grants)
	}
	body, err := store.retrieve(context.Background(), in, digest, receipts, access)
	if err != nil || string(body) != in.Content {
		t.Fatalf("retrieve failed: %q %v", body, err)
	}
	f.mu.Lock()
	requests := append([]string(nil), f.requests...)
	f.mu.Unlock()
	puts := 0
	for _, req := range requests {
		if strings.HasPrefix(req, "PUT ") {
			puts++
		}
	}
	if puts != 1 {
		t.Fatalf("wanted exactly one provider write, got %d requests=%v", puts, requests)
	}
}

func TestManagedExportDenialConflictAndRedirectNeverRetry(t *testing.T) {
	for _, status := range []int{http.StatusPreconditionFailed, http.StatusTemporaryRedirect, http.StatusInternalServerError} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			store, f := newS3Fixture(t)
			f.putStatus = status
			in := fixtureExport()
			digest := contracts.ExecutionDigest(in)
			receipts := &fakeReceiptStore{}
			access := func(context.Context, string, string) error { return nil }
			authorize := func(context.Context) error { return nil }
			if _, err := store.execute(context.Background(), in, digest, receipts, access, authorize); err == nil {
				t.Fatal("ambiguous or rejected write accepted")
			}
			if _, err := store.execute(context.Background(), in, digest, receipts, access, authorize); err == nil {
				t.Fatal("uncertain effect retried")
			}
			f.mu.Lock()
			requests := append([]string(nil), f.requests...)
			f.mu.Unlock()
			puts := 0
			for _, req := range requests {
				if strings.HasPrefix(req, "PUT ") {
					puts++
				}
			}
			if puts != 1 {
				t.Fatalf("got %d PUTs: %v", puts, requests)
			}
		})
	}
	store, f := newS3Fixture(t)
	in := fixtureExport()
	receipts := &fakeReceiptStore{}
	denied := func(context.Context, string, string) error { return errors.New("revoked") }
	if _, err := store.execute(context.Background(), in, contracts.ExecutionDigest(in), receipts, denied, func(context.Context) error { t.Fatal("denied authorization executed"); return nil }); err == nil {
		t.Fatal("revoked access accepted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) != 0 {
		t.Fatalf("denied caller caused network requests: %v", f.requests)
	}
}

func TestManagedExportRejectsTamperedVersionedObjectAndMalformedReceipt(t *testing.T) {
	store, f := newS3Fixture(t)
	in := fixtureExport()
	digest := contracts.ExecutionDigest(in)
	receipts := &fakeReceiptStore{}
	access := func(context.Context, string, string) error { return nil }
	if _, err := store.execute(context.Background(), in, digest, receipts, access, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.badRead = true
	f.mu.Unlock()
	if _, err := store.retrieve(context.Background(), in, digest, receipts, access); err == nil {
		t.Fatal("tampered content returned")
	}
	key, contentDigest, err := store.validate(in, digest)
	if err != nil {
		t.Fatal(err)
	}
	bad := fmt.Sprintf(`{"artifact_id":%q,"artifact_id":%q,"object_key":%q,"content_digest":%q,"version_id":"v1"}`, in.OperationID, in.OperationID, key, contentDigest)
	if _, err := decodeS3Receipt(json.RawMessage(bad), in.OperationID, key, contentDigest); err == nil {
		t.Fatal("duplicate receipt field accepted")
	}
	if _, _, err := store.validate(in, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong manifest digest accepted")
	}
	wrongTenant := in
	wrongTenant.TenantID = "other-tenant"
	if _, _, err := store.validate(wrongTenant, digest); err == nil {
		t.Fatal("tenant change accepted")
	}
}

func TestManagedExportRejectsUnversionedBucketAndKeepsOutcomeUnknown(t *testing.T) {
	store, f := newS3Fixture(t)
	f.versioning = "Suspended"
	in, receipts := fixtureExport(), &fakeReceiptStore{}
	access := func(context.Context, string, string) error { return nil }
	digest := contracts.ExecutionDigest(in)
	if _, err := store.execute(context.Background(), in, digest, receipts, access, func(context.Context) error { return nil }); err == nil {
		t.Fatal("unversioned bucket accepted")
	}
	if _, err := store.execute(context.Background(), in, digest, receipts, access, func(context.Context) error { return nil }); err == nil {
		t.Fatal("unknown operation retried")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) != 2 || !strings.Contains(f.requests[1], "versioning") {
		t.Fatalf("unexpected provider operations: %v", f.requests)
	}
}

func TestManagedExportRechecksRevocationBeforeReturning(t *testing.T) {
	store, f := newS3Fixture(t)
	in, receipts := fixtureExport(), &fakeReceiptStore{}
	digest, checks := contracts.ExecutionDigest(in), 0
	access := func(context.Context, string, string) error {
		checks++
		if checks > 1 {
			return errors.New("revoked")
		}
		return nil
	}
	if _, err := store.execute(context.Background(), in, digest, receipts, access, func(context.Context) error { return nil }); err == nil {
		t.Fatal("revoked response returned")
	}
	if receipts.result == nil {
		t.Fatal("completed effect receipt lost")
	}
	f.mu.Lock()
	before := len(f.requests)
	f.mu.Unlock()
	if _, err := store.retrieve(context.Background(), in, digest, receipts, access); err == nil {
		t.Fatal("revoked retrieval returned")
	}
	f.mu.Lock()
	after := len(f.requests)
	f.mu.Unlock()
	if after != before {
		t.Fatal("revoked retrieval contacted object store")
	}
	allowed := func(context.Context, string, string) error { return nil }
	value, err := store.retrieve(context.Background(), in, digest, receipts, allowed)
	if err != nil || string(value) != in.Content {
		t.Fatalf("authorized reconciliation failed: %q %v", value, err)
	}
}

func TestManagedExportPolicyDeniesUnapprovedOrAmbiguousRoutes(t *testing.T) {
	store, _ := newS3Fixture(t)
	valid := store.policy
	for _, mutate := range []func(*S3ExportPolicy){
		func(p *S3ExportPolicy) { p.AccountID = "123" },
		func(p *S3ExportPolicy) { p.Partition = "aws" },
		func(p *S3ExportPolicy) {
			p.KMSKeyARN = "arn:aws-us-gov:kms:us-gov-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
		},
		func(p *S3ExportPolicy) { p.Bucket = "169.254.169.254" },
		func(p *S3ExportPolicy) { p.Bucket = "nex--x-s3" },
		func(p *S3ExportPolicy) { p.Prefix = "../escape/" },
		func(p *S3ExportPolicy) { p.DestinationID = "https://unapproved.example" },
		func(p *S3ExportPolicy) { p.RequestTimeout = 0 },
	} {
		p := valid
		mutate(&p)
		if validS3Policy(p) {
			t.Fatalf("unsafe policy accepted: %#v", p)
		}
	}
	for _, endpoint := range []string{"http://nex-test-exports.s3.us-gov-west-1.amazonaws.com", "https://unapproved.invalid", valid.Endpoint + "?override=1", valid.Endpoint + "/extra"} {
		p := valid
		p.Endpoint = endpoint
		if _, err := approvedS3Endpoint(context.Background(), p); err == nil {
			t.Fatalf("unsafe endpoint accepted: %s", endpoint)
		}
	}
	for _, endpoint := range []string{"http://sts.us-gov-west-1.amazonaws.com", "https://unapproved.invalid", valid.STSEndpoint + "?override=1", "https://sts.us-gov-east-1.amazonaws.com"} {
		p := valid
		p.STSEndpoint = endpoint
		if _, err := approvedSTSEndpoint(context.Background(), p); err == nil {
			t.Fatalf("unsafe STS endpoint accepted: %s", endpoint)
		}
	}
}

func TestManagedExportRejectsUntrustedTLSCertificate(t *testing.T) {
	store, f := newS3Fixture(t)
	cfg := store.cfg
	cfg.HTTPClient = awshttp.NewBuildableClient().WithTransportOptions(func(tr *http.Transport) {
		tr.Proxy = nil // Synthetic loopback server only.
		tr.TLSClientConfig = &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, f.server.Listener.Addr().String())
		}
	})
	store, err := newS3ExportStore(context.Background(), store.policy, cfg)
	if err != nil {
		t.Fatal(err)
	}
	in := fixtureExport()
	_, err = store.execute(context.Background(), in, contracts.ExecutionDigest(in), &fakeReceiptStore{}, func(context.Context, string, string) error { return nil }, func(context.Context) error { return nil })
	if err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) != 0 {
		t.Fatalf("request reached untrusted server: %v", f.requests)
	}
}

func TestManagedExportBindsTLSIdentityToEndpoint(t *testing.T) {
	store, _ := newS3Fixture(t)
	for _, endpoint := range []string{store.policy.Endpoint, store.policy.STSEndpoint} {
		u, err := url.Parse(endpoint)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name, serverName string
			wantError        bool
		}{
			{"default", "", false},
			{"matching", u.Hostname(), false},
			{"alternate", "attacker.example", true},
		} {
			t.Run(u.Hostname()+"/"+tc.name, func(t *testing.T) {
				roots := x509.NewCertPool()
				client := awshttp.NewBuildableClient().WithTransportOptions(func(tr *http.Transport) {
					tr.TLSClientConfig = &tls.Config{RootCAs: roots, ServerName: tc.serverName, MinVersion: tls.VersionTLS12}
				})
				bound, err := boundAWSHTTP(client, endpoint)
				if (err != nil) != tc.wantError {
					t.Fatalf("ServerName %q: unexpected error %v", tc.serverName, err)
				}
				if err == nil {
					transport, ok := bound.Transport.(s3BoundTransport)
					if !ok {
						t.Fatal("missing endpoint-bound transport")
					}
					tlsConfig := transport.next.(*http.Transport).TLSClientConfig
					if tlsConfig.RootCAs != roots || tlsConfig.ServerName != tc.serverName {
						t.Fatal("approved TLS settings were not preserved")
					}
				}
			})
		}
	}
}

func TestManagedExportCallerIdentityMismatchNeverWrites(t *testing.T) {
	for _, mismatch := range []struct{ account, role string }{{"999999999999", "nex-export"}, {"123456789012", "wrong-role"}, {"123456789012", "nex-export/extra-path"}} {
		t.Run(mismatch.account+"/"+mismatch.role, func(t *testing.T) {
			store, f := newS3Fixture(t)
			f.callerAccount, f.callerRole = mismatch.account, mismatch.role
			in, receipts := fixtureExport(), &fakeReceiptStore{}
			if _, err := store.execute(context.Background(), in, contracts.ExecutionDigest(in), receipts, func(context.Context, string, string) error { return nil }, func(context.Context) error { return nil }); err == nil {
				t.Fatal("wrong workload identity accepted")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.requests) != 1 || !strings.HasPrefix(f.requests[0], "POST ") {
				t.Fatalf("S3 was contacted after wrong caller: %v", f.requests)
			}
		})
	}
}

func TestManagedExportRejectsCredentialsThatMayExpireDuringOperation(t *testing.T) {
	for _, remaining := range []time.Duration{-time.Second, 7 * time.Second} {
		t.Run(remaining.String(), func(t *testing.T) {
			store, f := newS3Fixture(t)
			store.cfg.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
				return aws.Credentials{AccessKeyID: "TESTKEY", SecretAccessKey: "synthetic-secret", CanExpire: true, Expires: time.Now().Add(remaining)}, nil
			})
			in, receipts := fixtureExport(), &fakeReceiptStore{}
			_, err := store.execute(context.Background(), in, contracts.ExecutionDigest(in), receipts, func(context.Context, string, string) error { return nil }, func(context.Context) error { return nil })
			if err == nil {
				t.Fatal("expired or near-expiry credentials accepted")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.requests) != 0 {
				t.Fatalf("credentials contacted remote services: %v", f.requests)
			}
		})
	}
}

func TestManagedExportRejectsCrossTenantReceiptBeforeNetworkRead(t *testing.T) {
	store, f := newS3Fixture(t)
	in, receipts := fixtureExport(), &fakeReceiptStore{}
	access := func(context.Context, string, string) error { return nil }
	if _, err := store.execute(context.Background(), in, contracts.ExecutionDigest(in), receipts, access, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	before := len(f.requests)
	f.mu.Unlock()
	other := in
	other.TenantID = "tenant-b"
	if _, err := store.retrieve(context.Background(), other, contracts.ExecutionDigest(other), receipts, access); err == nil {
		t.Fatal("cross-tenant receipt accepted")
	}
	f.mu.Lock()
	after := len(f.requests)
	f.mu.Unlock()
	if after != before {
		t.Fatal("cross-tenant receipt contacted remote services")
	}
}

func TestManagedExportCapturesOneCredentialSetPerOperation(t *testing.T) {
	store, f := newS3Fixture(t)
	calls := 0
	store.cfg.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		calls++
		return aws.Credentials{AccessKeyID: fmt.Sprintf("TESTKEY%d", calls), SecretAccessKey: "synthetic-secret"}, nil
	})
	in, receipts := fixtureExport(), &fakeReceiptStore{}
	access := func(context.Context, string, string) error { return nil }
	if _, err := store.execute(context.Background(), in, contracts.ExecutionDigest(in), receipts, access, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("credential provider called %d times", calls)
	}
	f.mu.Lock()
	keys := append([]string(nil), f.accessKeys...)
	f.mu.Unlock()
	if len(keys) < 4 {
		t.Fatalf("expected signed STS/S3 requests, got %d", len(keys))
	}
	for _, key := range keys {
		if key != "TESTKEY1" {
			t.Fatal("identity and object requests used different credentials")
		}
	}
}
