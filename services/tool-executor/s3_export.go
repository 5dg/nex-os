package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithyendpoints "github.com/aws/smithy-go/endpoints"
)

// S3ExportPolicy is trusted service configuration, never browser input. A
// deployment must independently verify bucket ownership, versioning, private
// access, KMS policy, retention/deletion controls and recovery fencing.
type S3ExportPolicy struct {
	Partition, AccountID, Region, Bucket, KMSKeyARN, Endpoint string
	STSEndpoint, CallerRoleName                               string
	DestinationID, Prefix                                     string
	RequestTimeout                                            time.Duration
	HistoricalKMSKeyARNs                                      []string
	LegacyReceiptKMSKeyARN                                    string
}

type s3ExportReceipt struct {
	ArtifactID    string `json:"artifact_id"`
	ContentDigest string `json:"content_digest"`
	ObjectKey     string `json:"object_key"`
	VersionID     string `json:"version_id"`
	KMSKeyARN     string `json:"kms_key_arn"`
}

// The exported methods accept the concrete reviewed PostgreSQL store; this
// private interface permits isolated failure/ordering tests without a database.
type exportReceiptOps interface {
	DoAuthorized(context.Context, string, string, broker.ReceiptAccess, func(context.Context) error, func(context.Context) (any, error)) (json.RawMessage, error)
	Inspect(context.Context, string, string, broker.ReceiptAccess) (json.RawMessage, error)
}

// S3ExportStore is an explicitly configured route. It is not wired into any
// production profile; Guard authentication, durable recovery fencing and the
// bucket's actual policies remain required before live activation.
type S3ExportStore struct {
	policy    S3ExportPolicy
	cfg       aws.Config
	client    *s3.Client
	stsClient *sts.Client
}

var (
	accountPattern = regexp.MustCompile(`^[0-9]{12}$`)
	regionPattern  = regexp.MustCompile(`^(us|af|ap|ca|eu|il|me|mx|sa)-(east|west|north|south|central|northeast|northwest|southeast|southwest)-[0-9]$`)
	bucketPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	namePattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	keyPattern     = regexp.MustCompile(`^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|mrk-[0-9a-f]{32})$`)
	rolePattern    = regexp.MustCompile(`^[A-Za-z0-9_+=,.@-]{1,64}$`)
	invalidExport  = errors.New("managed export unavailable or denied")
)

func validS3Policy(p S3ExportPolicy) bool {
	regionValid := regionPattern.MatchString(p.Region) || p.Region == "us-gov-east-1" || p.Region == "us-gov-west-1"
	if !accountPattern.MatchString(p.AccountID) || !regionValid || !bucketPattern.MatchString(p.Bucket) ||
		strings.Contains(p.Bucket, "..") || strings.Contains(p.Bucket, ".-") || strings.Contains(p.Bucket, "-.") ||
		strings.HasSuffix(p.Bucket, "--x-s3") || net.ParseIP(p.Bucket) != nil || !namePattern.MatchString(p.DestinationID) || !rolePattern.MatchString(p.CallerRoleName) ||
		p.RequestTimeout <= 0 || p.RequestTimeout > 5*time.Minute {
		return false
	}
	if (p.Partition == "aws-us-gov" && p.Region != "us-gov-east-1" && p.Region != "us-gov-west-1") ||
		(p.Partition == "aws" && strings.HasPrefix(p.Region, "us-gov-")) || (p.Partition != "aws" && p.Partition != "aws-us-gov") {
		return false
	}
	if !validS3KMSKey(p, p.KMSKeyARN) || len(p.HistoricalKMSKeyARNs) > 32 {
		return false
	}
	seen := map[string]bool{p.KMSKeyARN: true}
	for _, key := range p.HistoricalKMSKeyARNs {
		if !validS3KMSKey(p, key) || seen[key] {
			return false
		}
		seen[key] = true
	}
	if p.LegacyReceiptKMSKeyARN != "" && !seen[p.LegacyReceiptKMSKeyARN] {
		return false
	}
	if p.Prefix == "" || len(p.Prefix) > 128 || strings.HasPrefix(p.Prefix, "/") || !strings.HasSuffix(p.Prefix, "/") || strings.Contains(p.Prefix, "//") {
		return false
	}
	for _, part := range strings.Split(strings.TrimSuffix(p.Prefix, "/"), "/") {
		if !namePattern.MatchString(part) {
			return false
		}
	}
	return true
}

func validS3KMSKey(p S3ExportPolicy, key string) bool {
	prefix := "arn:" + p.Partition + ":kms:" + p.Region + ":" + p.AccountID + ":key/"
	return strings.HasPrefix(key, prefix) && keyPattern.MatchString(strings.TrimPrefix(key, prefix))
}

func (s *S3ExportStore) approvedReceiptKey(key string) bool {
	if key == s.policy.KMSKeyARN {
		return true
	}
	for _, historical := range s.policy.HistoricalKMSKeyARNs {
		if key == historical {
			return true
		}
	}
	return false
}

type pinnedS3Endpoint struct {
	policy S3ExportPolicy
	fips   bool
}

func (r *pinnedS3Endpoint) ResolveEndpoint(ctx context.Context, p s3.EndpointParameters) (smithyendpoints.Endpoint, error) {
	if aws.ToString(p.Bucket) != r.policy.Bucket || aws.ToString(p.Region) != r.policy.Region || aws.ToBool(p.UseFIPS) != r.fips ||
		aws.ToBool(p.UseDualStack) || aws.ToBool(p.ForcePathStyle) || aws.ToBool(p.Accelerate) || aws.ToBool(p.UseGlobalEndpoint) ||
		aws.ToBool(p.UseArnRegion) || aws.ToBool(p.UseObjectLambdaEndpoint) || p.Endpoint != nil {
		return smithyendpoints.Endpoint{}, invalidExport
	}
	resolved, err := s3.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx, p)
	if err != nil || resolved.URI.String() != r.policy.Endpoint {
		return smithyendpoints.Endpoint{}, invalidExport
	}
	return resolved, nil
}

func approvedS3Endpoint(ctx context.Context, policy S3ExportPolicy) (*pinnedS3Endpoint, error) {
	u, err := url.Parse(policy.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" {
		return nil, invalidExport
	}
	for _, fips := range []bool{false, true} {
		p := (s3.EndpointParameters{Bucket: aws.String(policy.Bucket), Region: aws.String(policy.Region), UseFIPS: aws.Bool(fips), UseDualStack: aws.Bool(false)}).WithDefaults()
		resolved, err := s3.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx, p)
		if err == nil && resolved.URI.String() == policy.Endpoint {
			return &pinnedS3Endpoint{policy: policy, fips: fips}, nil
		}
	}
	return nil, invalidExport
}

type pinnedSTSEndpoint struct {
	policy S3ExportPolicy
	fips   bool
}

func (r *pinnedSTSEndpoint) ResolveEndpoint(ctx context.Context, p sts.EndpointParameters) (smithyendpoints.Endpoint, error) {
	if aws.ToString(p.Region) != r.policy.Region || aws.ToBool(p.UseFIPS) != r.fips || aws.ToBool(p.UseDualStack) || aws.ToBool(p.UseGlobalEndpoint) || p.Endpoint != nil {
		return smithyendpoints.Endpoint{}, invalidExport
	}
	resolved, err := sts.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx, p)
	if err != nil || resolved.URI.String() != r.policy.STSEndpoint {
		return smithyendpoints.Endpoint{}, invalidExport
	}
	return resolved, nil
}

func approvedSTSEndpoint(ctx context.Context, policy S3ExportPolicy) (*pinnedSTSEndpoint, error) {
	u, err := url.Parse(policy.STSEndpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" {
		return nil, invalidExport
	}
	for _, fips := range []bool{false, true} {
		p := (sts.EndpointParameters{Region: aws.String(policy.Region), UseFIPS: aws.Bool(fips), UseDualStack: aws.Bool(false), UseGlobalEndpoint: aws.Bool(false)}).WithDefaults()
		resolved, err := sts.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx, p)
		if err == nil && resolved.URI.String() == policy.STSEndpoint {
			return &pinnedSTSEndpoint{policy: policy, fips: fips}, nil
		}
	}
	return nil, invalidExport
}

type s3BoundTransport struct {
	host string
	next http.RoundTripper
}

func (t s3BoundTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || req.URL.Scheme != "https" || req.URL.Host != t.host || req.URL.User != nil || (req.Host != "" && req.Host != t.host) {
		return nil, invalidExport
	}
	return t.next.RoundTrip(req)
}

type s3DeadlineConn struct {
	net.Conn
	timeout time.Duration
}

func (c *s3DeadlineConn) Read(p []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	n, err := c.Conn.Read(p)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return n, &awshttp.ResponseTimeoutError{TimeoutDur: c.timeout}
	}
	return n, err
}

// NewS3ExportStore resolves only explicitly selected AWS regional endpoints;
// no AWS request is made here. No custom/VPC endpoint is admitted implicitly.
func NewS3ExportStore(ctx context.Context, policy S3ExportPolicy) (*S3ExportStore, error) {
	if ctx == nil || !validS3Policy(policy) {
		return nil, invalidExport
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(policy.Region), config.WithRetryMaxAttempts(1))
	if err != nil {
		return nil, invalidExport
	}
	return newS3ExportStore(ctx, policy, cfg)
}

func boundAWSHTTP(client aws.HTTPClient, endpoint string) (*http.Client, error) {
	sdkHTTP, ok := client.(*awshttp.BuildableClient)
	if !ok || sdkHTTP == nil {
		return nil, invalidExport
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return nil, invalidExport
	}
	transport := sdkHTTP.GetTransport()
	if (transport.TLSClientConfig != nil && (transport.TLSClientConfig.InsecureSkipVerify ||
		(transport.TLSClientConfig.ServerName != "" && transport.TLSClientConfig.ServerName != u.Hostname()))) || transport.DialTLSContext != nil || transport.DialTLS != nil {
		return nil, invalidExport
	}
	dial := transport.DialContext
	if dial == nil {
		dial = sdkHTTP.GetDialer().DialContext
	}
	if timeout, set := sdkHTTP.GetReadTimeout(); set && timeout > 0 {
		inner := dial
		dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := inner(ctx, network, address)
			if err != nil {
				return nil, err
			}
			return &s3DeadlineConn{Conn: conn, timeout: timeout}, nil
		}
	}
	transport.DialContext = dial
	return &http.Client{Transport: s3BoundTransport{host: u.Host, next: transport}, Timeout: sdkHTTP.GetTimeout(), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func newS3ExportStore(ctx context.Context, policy S3ExportPolicy, cfg aws.Config) (*S3ExportStore, error) {
	if ctx == nil || !validS3Policy(policy) || cfg.Region != policy.Region || cfg.Credentials == nil || cfg.EndpointResolver != nil || cfg.EndpointResolverWithOptions != nil {
		return nil, invalidExport
	}
	policy.HistoricalKMSKeyARNs = append([]string(nil), policy.HistoricalKMSKeyARNs...)
	resolver, err := approvedS3Endpoint(ctx, policy)
	if err != nil {
		return nil, invalidExport
	}
	stsResolver, err := approvedSTSEndpoint(ctx, policy)
	if err != nil {
		return nil, invalidExport
	}
	configured := s3.NewFromConfig(cfg).Options()
	if configured.BaseEndpoint != nil || configured.ClientLogMode != 0 || configured.UsePathStyle || configured.UseAccelerate || configured.UseDualstack || configured.UseARNRegion ||
		configured.EndpointOptions.UseDualStackEndpoint == aws.DualStackEndpointStateEnabled ||
		(configured.EndpointOptions.UseFIPSEndpoint == aws.FIPSEndpointStateEnabled && !resolver.fips) ||
		(configured.EndpointOptions.UseFIPSEndpoint == aws.FIPSEndpointStateDisabled && resolver.fips) {
		return nil, invalidExport
	}
	s3HTTP, err := boundAWSHTTP(configured.HTTPClient, policy.Endpoint)
	if err != nil {
		return nil, invalidExport
	}
	stsConfigured := sts.NewFromConfig(cfg).Options()
	if stsConfigured.BaseEndpoint != nil || stsConfigured.ClientLogMode != 0 ||
		stsConfigured.EndpointOptions.UseDualStackEndpoint == aws.DualStackEndpointStateEnabled ||
		(stsConfigured.EndpointOptions.UseFIPSEndpoint == aws.FIPSEndpointStateEnabled && !stsResolver.fips) ||
		(stsConfigured.EndpointOptions.UseFIPSEndpoint == aws.FIPSEndpointStateDisabled && stsResolver.fips) {
		return nil, invalidExport
	}
	stsHTTP, err := boundAWSHTTP(stsConfigured.HTTPClient, policy.STSEndpoint)
	if err != nil {
		return nil, invalidExport
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.EndpointResolver = nil
		o.EndpointResolverV2 = resolver
		o.BaseEndpoint = nil
		o.UsePathStyle = false
		o.UseAccelerate = false
		o.UseDualstack = false
		o.UseARNRegion = false
		o.EndpointOptions.UseDualStackEndpoint = aws.DualStackEndpointStateDisabled
		if resolver.fips {
			o.EndpointOptions.UseFIPSEndpoint = aws.FIPSEndpointStateEnabled
		} else {
			o.EndpointOptions.UseFIPSEndpoint = aws.FIPSEndpointStateDisabled
		}
		o.Retryer = aws.NopRetryer{}
		o.RetryMaxAttempts = 1
		o.HTTPClient = s3HTTP
	})
	stsClient := sts.NewFromConfig(cfg, func(o *sts.Options) {
		o.EndpointResolver = nil
		o.EndpointResolverV2 = stsResolver
		o.BaseEndpoint = nil
		o.EndpointOptions.UseDualStackEndpoint = aws.DualStackEndpointStateDisabled
		if stsResolver.fips {
			o.EndpointOptions.UseFIPSEndpoint = aws.FIPSEndpointStateEnabled
		} else {
			o.EndpointOptions.UseFIPSEndpoint = aws.FIPSEndpointStateDisabled
		}
		o.Retryer = aws.NopRetryer{}
		o.RetryMaxAttempts = 1
		o.HTTPClient = stsHTTP
	})
	return &S3ExportStore{policy: policy, cfg: cfg, client: client, stsClient: stsClient}, nil
}

// A single captured credential set signs both the STS check and every S3
// request in this operation. A refreshable provider cannot silently change
// principals between the identity check and a write/read.
func (s *S3ExportStore) authenticatedClient(ctx context.Context) (*s3.Client, error) {
	if s == nil || s.client == nil || s.stsClient == nil || s.cfg.Credentials == nil {
		return nil, invalidExport
	}
	credentials, err := s.cfg.Credentials.Retrieve(ctx)
	if err != nil || credentials.AccessKeyID == "" || credentials.SecretAccessKey == "" ||
		(credentials.CanExpire && !credentials.Expires.After(time.Now().Add(s.policy.RequestTimeout+5*time.Second))) {
		return nil, invalidExport
	}
	static := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) { return credentials, nil })
	stsOptions := s.stsClient.Options()
	stsOptions.Credentials = static
	identity, err := sts.New(stsOptions).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || identity == nil || aws.ToString(identity.Account) != s.policy.AccountID {
		return nil, invalidExport
	}
	parts := strings.SplitN(aws.ToString(identity.Arn), ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != s.policy.Partition || parts[2] != "sts" || parts[3] != "" || parts[4] != s.policy.AccountID {
		return nil, invalidExport
	}
	role := strings.Split(parts[5], "/")
	if len(role) != 3 || role[0] != "assumed-role" || role[1] != s.policy.CallerRoleName || role[2] == "" {
		return nil, invalidExport
	}
	s3Options := s.client.Options()
	s3Options.Credentials = static
	return s3.New(s3Options), nil
}

func (s *S3ExportStore) boundedContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, s.policy.RequestTimeout)
}
func (s *S3ExportStore) validate(in contracts.Export, digest string) (string, string, error) {
	if s == nil || s.client == nil || in.ManifestVersion != 3 || !namePattern.MatchString(in.TenantID) || !namePattern.MatchString(in.OperationID) || len(in.OperationID) < 8 ||
		in.DestinationID != s.policy.DestinationID || in.RequestDigest == "" || !utf8.ValidString(in.Content) || len(in.Content) == 0 || len(in.Content) > 13000 {
		return "", "", invalidExport
	}
	computed := contracts.ExecutionDigest(in)
	if len(digest) != 64 || subtle.ConstantTimeCompare([]byte(computed), []byte(digest)) != 1 {
		return "", "", invalidExport
	}
	content := sha256.Sum256([]byte(in.Content))
	tenant := sha256.Sum256([]byte(in.TenantID))
	operation := sha256.Sum256([]byte(in.OperationID))
	key := s.policy.Prefix + hex.EncodeToString(tenant[:]) + "/" + hex.EncodeToString(operation[:]) + "/" + digest
	return key, hex.EncodeToString(content[:]), nil
}
func validVersion(v string) bool {
	if v == "" || v == "null" || len(v) > 1024 {
		return false
	}
	for _, c := range v {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

// Execute is a legacy, unphased precursor and must not be wired into a
// production profile. It binds a Guard-authorized v3 payload to a receipt.
// access must recheck current actor/tenant/result authority for this request;
// authorize must authenticate the one-shot Guard effect decision. Fence and
// receipt integrity are enforced by the separately provisioned receiver store.
func (s *S3ExportStore) Execute(ctx context.Context, in contracts.Export, digest string, receipts *broker.PostgresReceiptStore, access broker.ReceiptAccess, authorize func(context.Context) error) (contracts.ExportResult, error) {
	if receipts == nil {
		return contracts.ExportResult{}, invalidExport
	}
	return s.execute(ctx, in, digest, receipts, access, authorize)
}

func (s *S3ExportStore) execute(ctx context.Context, in contracts.Export, digest string, receipts exportReceiptOps, access broker.ReceiptAccess, authorize func(context.Context) error) (contracts.ExportResult, error) {
	var empty contracts.ExportResult
	if ctx == nil || receipts == nil || access == nil || authorize == nil {
		return empty, invalidExport
	}
	key, contentDigest, err := s.validate(in, digest)
	if err != nil {
		return empty, invalidExport
	}
	ctx, cancel := s.boundedContext(ctx)
	defer cancel()
	var verified *s3.Client
	raw, err := receipts.DoAuthorized(ctx, in.OperationID, digest, access, authorize, func(effectCtx context.Context) (any, error) {
		// No network request precedes the authenticated access check and Guard
		// authorization enforced by the receipt store. The durable started
		// marker already prevents a retry if readiness becomes ambiguous.
		rec, client, err := s.putVerified(effectCtx, in, digest, key, contentDigest)
		if err != nil {
			return nil, broker.ErrUnknown
		}
		verified = client
		return rec, nil
	})
	if err != nil {
		return empty, err
	}
	rec, err := s.decodeS3Receipt(raw, in.OperationID, key, contentDigest)
	if err != nil {
		return empty, invalidExport
	}
	if verified == nil {
		verified, err = s.authenticatedClient(ctx)
		if err != nil {
			return empty, invalidExport
		}
	}
	if _, err := s.readExact(ctx, verified, in, digest, rec); err != nil {
		return empty, invalidExport
	}
	if access(ctx, in.OperationID, digest) != nil {
		return empty, invalidExport
	}
	return contracts.ExportResult{ArtifactID: rec.ArtifactID, ContentDigest: rec.ContentDigest}, nil
}

func (s *S3ExportStore) decodeS3Receipt(raw json.RawMessage, operationID, key, digest string) (s3ExportReceipt, error) {
	var rec s3ExportReceipt
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return rec, invalidExport
	}
	values := map[string]string{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return rec, invalidExport
		}
		name, ok := token.(string)
		if !ok || (name != "artifact_id" && name != "content_digest" && name != "object_key" && name != "version_id" && name != "kms_key_arn") {
			return rec, invalidExport
		}
		if _, exists := values[name]; exists {
			return rec, invalidExport
		}
		var value string
		if decoder.Decode(&value) != nil {
			return rec, invalidExport
		}
		values[name] = value
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim('}') || decoder.Decode(new(any)) != io.EOF || (len(values) != 4 && len(values) != 5) {
		return rec, invalidExport
	}
	keyARN, present := values["kms_key_arn"]
	if !present {
		keyARN = s.policy.LegacyReceiptKMSKeyARN
	}
	rec = s3ExportReceipt{ArtifactID: values["artifact_id"], ContentDigest: values["content_digest"], ObjectKey: values["object_key"], VersionID: values["version_id"], KMSKeyARN: keyARN}
	if rec.ArtifactID != operationID || rec.ObjectKey != key || rec.ContentDigest != digest || !validVersion(rec.VersionID) || !s.approvedReceiptKey(rec.KMSKeyARN) {
		return rec, invalidExport
	}
	return rec, nil
}

// Retrieve is a legacy, unphased precursor, not a production read path. It
// performs a fresh authenticated receipt check before reading the
// exact immutable version and rechecking its encryption, metadata and bytes.
func (s *S3ExportStore) Retrieve(ctx context.Context, in contracts.Export, digest string, receipts *broker.PostgresReceiptStore, access broker.ReceiptAccess) ([]byte, error) {
	if receipts == nil {
		return nil, invalidExport
	}
	return s.retrieve(ctx, in, digest, receipts, access)
}

// putVerified runs only inside a receipt store's durable started callback.
// A failed or ambiguous write, verification, or identity check remains unknown.
func (s *S3ExportStore) putVerified(ctx context.Context, in contracts.Export, digest, key, contentDigest string) (s3ExportReceipt, *s3.Client, error) {
	var empty s3ExportReceipt
	client, err := s.authenticatedClient(ctx)
	if err != nil {
		return empty, nil, broker.ErrUnknown
	}
	versioning, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(s.policy.Bucket), ExpectedBucketOwner: aws.String(s.policy.AccountID)})
	if err != nil || versioning == nil || versioning.Status != types.BucketVersioningStatusEnabled {
		return empty, nil, broker.ErrUnknown
	}
	checksum := sha256.Sum256([]byte(in.Content))
	out, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(s.policy.Bucket), Key: aws.String(key), ExpectedBucketOwner: aws.String(s.policy.AccountID),
		Body: bytes.NewReader([]byte(in.Content)), ContentLength: aws.Int64(int64(len(in.Content))), IfNoneMatch: aws.String("*"),
		ServerSideEncryption: types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(s.policy.KMSKeyARN), ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(checksum[:])),
		Metadata: map[string]string{"nex-execution-sha256": digest, "nex-content-sha256": contentDigest}})
	if err != nil || out == nil || !validVersion(aws.ToString(out.VersionId)) || out.ServerSideEncryption != types.ServerSideEncryptionAwsKms || aws.ToString(out.SSEKMSKeyId) != s.policy.KMSKeyARN || aws.ToString(out.ChecksumSHA256) != base64.StdEncoding.EncodeToString(checksum[:]) {
		return empty, nil, broker.ErrUnknown
	}
	rec := s3ExportReceipt{ArtifactID: in.OperationID, ContentDigest: contentDigest, ObjectKey: key, VersionID: aws.ToString(out.VersionId), KMSKeyARN: s.policy.KMSKeyARN}
	if _, err := s.readExact(ctx, client, in, digest, rec); err != nil {
		return empty, nil, broker.ErrUnknown
	}
	return rec, client, nil
}

func (s *S3ExportStore) retrieve(ctx context.Context, in contracts.Export, digest string, receipts exportReceiptOps, access broker.ReceiptAccess) ([]byte, error) {
	if ctx == nil || receipts == nil || access == nil {
		return nil, invalidExport
	}
	key, contentDigest, err := s.validate(in, digest)
	if err != nil {
		return nil, invalidExport
	}
	ctx, cancel := s.boundedContext(ctx)
	defer cancel()
	raw, err := receipts.Inspect(ctx, in.OperationID, digest, access)
	if err != nil {
		return nil, err
	}
	rec, err := s.decodeS3Receipt(raw, in.OperationID, key, contentDigest)
	if err != nil {
		return nil, invalidExport
	}
	verified, err := s.authenticatedClient(ctx)
	if err != nil {
		return nil, invalidExport
	}
	content, err := s.readExact(ctx, verified, in, digest, rec)
	if err != nil {
		return nil, invalidExport
	}
	if access(ctx, in.OperationID, digest) != nil {
		return nil, invalidExport
	}
	return content, nil
}

func (s *S3ExportStore) readExact(ctx context.Context, client *s3.Client, in contracts.Export, digest string, rec s3ExportReceipt) ([]byte, error) {
	if client == nil {
		return nil, invalidExport
	}
	out, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.policy.Bucket), Key: aws.String(rec.ObjectKey), VersionId: aws.String(rec.VersionID), ExpectedBucketOwner: aws.String(s.policy.AccountID)})
	if err != nil || out == nil || out.Body == nil {
		return nil, invalidExport
	}
	defer out.Body.Close()
	if aws.ToString(out.VersionId) != rec.VersionID || out.ServerSideEncryption != types.ServerSideEncryptionAwsKms || aws.ToString(out.SSEKMSKeyId) != rec.KMSKeyARN ||
		out.Metadata["nex-execution-sha256"] != digest || out.Metadata["nex-content-sha256"] != rec.ContentDigest {
		return nil, invalidExport
	}
	content, err := io.ReadAll(io.LimitReader(out.Body, 13001))
	if err != nil || len(content) > 13000 || !bytes.Equal(content, []byte(in.Content)) {
		return nil, invalidExport
	}
	hash := sha256.Sum256(content)
	if hex.EncodeToString(hash[:]) != rec.ContentDigest {
		return nil, invalidExport
	}
	return content, nil
}
