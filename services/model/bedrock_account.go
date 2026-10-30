package model

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/5dg/nex-os/packages/contracts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithyendpoints "github.com/aws/smithy-go/endpoints"
)

var modelAccountID = regexp.MustCompile(`^[0-9]{12}$`)
var modelRoleName = regexp.MustCompile(`^[A-Za-z0-9_+=,.@-]{1,64}$`)
var invalidModelIdentity = errors.New("approved model account or role unavailable")

// BedrockAccountPolicy is explicit trusted configuration, not request input.
// STSEndpoint must be the SDK-resolved regional endpoint with the same FIPS
// choice as the already approved Bedrock route. No account is selected here.
// GovCloud STS may resolve both choices to the same hostname; the pinned
// resolver still requires the exact FIPS parameter on every request. Actual
// service compliance remains a deployment verification.
type BedrockAccountPolicy struct {
	AccountID, CallerRoleName, STSEndpoint string
	RequestTimeout                         time.Duration
}

type pinnedModelSTSEndpoint struct {
	region, endpoint string
	fips             bool
}

func (r *pinnedModelSTSEndpoint) ResolveEndpoint(ctx context.Context, p sts.EndpointParameters) (smithyendpoints.Endpoint, error) {
	if aws.ToString(p.Region) != r.region || aws.ToBool(p.UseFIPS) != r.fips || aws.ToBool(p.UseDualStack) || aws.ToBool(p.UseGlobalEndpoint) || p.Endpoint != nil {
		return smithyendpoints.Endpoint{}, invalidModelIdentity
	}
	resolved, err := sts.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx, p)
	if err != nil || resolved.URI.String() != r.endpoint {
		return smithyendpoints.Endpoint{}, invalidModelIdentity
	}
	return resolved, nil
}

func approvedModelSTS(ctx context.Context, region, endpoint string, fips bool) (*pinnedModelSTSEndpoint, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" {
		return nil, invalidModelIdentity
	}
	params := (sts.EndpointParameters{Region: aws.String(region), UseFIPS: aws.Bool(fips), UseDualStack: aws.Bool(false), UseGlobalEndpoint: aws.Bool(false)}).WithDefaults()
	resolved, err := sts.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx, params)
	if err != nil || resolved.URI.String() != endpoint {
		return nil, invalidModelIdentity
	}
	return &pinnedModelSTSEndpoint{region: region, endpoint: endpoint, fips: fips}, nil
}

// AccountBoundBedrock is an unactivated building block. It verifies the
// configured account/role through regional STS and binds the same captured
// credentials to one Bedrock request. IAM/crypto policy and real effect fencing
// remain independent deployment requirements.
// Generate alone does not validate a trusted Guard digest, template, catalogue
// or phase authority. Production wiring must expose only the authenticated
// coordinator and must enforce its independent effect-spanning fence. The
// configured credential provider must honor cancellation and deadlines.
type AccountBoundBedrock struct {
	base   *Bedrock
	policy BedrockAccountPolicy
	sts    *sts.Client
}

func NewAccountBoundBedrock(ctx context.Context, base *Bedrock, policy BedrockAccountPolicy) (*AccountBoundBedrock, error) {
	if ctx == nil || !base.validRoute() {
		return nil, invalidModelIdentity
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(base.route.region), config.WithRetryMaxAttempts(1))
	if err != nil {
		return nil, invalidModelIdentity
	}
	return newAccountBoundBedrock(ctx, base, policy, cfg)
}

func newAccountBoundBedrock(ctx context.Context, base *Bedrock, policy BedrockAccountPolicy, cfg aws.Config) (*AccountBoundBedrock, error) {
	if ctx == nil || !base.validRoute() || !modelAccountID.MatchString(policy.AccountID) || !modelRoleName.MatchString(policy.CallerRoleName) || policy.RequestTimeout <= 0 || policy.RequestTimeout > 5*time.Minute || cfg.Region != base.route.region || cfg.EndpointResolver != nil || cfg.EndpointResolverWithOptions != nil {
		return nil, invalidModelIdentity
	}
	model, ok := base.route.client.(*bedrockruntime.Client)
	if !ok || model == nil || model.Options().Credentials == nil || model.Options().ClientLogMode != 0 {
		return nil, invalidModelIdentity
	}
	approved, err := approvedBedrockEndpoint(ctx, base.route.region, base.route.endpoint)
	if err != nil {
		return nil, invalidModelIdentity
	}
	resolver, err := approvedModelSTS(ctx, base.route.region, policy.STSEndpoint, approved.fips)
	if err != nil {
		return nil, invalidModelIdentity
	}
	stsConfigured := sts.NewFromConfig(cfg).Options()
	if stsConfigured.BaseEndpoint != nil || stsConfigured.ClientLogMode != 0 || stsConfigured.EndpointOptions.UseDualStackEndpoint == aws.DualStackEndpointStateEnabled || (stsConfigured.EndpointOptions.UseFIPSEndpoint == aws.FIPSEndpointStateEnabled && !resolver.fips) || (stsConfigured.EndpointOptions.UseFIPSEndpoint == aws.FIPSEndpointStateDisabled && resolver.fips) {
		return nil, invalidModelIdentity
	}
	parsed, _ := url.Parse(policy.STSEndpoint)
	transport, timeout, err := configuredBedrockTransport(stsConfigured.HTTPClient, parsed.Host)
	if err != nil {
		return nil, invalidModelIdentity
	}
	client := sts.NewFromConfig(cfg, func(o *sts.Options) {
		o.EndpointResolver = nil
		o.EndpointResolverV2 = resolver
		o.BaseEndpoint = nil
		o.EndpointOptions.UseDualStackEndpoint = aws.DualStackEndpointStateDisabled
		if resolver.fips {
			o.EndpointOptions.UseFIPSEndpoint = aws.FIPSEndpointStateEnabled
		} else {
			o.EndpointOptions.UseFIPSEndpoint = aws.FIPSEndpointStateDisabled
		}
		o.Retryer = aws.NopRetryer{}
		o.RetryMaxAttempts = 1
		o.HTTPClient = bedrockHTTPClient(parsed.Host, transport, timeout)
	})
	return &AccountBoundBedrock{base: base, policy: policy, sts: client}, nil
}

func (b *AccountBoundBedrock) Binding() ProviderBinding {
	if !b.validAccountBinding() {
		return ProviderBinding{}
	}
	return b.base.Binding()
}

func (b *AccountBoundBedrock) validAccountBinding() bool {
	if b == nil || !b.base.validRoute() || b.sts == nil || !modelAccountID.MatchString(b.policy.AccountID) || !modelRoleName.MatchString(b.policy.CallerRoleName) || b.policy.STSEndpoint == "" || b.policy.RequestTimeout <= 0 || b.policy.RequestTimeout > 5*time.Minute {
		return false
	}
	client, ok := b.base.route.client.(*bedrockruntime.Client)
	return ok && client != nil && client.Options().Credentials != nil && client.Options().ClientLogMode == 0
}

func (b *AccountBoundBedrock) Generate(ctx context.Context, in contracts.Generation) (contracts.GenerationResult, error) {
	if ctx == nil || !b.validAccountBinding() {
		return contracts.GenerationResult{}, invalidModelIdentity
	}
	if in.ManifestVersion != 3 || in.Provider != "bedrock" || in.Region != b.base.route.region || in.ModelID != b.base.route.modelARN || in.EffectiveEndpoint != b.base.route.endpoint || (in.Classification != "public" && in.Classification != "internal" && in.Classification != "confidential") || in.MaxTokens < 1 || in.MaxTokens > 256 || len(in.Prompt) == 0 || len(in.Prompt) > 6000 {
		return contracts.GenerationResult{}, invalidModelIdentity
	}
	model, ok := b.base.route.client.(*bedrockruntime.Client)
	if !ok || model == nil {
		return contracts.GenerationResult{}, invalidModelIdentity
	}
	options := model.Options()
	if options.Credentials == nil {
		return contracts.GenerationResult{}, invalidModelIdentity
	}
	bounded, cancel := context.WithTimeout(ctx, b.policy.RequestTimeout)
	defer cancel()
	credentials, err := options.Credentials.Retrieve(bounded)
	if err != nil || bounded.Err() != nil || credentials.AccessKeyID == "" || credentials.SecretAccessKey == "" || (credentials.CanExpire && !credentials.Expires.After(time.Now().Add(b.policy.RequestTimeout+5*time.Second))) {
		return contracts.GenerationResult{}, invalidModelIdentity
	}
	static := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) { return credentials, nil })
	stsOptions := b.sts.Options()
	stsOptions.Credentials = static
	identity, err := sts.New(stsOptions).GetCallerIdentity(bounded, &sts.GetCallerIdentityInput{})
	if err != nil || bounded.Err() != nil || identity == nil || aws.ToString(identity.Account) != b.policy.AccountID {
		return contracts.GenerationResult{}, invalidModelIdentity
	}
	parts := strings.SplitN(aws.ToString(identity.Arn), ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != "aws-us-gov" || parts[2] != "sts" || parts[3] != "" || parts[4] != b.policy.AccountID {
		return contracts.GenerationResult{}, invalidModelIdentity
	}
	role := strings.Split(parts[5], "/")
	if len(role) != 3 || role[0] != "assumed-role" || role[1] != b.policy.CallerRoleName || role[2] == "" {
		return contracts.GenerationResult{}, invalidModelIdentity
	}
	options.Credentials = static
	client := bedrockruntime.New(options)
	route := bedrockRoute{client: client, region: b.base.route.region, modelARN: b.base.route.modelARN, endpoint: b.base.route.endpoint}
	result, err := (&Bedrock{route: &route, seal: route}).Generate(bounded, in)
	if err != nil || bounded.Err() != nil {
		return contracts.GenerationResult{}, invalidModelIdentity
	}
	return result, nil
}
