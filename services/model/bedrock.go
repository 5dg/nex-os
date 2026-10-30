package model

import (
	"context"
	"errors"
	"github.com/5dg/nex-os/packages/contracts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"reflect"
	"regexp"
	"strings"
)

// Foundation model IDs are a single ARN resource component, not a path or
// wildcard. Do not let whitespace, control characters, or an empty resource
// turn a configured exact route into an ambiguous one.
var foundationModelID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)

type ConverseAPI interface {
	Converse(context.Context, *bedrockruntime.ConverseInput, ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error)
}
type Bedrock struct {
	route *bedrockRoute
	seal  bedrockRoute
}

// The route and SDK client are constructor-owned; callers cannot replace the
// client or relabel its identity through the public adapter API.
type bedrockRoute struct {
	client                     ConverseAPI
	region, modelARN, endpoint string
}

func (b *Bedrock) validRoute() bool {
	if b == nil || b.route == nil || b.route.client == nil || b.seal.client == nil || b.route.region == "" || b.route.modelARN == "" || b.route.endpoint == "" {
		return false
	}
	a, z := reflect.ValueOf(b.route.client), reflect.ValueOf(b.seal.client)
	if !a.Comparable() || !z.Comparable() || (a.Kind() == reflect.Ptr && a.IsNil()) || (z.Kind() == reflect.Ptr && z.IsNil()) {
		return false
	}
	return b.route.client == b.seal.client && b.route.region == b.seal.region && b.route.modelARN == b.seal.modelARN && b.route.endpoint == b.seal.endpoint
}

func NewBedrock(ctx context.Context, region, arn string, endpoint ...string) (*Bedrock, error) {
	if region != "us-gov-west-1" && region != "us-gov-east-1" {
		return nil, errors.New("approved GovCloud region required")
	}
	prefix := "arn:aws-us-gov:bedrock:" + region + "::foundation-model/"
	if !strings.HasPrefix(arn, prefix) || !foundationModelID.MatchString(strings.TrimPrefix(arn, prefix)) {
		return nil, errors.New("exact regional foundation-model ARN required")
	}
	if len(endpoint) != 1 {
		return nil, errors.New("explicit approved Bedrock endpoint required")
	}
	resolver, e := approvedBedrockEndpoint(ctx, region, endpoint[0])
	if e != nil {
		return nil, e
	}
	cfg, e := config.LoadDefaultConfig(ctx, config.WithRegion(region), config.WithRetryMaxAttempts(1))
	if e != nil {
		return nil, e
	}
	if cfg.EndpointResolver != nil || cfg.EndpointResolverWithOptions != nil {
		return nil, errors.New("custom endpoint resolver is not permitted")
	}
	configured := bedrockruntime.NewFromConfig(cfg).Options()
	if configured.BaseEndpoint != nil || configured.BearerAuthTokenProvider != nil || configured.EndpointOptions.UseDualStackEndpoint == aws.DualStackEndpointStateEnabled ||
		(configured.EndpointOptions.UseFIPSEndpoint == aws.FIPSEndpointStateEnabled && !resolver.fips) ||
		(configured.EndpointOptions.UseFIPSEndpoint == aws.FIPSEndpointStateDisabled && resolver.fips) {
		return nil, errors.New("ambient endpoint configuration conflicts with approved route")
	}
	transport, timeout, err := configuredBedrockTransport(configured.HTTPClient)
	if err != nil {
		return nil, err
	}
	client := bedrockruntime.NewFromConfig(cfg, func(o *bedrockruntime.Options) {
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
		o.HTTPClient = bedrockHTTPClient(resolver.host, transport, timeout)
	})
	if client.Options().BearerAuthTokenProvider != nil {
		return nil, errors.New("ambient bearer authentication is not permitted")
	}
	route := bedrockRoute{client: client, region: region, modelARN: arn, endpoint: endpoint[0]}
	return &Bedrock{route: &route, seal: route}, nil
}
func (b *Bedrock) Generate(ctx context.Context, in contracts.Generation) (contracts.GenerationResult, error) {
	if !b.validRoute() || (in.Classification != "public" && in.Classification != "internal" && in.Classification != "confidential") || in.MaxTokens < 1 || in.MaxTokens > 256 || len(in.Prompt) == 0 || len(in.Prompt) > 6000 {
		return contracts.GenerationResult{}, errors.New("invalid model limits or classification")
	}
	out, e := b.route.client.Converse(ctx, &bedrockruntime.ConverseInput{ModelId: aws.String(b.route.modelARN), Messages: []types.Message{{Role: types.ConversationRoleUser, Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: in.Prompt}}}}, InferenceConfig: &types.InferenceConfiguration{MaxTokens: aws.Int32(int32(in.MaxTokens))}})
	if e != nil {
		return contracts.GenerationResult{}, errors.New("approved Bedrock route unavailable; no fallback performed")
	}
	if out == nil || out.StopReason != types.StopReasonEndTurn {
		return contracts.GenerationResult{}, errors.New("unexpected provider output")
	}
	message, ok := out.Output.(*types.ConverseOutputMemberMessage)
	if !ok || message == nil || message.Value.Role != types.ConversationRoleAssistant {
		return contracts.GenerationResult{}, errors.New("unexpected provider output")
	}
	var text strings.Builder
	for _, c := range message.Value.Content {
		item, ok := c.(*types.ContentBlockMemberText)
		if !ok || item == nil || len(item.Value) > 12000-text.Len() {
			return contracts.GenerationResult{}, errors.New("invalid provider response")
		}
		text.WriteString(item.Value)
	}
	if text.Len() == 0 || text.Len() > 12000 {
		return contracts.GenerationResult{}, errors.New("invalid provider response")
	}
	return contracts.GenerationResult{Text: text.String(), Provider: "bedrock", ModelID: b.route.modelARN}, nil
}
