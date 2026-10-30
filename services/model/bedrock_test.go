package model

import (
	"context"
	"errors"
	"github.com/5dg/nex-os/packages/contracts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"io"
	"net/http"
	"strings"
	"testing"
)

type converseStub struct {
	calls       int
	request     *bedrockruntime.ConverseInput
	failure     bool
	response    *bedrockruntime.ConverseOutput
	useResponse bool
}

func testBedrock(client ConverseAPI, region, arn, endpoint string) *Bedrock {
	route := bedrockRoute{client: client, region: region, modelARN: arn, endpoint: endpoint}
	return &Bedrock{route: &route, seal: route}
}

type failingBedrockHTTP struct {
	calls         int
	url           string
	authorization string
	redirect      bool
}

func (c *failingBedrockHTTP) RoundTrip(r *http.Request) (*http.Response, error) {
	c.calls++
	c.url = r.URL.String()
	c.authorization = r.Header.Get("Authorization")
	if c.redirect {
		return &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: http.Header{"Location": []string{"https://unexpected.invalid/stolen"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	}
	return &http.Response{StatusCode: http.StatusInternalServerError, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"message":"unavailable"}`))}, nil
}

func TestBedrockSDKDoesNotRetryAnUncertainInvocation(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "fixture-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "fixture-secret")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_RETRY_MODE", "standard")
	t.Setenv("AWS_MAX_ATTEMPTS", "15")
	t.Setenv("AWS_ENDPOINT_URL", "")
	t.Setenv("AWS_ENDPOINT_URL_BEDROCK_RUNTIME", "")
	t.Setenv("AWS_USE_FIPS_ENDPOINT", "")
	t.Setenv("AWS_USE_DUALSTACK_ENDPOINT", "")
	t.Setenv("AWS_BEARER_TOKEN_BEDROCK", "")
	endpoint := "https://bedrock-runtime.us-gov-west-1.amazonaws.com"
	adapter, err := NewBedrock(context.Background(), "us-gov-west-1", "arn:aws-us-gov:bedrock:us-gov-west-1::foundation-model/fixture-model-v1:0", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	client := adapter.route.client.(*bedrockruntime.Client)
	opts := client.Options()
	httpClient := &failingBedrockHTTP{}
	opts.HTTPClient = bedrockHTTPClient("bedrock-runtime.us-gov-west-1.amazonaws.com", httpClient, 0)
	adapter.route.client = bedrockruntime.New(opts)
	adapter.seal.client = adapter.route.client
	_, err = adapter.Generate(context.Background(), contracts.Generation{Prompt: "synthetic", Classification: "public", MaxTokens: 32})
	if err == nil || httpClient.calls != 1 || !strings.HasPrefix(httpClient.url, endpoint+"/") || !strings.Contains(httpClient.authorization, "/us-gov-west-1/bedrock/aws4_request") {
		t.Fatalf("uncertain invocation: err=%v attempts=%d", err, httpClient.calls)
	}
}

func TestBedrockRejectsEndpointSubstitutionAndFIPSMismatch(t *testing.T) {
	region := "us-gov-west-1"
	arn := "arn:aws-us-gov:bedrock:us-gov-west-1::foundation-model/fixture-model-v1:0"
	standard := "https://bedrock-runtime.us-gov-west-1.amazonaws.com"
	fips := "https://bedrock-runtime-fips.us-gov-west-1.amazonaws.com"
	for _, endpoint := range []string{"", "http://bedrock-runtime.us-gov-west-1.amazonaws.com", "https://bedrock-runtime.us-gov-east-1.amazonaws.com", "https://unexpected.invalid", "https://user@bedrock-runtime.us-gov-west-1.amazonaws.com", standard + "/", standard + ":443", standard + "?foo=bar"} {
		if _, err := NewBedrock(context.Background(), region, arn, endpoint); err == nil {
			t.Fatalf("unapproved endpoint accepted: %q", endpoint)
		}
	}
	if _, err := NewBedrock(context.Background(), region, arn); err == nil {
		t.Fatal("missing explicit endpoint accepted")
	}
	t.Setenv("AWS_ENDPOINT_URL_BEDROCK_RUNTIME", "https://unexpected.invalid")
	if _, err := NewBedrock(context.Background(), region, arn, standard); err == nil {
		t.Fatal("ambient service endpoint override accepted")
	}
	t.Setenv("AWS_ENDPOINT_URL_BEDROCK_RUNTIME", "")
	t.Setenv("AWS_ENDPOINT_URL", "https://unexpected.invalid")
	if _, err := NewBedrock(context.Background(), region, arn, standard); err == nil {
		t.Fatal("ambient global endpoint override accepted")
	}
	t.Setenv("AWS_ENDPOINT_URL", "")
	t.Setenv("AWS_BEARER_TOKEN_BEDROCK", "fixture-token")
	if _, err := NewBedrock(context.Background(), region, arn, standard); err == nil {
		t.Fatal("ambient bearer authentication accepted")
	}
	t.Setenv("AWS_BEARER_TOKEN_BEDROCK", "")
	t.Setenv("AWS_USE_DUALSTACK_ENDPOINT", "true")
	if _, err := NewBedrock(context.Background(), region, arn, standard); err == nil {
		t.Fatal("ambient dual-stack endpoint accepted")
	}
	t.Setenv("AWS_USE_DUALSTACK_ENDPOINT", "")
	t.Setenv("AWS_USE_FIPS_ENDPOINT", "true")
	if _, err := NewBedrock(context.Background(), region, arn, standard); err == nil {
		t.Fatal("FIPS environment mismatch accepted")
	}
	adapter, err := NewBedrock(context.Background(), region, arn, fips)
	if err != nil || adapter.Binding().EffectiveEndpoint != fips {
		t.Fatalf("explicit FIPS route was not bound: %v", err)
	}
}

func TestBedrockResolverAndTransportRejectChangedDestination(t *testing.T) {
	endpoint := "https://bedrock-runtime.us-gov-west-1.amazonaws.com"
	resolver, err := approvedBedrockEndpoint(context.Background(), "us-gov-west-1", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []bedrockruntime.EndpointParameters{
		{Region: aws.String("us-gov-east-1"), UseFIPS: aws.Bool(false), UseDualStack: aws.Bool(false)},
		{Region: aws.String("us-gov-west-1"), UseFIPS: aws.Bool(true), UseDualStack: aws.Bool(false)},
		{Region: aws.String("us-gov-west-1"), UseFIPS: aws.Bool(false), UseDualStack: aws.Bool(true)},
		{Region: aws.String("us-gov-west-1"), UseFIPS: aws.Bool(false), UseDualStack: aws.Bool(false), Endpoint: aws.String("https://unexpected.invalid")},
	} {
		if _, err := resolver.ResolveEndpoint(context.Background(), p); err == nil {
			t.Fatal("changed SDK endpoint parameters accepted")
		}
	}
	transport := &failingBedrockHTTP{}
	client := bedrockHTTPClient("bedrock-runtime.us-gov-west-1.amazonaws.com", transport, 0)
	req, err := http.NewRequest(http.MethodPost, "https://unexpected.invalid", strings.NewReader("synthetic"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Do(req); err == nil || transport.calls != 0 {
		t.Fatal("changed transport destination reached the network")
	}
}

func TestBedrockDoesNotFollowProviderRedirect(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "fixture-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "fixture-secret")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_ENDPOINT_URL", "")
	t.Setenv("AWS_ENDPOINT_URL_BEDROCK_RUNTIME", "")
	t.Setenv("AWS_USE_FIPS_ENDPOINT", "")
	t.Setenv("AWS_BEARER_TOKEN_BEDROCK", "")
	endpoint := "https://bedrock-runtime.us-gov-west-1.amazonaws.com"
	adapter, err := NewBedrock(context.Background(), "us-gov-west-1", "arn:aws-us-gov:bedrock:us-gov-west-1::foundation-model/fixture-model-v1:0", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	client := adapter.route.client.(*bedrockruntime.Client)
	opts := client.Options()
	transport := &failingBedrockHTTP{redirect: true}
	opts.HTTPClient = bedrockHTTPClient("bedrock-runtime.us-gov-west-1.amazonaws.com", transport, 0)
	adapter.route.client = bedrockruntime.New(opts)
	adapter.seal.client = adapter.route.client
	_, err = adapter.Generate(context.Background(), contracts.Generation{Prompt: "synthetic", Classification: "public", MaxTokens: 32})
	if err == nil || transport.calls != 1 || !strings.HasPrefix(transport.url, endpoint+"/") {
		t.Fatalf("redirect followed or invocation accepted: err=%v calls=%d", err, transport.calls)
	}
}

func TestBedrockFIPSEndpointAndSigningRegion(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "fixture-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "fixture-secret")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_ENDPOINT_URL", "")
	t.Setenv("AWS_ENDPOINT_URL_BEDROCK_RUNTIME", "")
	t.Setenv("AWS_USE_FIPS_ENDPOINT", "true")
	t.Setenv("AWS_BEARER_TOKEN_BEDROCK", "")
	endpoint := "https://bedrock-runtime-fips.us-gov-east-1.amazonaws.com"
	adapter, err := NewBedrock(context.Background(), "us-gov-east-1", "arn:aws-us-gov:bedrock:us-gov-east-1::foundation-model/fixture-model-v1:0", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	client := adapter.route.client.(*bedrockruntime.Client)
	opts := client.Options()
	transport := &failingBedrockHTTP{}
	opts.HTTPClient = bedrockHTTPClient("bedrock-runtime-fips.us-gov-east-1.amazonaws.com", transport, 0)
	adapter.route.client = bedrockruntime.New(opts)
	adapter.seal.client = adapter.route.client
	_, err = adapter.Generate(context.Background(), contracts.Generation{Prompt: "synthetic", Classification: "public", MaxTokens: 32})
	if err == nil || transport.calls != 1 || !strings.HasPrefix(transport.url, endpoint+"/") || !strings.Contains(transport.authorization, "/us-gov-east-1/bedrock/aws4_request") {
		t.Fatalf("FIPS route/signing failed: err=%v attempts=%d", err, transport.calls)
	}
}

func (s *converseStub) Converse(ctx context.Context, in *bedrockruntime.ConverseInput, options ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error) {
	s.calls++
	s.request = in
	if s.failure {
		return nil, errors.New("provider unavailable")
	}
	if s.useResponse {
		return s.response, nil
	}
	return &bedrockruntime.ConverseOutput{StopReason: types.StopReasonEndTurn, Output: &types.ConverseOutputMemberMessage{Value: types.Message{Role: types.ConversationRoleAssistant, Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: "synthetic provider response"}}}}}, nil
}

func TestBedrockRejectsUnrecognizedClassificationBeforeDispatch(t *testing.T) {
	stub := &converseStub{}
	adapter := testBedrock(stub, "us-gov-west-1", "configured-route", "https://bedrock-runtime.us-gov-west-1.amazonaws.com")
	for _, classification := range []string{"", "restricted", "secret", "CONFIDENTIAL", "internal\n"} {
		_, err := adapter.Generate(context.Background(), contracts.Generation{Prompt: "synthetic", Classification: classification, MaxTokens: 32})
		if err == nil || stub.calls != 0 {
			t.Fatalf("classification %q reached provider", classification)
		}
	}
}

func TestBedrockRejectsAmbiguousFoundationModelARN(t *testing.T) {
	prefix := "arn:aws-us-gov:bedrock:us-gov-west-1::foundation-model/"
	for _, suffix := range []string{"", "model/extra", "model\n", "model\t", "*", " model", ".model"} {
		if _, err := NewBedrock(context.Background(), "us-gov-west-1", prefix+suffix, "https://bedrock-runtime.us-gov-west-1.amazonaws.com"); err == nil {
			t.Fatalf("ambiguous model ARN accepted: %q", suffix)
		}
	}
}

func TestBedrockRejectsMalformedProviderResponses(t *testing.T) {
	var typedNil *types.ConverseOutputMemberMessage
	responses := []*bedrockruntime.ConverseOutput{
		nil,
		{StopReason: types.StopReasonEndTurn, Output: typedNil},
		{StopReason: types.StopReasonEndTurn, Output: &types.ConverseOutputMemberMessage{Value: types.Message{Role: types.ConversationRoleUser, Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: "not an assistant response"}}}}},
		{StopReason: types.StopReasonEndTurn, Output: &types.ConverseOutputMemberMessage{Value: types.Message{Role: types.ConversationRoleAssistant, Content: []types.ContentBlock{(*types.ContentBlockMemberText)(nil)}}}},
		{StopReason: types.StopReasonEndTurn, Output: &types.ConverseOutputMemberMessage{Value: types.Message{Role: types.ConversationRoleAssistant, Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: "partial"}, &types.ContentBlockMemberToolUse{}}}}},
		{StopReason: types.StopReasonMaxTokens, Output: &types.ConverseOutputMemberMessage{Value: types.Message{Role: types.ConversationRoleAssistant, Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: "truncated"}}}}},
		{StopReason: types.StopReasonEndTurn, Output: &types.ConverseOutputMemberMessage{Value: types.Message{Role: types.ConversationRoleAssistant, Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: strings.Repeat("x", 12001)}}}}},
	}
	for i, response := range responses {
		stub := &converseStub{useResponse: true, response: response}
		adapter := testBedrock(stub, "us-gov-west-1", "configured-route", "https://bedrock-runtime.us-gov-west-1.amazonaws.com")
		if _, err := adapter.Generate(context.Background(), contracts.Generation{Prompt: "synthetic", Classification: "public", MaxTokens: 32}); err == nil || stub.calls != 1 {
			t.Fatalf("malformed response %d accepted", i)
		}
	}
	var adapter *Bedrock
	if _, err := adapter.Generate(context.Background(), contracts.Generation{Prompt: "synthetic", Classification: "public", MaxTokens: 32}); err == nil {
		t.Fatal("nil adapter accepted")
	}
}

func TestBedrockRejectsUninitializedOrMutatedRoute(t *testing.T) {
	stub := &converseStub{}
	base := testBedrock(stub, "us-gov-west-1", "arn:aws-us-gov:bedrock:us-gov-west-1::foundation-model/fixture-model-v1:0", "https://bedrock-runtime.us-gov-west-1.amazonaws.com")
	copyBinding := base.Binding()
	copyBinding.ModelID = "forged"
	if base.Binding().ModelID == copyBinding.ModelID {
		t.Fatal("mutable binding escaped adapter")
	}
	for _, mutate := range []func(*bedrockRoute){
		func(x *bedrockRoute) { x.region = "us-gov-east-1" },
		func(x *bedrockRoute) { x.modelARN = "forged" },
		func(x *bedrockRoute) { x.endpoint = "https://unexpected.invalid" },
		func(x *bedrockRoute) { x.client = &converseStub{} },
	} {
		changed := *base
		route := *base.route
		changed.route = &route
		mutate(changed.route)
		if changed.Binding().Provider != "" {
			t.Fatal("mutated adapter advertised a binding")
		}
		if _, err := changed.Generate(context.Background(), contracts.Generation{Prompt: "synthetic", Classification: "public", MaxTokens: 32}); err == nil {
			t.Fatal("mutated adapter dispatched")
		}
	}
	if (&Bedrock{}).Binding().Provider != "" || stub.calls != 0 {
		t.Fatal("uninitialized or mutated adapter reached provider")
	}
}
func TestBedrockUsesExactRouteAndBoundedRequest(t *testing.T) {
	stub := &converseStub{}
	arn := "arn:aws-us-gov:bedrock:us-gov-west-1::foundation-model/synthetic-test-model-v1"
	adapter := testBedrock(stub, "us-gov-west-1", arn, "https://bedrock-runtime.us-gov-west-1.amazonaws.com")
	result, e := adapter.Generate(context.Background(), contracts.Generation{Prompt: "synthetic context", Classification: "confidential", MaxTokens: 128})
	if e != nil || result.Provider != "bedrock" || result.ModelID != arn || stub.calls != 1 || *stub.request.ModelId != arn || *stub.request.InferenceConfig.MaxTokens != 128 {
		t.Fatalf("unexpected route/invocation: %v %v", result, e)
	}
	if _, e = adapter.Generate(context.Background(), contracts.Generation{Prompt: "synthetic", Classification: "restricted", MaxTokens: 128}); e == nil || stub.calls != 1 {
		t.Fatal("restricted context reached provider")
	}
}
func TestBedrockFailureDoesNotFallback(t *testing.T) {
	stub := &converseStub{failure: true}
	adapter := testBedrock(stub, "us-gov-west-1", "configured-route", "https://bedrock-runtime.us-gov-west-1.amazonaws.com")
	if _, e := adapter.Generate(context.Background(), contracts.Generation{Prompt: "synthetic", Classification: "public", MaxTokens: 32}); e == nil || stub.calls != 1 {
		t.Fatal("provider failure did not fail exactly once")
	}
	for _, x := range []struct{ region, arn string }{{"us-east-1", "arn:aws:bedrock:us-east-1::foundation-model/test"}, {"us-gov-west-1", "arn:aws-us-gov:bedrock:us-gov-east-1::foundation-model/test"}} {
		if _, e := NewBedrock(context.Background(), x.region, x.arn); e == nil {
			t.Fatal("unapproved region/model accepted")
		}
	}
}
