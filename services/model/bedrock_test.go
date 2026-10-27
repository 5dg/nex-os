package model

import (
	"context"
	"errors"
	"github.com/5dg/nex-os/packages/contracts"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"testing"
)

type converseStub struct {
	calls   int
	request *bedrockruntime.ConverseInput
	failure bool
}

func (s *converseStub) Converse(ctx context.Context, in *bedrockruntime.ConverseInput, options ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error) {
	s.calls++
	s.request = in
	if s.failure {
		return nil, errors.New("provider unavailable")
	}
	return &bedrockruntime.ConverseOutput{Output: &types.ConverseOutputMemberMessage{Value: types.Message{Role: types.ConversationRoleAssistant, Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: "synthetic provider response"}}}}}, nil
}
func TestBedrockUsesExactRouteAndBoundedRequest(t *testing.T) {
	stub := &converseStub{}
	arn := "arn:aws-us-gov:bedrock:us-gov-west-1::foundation-model/synthetic-test-model-v1"
	adapter := &Bedrock{Client: stub, Region: "us-gov-west-1", ModelARN: arn}
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
	adapter := &Bedrock{Client: stub, Region: "us-gov-west-1", ModelARN: "configured-route"}
	if _, e := adapter.Generate(context.Background(), contracts.Generation{Prompt: "synthetic", Classification: "public", MaxTokens: 32}); e == nil || stub.calls != 1 {
		t.Fatal("provider failure did not fail exactly once")
	}
	for _, x := range []struct{ region, arn string }{{"us-east-1", "arn:aws:bedrock:us-east-1::foundation-model/test"}, {"us-gov-west-1", "arn:aws-us-gov:bedrock:us-gov-east-1::foundation-model/test"}} {
		if _, e := NewBedrock(context.Background(), x.region, x.arn); e == nil {
			t.Fatal("unapproved region/model accepted")
		}
	}
}
