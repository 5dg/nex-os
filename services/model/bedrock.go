package model

import (
	"context"
	"errors"
	"github.com/5dg/nex-os/packages/contracts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"strings"
)

type ConverseAPI interface {
	Converse(context.Context, *bedrockruntime.ConverseInput, ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error)
}
type Bedrock struct {
	Client           ConverseAPI
	Region, ModelARN string
}

func NewBedrock(ctx context.Context, region, arn string) (*Bedrock, error) {
	if region != "us-gov-west-1" && region != "us-gov-east-1" {
		return nil, errors.New("approved GovCloud region required")
	}
	if !strings.HasPrefix(arn, "arn:aws-us-gov:bedrock:"+region+"::foundation-model/") || strings.ContainsAny(arn, "*? ") {
		return nil, errors.New("exact regional foundation-model ARN required")
	}
	cfg, e := config.LoadDefaultConfig(ctx, config.WithRegion(region), config.WithRetryMaxAttempts(1))
	if e != nil {
		return nil, e
	}
	return &Bedrock{bedrockruntime.NewFromConfig(cfg), region, arn}, nil
}
func (b *Bedrock) Generate(ctx context.Context, in contracts.Generation) (contracts.GenerationResult, error) {
	if in.Classification == "restricted" || in.MaxTokens < 1 || in.MaxTokens > 256 || len(in.Prompt) == 0 || len(in.Prompt) > 6000 {
		return contracts.GenerationResult{}, errors.New("invalid model limits or classification")
	}
	out, e := b.Client.Converse(ctx, &bedrockruntime.ConverseInput{ModelId: aws.String(b.ModelARN), Messages: []types.Message{{Role: types.ConversationRoleUser, Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: in.Prompt}}}}, InferenceConfig: &types.InferenceConfiguration{MaxTokens: aws.Int32(int32(in.MaxTokens))}})
	if e != nil {
		return contracts.GenerationResult{}, errors.New("approved Bedrock route unavailable; no fallback performed")
	}
	message, ok := out.Output.(*types.ConverseOutputMemberMessage)
	if !ok {
		return contracts.GenerationResult{}, errors.New("unexpected provider output")
	}
	var text strings.Builder
	for _, c := range message.Value.Content {
		if item, ok := c.(*types.ContentBlockMemberText); ok {
			text.WriteString(item.Value)
		}
	}
	if text.Len() == 0 || text.Len() > 12000 {
		return contracts.GenerationResult{}, errors.New("invalid provider response")
	}
	return contracts.GenerationResult{Text: text.String(), Provider: "bedrock", ModelID: b.ModelARN}, nil
}
