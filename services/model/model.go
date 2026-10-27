package model

import (
	"errors"
	"github.com/5dg/nex-os/packages/contracts"
)

type Adapter interface {
	Invoke(contracts.ModelInvocation) (contracts.ModelResult, error)
}
type Development struct{}

func (Development) Invoke(in contracts.ModelInvocation) (contracts.ModelResult, error) {
	if in.MaxOutputTokens < 1 || in.MaxOutputTokens > 256 || len(in.Prompt) == 0 || len(in.Prompt) > 4096 {
		return contracts.ModelResult{}, errors.New("invalid invocation limits")
	}
	// Deterministic synthetic response; never echoes or persists prompt contents.
	return contracts.ModelResult{Provider: "development", ModelID: "deterministic-v1", Text: "Synthetic development response. No Bedrock inference was performed."}, nil
}
func New(environment, provider string) (Adapter, error) {
	if environment != "development" && environment != "production" {
		return nil, errors.New("APP_ENV must be development or production")
	}
	if provider == "development" && environment == "development" {
		return Development{}, nil
	}
	return nil, errors.New("requested model provider is unavailable; development adapter is forbidden in production")
}
