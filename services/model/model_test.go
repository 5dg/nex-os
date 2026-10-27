package model

import (
	"github.com/5dg/nex-os/packages/contracts"
	"testing"
)

func TestProviderConfiguration(t *testing.T) {
	for _, tt := range []struct {
		env, provider string
		valid         bool
	}{{"development", "development", true}, {"production", "development", false}, {"production", "bedrock", false}, {"", "development", false}, {"development", "unknown", false}} {
		_, err := New(tt.env, tt.provider)
		if (err == nil) != tt.valid {
			t.Fatalf("%s/%s: %v", tt.env, tt.provider, err)
		}
	}
}
func TestDevelopmentInvocationLimits(t *testing.T) {
	if _, err := (Development{}).Invoke(contracts.ModelInvocation{Prompt: "synthetic", MaxOutputTokens: 100000}); err == nil {
		t.Fatal("unbounded request accepted")
	}
}
