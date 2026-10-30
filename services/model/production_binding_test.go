package model

import (
	"strings"
	"testing"

	"github.com/5dg/nex-os/packages/contracts"
)

func productionBindingFixture() (contracts.Generation, *Bedrock, ProductionModelPolicy) {
	policy := ProductionModelPolicy{
		RouteID: "approved-route", Provider: "bedrock", Region: "us-gov-west-1",
		ModelID:           "arn:aws-us-gov:bedrock:us-gov-west-1::foundation-model/fixture-model-v1:0",
		EffectiveEndpoint: "https://bedrock-runtime-fips.us-gov-west-1.amazonaws.com",
		TemplateVersion:   "review-v1", QuestionCatalogueID: "review-question", QuestionCatalogueVersion: "v1",
		QuestionClassification: "internal", AllowedClassifications: []string{"internal", "confidential"}, MaxTokens: 200,
	}
	in := contracts.Generation{
		ManifestVersion: 3, OperationID: "operation-1", TenantID: "tenant-1", RouteID: policy.RouteID,
		Provider: policy.Provider, Region: policy.Region, ModelID: policy.ModelID, EffectiveEndpoint: policy.EffectiveEndpoint,
		TemplateVersion: policy.TemplateVersion, QuestionCatalogueID: policy.QuestionCatalogueID,
		QuestionCatalogueVersion: policy.QuestionCatalogueVersion, QuestionClassification: policy.QuestionClassification,
		Classification: "confidential", Prompt: "synthetic document", MaxTokens: 100,
	}
	actual := testBedrock(&converseStub{}, policy.Region, policy.ModelID, policy.EffectiveEndpoint)
	return in, actual, policy
}

func TestProductionModelBindingMatchesTrustedManifestAndRoute(t *testing.T) {
	in, actual, policy := productionBindingFixture()
	expected := contracts.ExecutionDigest(in)
	if got, err := ValidateProductionModelBinding(in, actual, policy, expected); err != nil || got != expected {
		t.Fatalf("valid bound manifest rejected: %v", err)
	}
}

func TestProductionModelBindingRejectsTamperedManifestEvenWithNewDigest(t *testing.T) {
	tests := map[string]func(*contracts.Generation){
		"version":                 func(x *contracts.Generation) { x.ManifestVersion = 2 },
		"route":                   func(x *contracts.Generation) { x.RouteID = "other" },
		"provider":                func(x *contracts.Generation) { x.Provider = "development" },
		"region":                  func(x *contracts.Generation) { x.Region = "us-gov-east-1" },
		"model":                   func(x *contracts.Generation) { x.ModelID = "other" },
		"endpoint":                func(x *contracts.Generation) { x.EffectiveEndpoint = "https://unexpected.invalid" },
		"template":                func(x *contracts.Generation) { x.TemplateVersion = "other" },
		"question":                func(x *contracts.Generation) { x.QuestionCatalogueID = "other" },
		"question version":        func(x *contracts.Generation) { x.QuestionCatalogueVersion = "other" },
		"question classification": func(x *contracts.Generation) { x.QuestionClassification = "confidential" },
		"classification":          func(x *contracts.Generation) { x.Classification = "restricted" },
		"underclassified":         func(x *contracts.Generation) { x.Classification = "public" },
		"token limit":             func(x *contracts.Generation) { x.MaxTokens = 201 },
		"feature":                 func(x *contracts.Generation) { x.Features = []string{"tools"} },
		"empty tenant":            func(x *contracts.Generation) { x.TenantID = "" },
		"empty operation":         func(x *contracts.Generation) { x.OperationID = "" },
		"empty prompt":            func(x *contracts.Generation) { x.Prompt = "" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			in, actual, policy := productionBindingFixture()
			mutate(&in)
			if _, err := ValidateProductionModelBinding(in, actual, policy, contracts.ExecutionDigest(in)); err == nil {
				t.Fatal("tampered manifest accepted")
			}
		})
	}
}

func TestProductionModelBindingRejectsWrongDigestAndAdapter(t *testing.T) {
	in, actual, policy := productionBindingFixture()
	expected := contracts.ExecutionDigest(in)
	for _, digest := range []string{"", strings.Repeat("0", 64), strings.ToUpper(expected), expected + "0"} {
		if _, err := ValidateProductionModelBinding(in, actual, policy, digest); err == nil {
			t.Fatal("invalid authorized digest accepted")
		}
	}
	tampered := in
	tampered.Prompt = "a different payload"
	if _, err := ValidateProductionModelBinding(tampered, actual, policy, expected); err == nil {
		t.Fatal("digest from a different signed payload accepted")
	}
	for _, mutate := range []func(*bedrockRoute){
		func(x *bedrockRoute) { x.region = "us-gov-east-1" },
		func(x *bedrockRoute) { x.modelARN = "other" },
		func(x *bedrockRoute) { x.endpoint = "https://unexpected.invalid" },
		func(x *bedrockRoute) { x.client = &converseStub{} },
	} {
		changed := *actual
		copyRoute := *actual.route
		changed.route = &copyRoute
		mutate(changed.route)
		if _, err := ValidateProductionModelBinding(in, &changed, policy, expected); err == nil {
			t.Fatal("mutated adapter binding accepted")
		}
	}
	for _, invalid := range []*Bedrock{nil, {}, {route: &bedrockRoute{}}} {
		if _, err := ValidateProductionModelBinding(in, invalid, policy, expected); err == nil {
			t.Fatal("uninitialized adapter accepted")
		}
	}
}

func TestProductionModelBindingRejectsIncompleteOrUnsafePolicy(t *testing.T) {
	in, actual, policy := productionBindingFixture()
	expected := contracts.ExecutionDigest(in)
	for _, mutate := range []func(*ProductionModelPolicy){
		func(x *ProductionModelPolicy) { x.RouteID = "" },
		func(x *ProductionModelPolicy) { x.Provider = "development" },
		func(x *ProductionModelPolicy) { x.EffectiveEndpoint = "" },
		func(x *ProductionModelPolicy) { x.QuestionCatalogueID = "" },
		func(x *ProductionModelPolicy) { x.MaxTokens = 257 },
		func(x *ProductionModelPolicy) { x.AllowedClassifications = nil },
		func(x *ProductionModelPolicy) { x.AllowedClassifications = []string{"confidential", "restricted"} },
	} {
		changed := policy
		mutate(&changed)
		if _, err := ValidateProductionModelBinding(in, actual, changed, expected); err == nil {
			t.Fatal("incomplete or unsafe policy accepted")
		}
	}
}
