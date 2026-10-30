package model

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"

	"github.com/5dg/nex-os/packages/contracts"
)

// ProductionModelPolicy must come from trusted, independently approved service
// configuration. It is not populated from the request being validated.
type ProductionModelPolicy struct {
	RouteID                  string
	Provider                 string
	Region                   string
	ModelID                  string
	EffectiveEndpoint        string
	TemplateVersion          string
	QuestionCatalogueID      string
	QuestionCatalogueVersion string
	QuestionClassification   string
	AllowedClassifications   []string
	MaxTokens                int
}

// ValidateProductionModelBinding checks a v3 payload against a trusted policy,
// the actual verified adapter binding and the digest obtained independently
// from an authenticated Guard manifest. It does not authenticate the manifest,
// authorize an effect, validate workload identity or enable a runtime profile.
func ValidateProductionModelBinding(in contracts.Generation, adapter *Bedrock, policy ProductionModelPolicy, authorizedDigest string) (string, error) {
	denied := errors.New("production model binding denied")
	if !adapter.validRoute() {
		return "", denied
	}
	actual := adapter.Binding()
	if policy.RouteID == "" || policy.Provider != "bedrock" || policy.Region == "" || policy.ModelID == "" || policy.EffectiveEndpoint == "" ||
		policy.TemplateVersion == "" || policy.QuestionCatalogueID == "" || policy.QuestionCatalogueVersion == "" || policy.QuestionClassification == "" ||
		policy.MaxTokens < 1 || policy.MaxTokens > 256 || len(policy.AllowedClassifications) == 0 {
		return "", denied
	}
	allowed := false
	for _, classification := range policy.AllowedClassifications {
		if classification != "public" && classification != "internal" && classification != "confidential" {
			return "", denied
		}
		if in.Classification == classification {
			allowed = true
		}
	}
	classification, err := contracts.AggregateClassification(in.Classification, in.QuestionClassification)
	if err != nil || classification != in.Classification || !allowed || in.ManifestVersion != 3 || in.OperationID == "" || in.TenantID == "" ||
		in.RouteID != policy.RouteID || in.Provider != policy.Provider || in.Region != policy.Region || in.ModelID != policy.ModelID || in.EffectiveEndpoint != policy.EffectiveEndpoint ||
		in.TemplateVersion != policy.TemplateVersion || in.QuestionCatalogueID != policy.QuestionCatalogueID || in.QuestionCatalogueVersion != policy.QuestionCatalogueVersion || in.QuestionClassification != policy.QuestionClassification ||
		in.MaxTokens < 1 || in.MaxTokens > policy.MaxTokens || in.Prompt == "" || len(in.Prompt) > 6000 || len(in.Features) != 0 ||
		actual.Provider != policy.Provider || actual.Region != policy.Region || actual.ModelID != policy.ModelID || actual.EffectiveEndpoint != policy.EffectiveEndpoint || len(actual.Features) != 0 {
		return "", denied
	}
	decoded, err := hex.DecodeString(authorizedDigest)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != authorizedDigest {
		return "", denied
	}
	digest := contracts.ExecutionDigest(in)
	computed, err := hex.DecodeString(digest)
	if err != nil || len(computed) != 32 || subtle.ConstantTimeCompare(computed, decoded) != 1 {
		return "", denied
	}
	return digest, nil
}
