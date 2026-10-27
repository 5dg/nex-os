package model

import (
	"errors"
	"github.com/5dg/nex-os/packages/contracts"
)

const qualificationProfile = "synthetic-qualification"

type ProviderBinding struct {
	Provider          string
	Region            string
	ModelID           string
	EffectiveEndpoint string
	Features          []string
}
type BoundGenerator interface {
	Generator
	Binding() ProviderBinding
}

func (SyntheticGenerator) Binding() ProviderBinding {
	return ProviderBinding{Provider: contracts.QualificationProvider, Region: contracts.QualificationRegion, ModelID: contracts.QualificationModelID, EffectiveEndpoint: contracts.QualificationEndpoint}
}
func (b *Bedrock) Binding() ProviderBinding {
	// No Bedrock binding is admitted to the synthetic qualification profile. A
	// future live profile must bind the SDK's resolved endpoint as well as its ARN.
	return ProviderBinding{Provider: "bedrock", Region: b.Region, ModelID: b.ModelARN, EffectiveEndpoint: "aws://bedrock-runtime/" + b.Region}
}
func validateQualificationBinding(in contracts.Generation, g Generator) error {
	if e := contracts.ValidateQualificationGeneration(in); e != nil {
		return e
	}
	bound, ok := g.(BoundGenerator)
	if !ok {
		return errors.New("bound synthetic generator required")
	}
	actual := bound.Binding()
	if actual.Provider != in.Provider || actual.Region != in.Region || actual.ModelID != in.ModelID || actual.EffectiveEndpoint != in.EffectiveEndpoint || len(actual.Features) != 0 {
		return errors.New("configured provider differs from sealed route")
	}
	return nil
}
