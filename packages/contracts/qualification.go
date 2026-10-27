package contracts

import "errors"

const QualificationManifestVersion = 3
const QualificationProvider = "development"
const QualificationRegion = "local"
const QualificationModelID = "deterministic-review-v1"
const QualificationEndpoint = "local://synthetic-generator"
const QualificationTemplate = "review-template-v2"
const QualificationQuestionID = "access-review-controls"
const QualificationQuestionVersion = "v1"
const QualificationQuestion = "What access review and export controls apply?"
const QualificationQuestionClassification = "internal"

// The fixed synthetic tuple is a closed admission contract, not a route registry.
func ValidateQualificationGeneration(x Generation) error {
	if x.ManifestVersion != 3 || x.RouteID != "dev-model" || x.Provider != QualificationProvider || x.Region != QualificationRegion || x.ModelID != QualificationModelID || x.EffectiveEndpoint != QualificationEndpoint || len(x.Features) != 0 || x.TemplateVersion != QualificationTemplate || x.QuestionCatalogueID != QualificationQuestionID || x.QuestionCatalogueVersion != QualificationQuestionVersion || x.QuestionClassification != QualificationQuestionClassification || x.MaxTokens != 256 || x.Prompt == "" || len(x.Prompt) > 6000 || (x.Classification != "internal" && x.Classification != "confidential") {
		return errors.New("synthetic qualification route, input admission or limits denied")
	}
	return nil
}
func AggregateClassification(document, question string) (string, error) {
	levels := map[string]int{"public": 0, "internal": 1, "confidential": 2}
	a, ok := levels[document]
	if !ok {
		return "", errors.New("document classification denied")
	}
	b, ok := levels[question]
	if !ok {
		return "", errors.New("question classification denied")
	}
	if b > a {
		return question, nil
	}
	return document, nil
}
