package model

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
	"net/http"
	"net/http/httptest"
	"testing"
)

type receiverAuthority struct {
	calls, completions int
	onAuthorize        func()
	readyError         error
	onReady            func()
}

func (a *receiverAuthority) AuthorizeEffect(context.Context, string, string) error {
	a.calls++
	if a.onAuthorize != nil {
		a.onAuthorize()
	}
	return nil
}
func (a *receiverAuthority) CompleteExecution(context.Context, string, string, any) error {
	a.completions++
	return nil
}
func (a *receiverAuthority) Readiness(context.Context) error {
	if a.onReady != nil {
		a.onReady()
	}
	return a.readyError
}

type recordingGenerator struct {
	calls   int
	binding ProviderBinding
	result  *contracts.GenerationResult
}

func (g *recordingGenerator) Binding() ProviderBinding { return g.binding }
func (g *recordingGenerator) Generate(ctx context.Context, in contracts.Generation) (contracts.GenerationResult, error) {
	g.calls++
	if g.result != nil {
		return *g.result, nil
	}
	return (SyntheticGenerator{}).Generate(ctx, in)
}
func qualifiedGeneration() contracts.Generation {
	return contracts.Generation{ManifestVersion: 3, OperationID: "operation-123", TenantID: "tenant-a", RouteID: "dev-model", Classification: "internal", Prompt: "Synthetic qualification context. Cite [record@v1].", MaxTokens: 256, Provider: contracts.QualificationProvider, Region: contracts.QualificationRegion, ModelID: contracts.QualificationModelID, EffectiveEndpoint: contracts.QualificationEndpoint, TemplateVersion: contracts.QualificationTemplate, QuestionCatalogueID: contracts.QualificationQuestionID, QuestionCatalogueVersion: contracts.QualificationQuestionVersion, QuestionClassification: contracts.QualificationQuestionClassification}
}
func modelRequest(t *testing.T, s *Service, in contracts.Generation, path, audience string) *httptest.ResponseRecorder {
	t.Helper()
	body, e := json.Marshal(in)
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("POST", path, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Capability "+broker.Token(s.Key, audience, body))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func modelFixture(t *testing.T) (*Service, *recordingGenerator, *receiverAuthority) {
	t.Helper()
	receipts, e := broker.OpenReceiptStore(t.TempDir(), "model")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { receipts.Close() })
	generator := &recordingGenerator{binding: (SyntheticGenerator{}).Binding()}
	authority := &receiverAuthority{}
	return &Service{Key: make([]byte, 32), Generator: generator, Receipts: receipts, Validate: authority, Profile: qualificationProfile, PeerCheck: func(*http.Request) error { return nil }}, generator, authority
}
func TestQualificationRouteAndAdapterSubstitutionsNeverReachProvider(t *testing.T) {
	for _, field := range []string{"version", "route", "provider", "region", "model", "endpoint", "features", "template", "question", "question_version", "question_classification", "classification", "limits", "actual_adapter"} {
		t.Run(field, func(t *testing.T) {
			s, g, a := modelFixture(t)
			in := qualifiedGeneration()
			switch field {
			case "version":
				in.ManifestVersion = 0
			case "route":
				in.RouteID = "other"
			case "provider":
				in.Provider = "bedrock"
			case "region":
				in.Region = "us-gov-west-1"
			case "model":
				in.ModelID = "other"
			case "endpoint":
				in.EffectiveEndpoint = "https://provider.invalid"
			case "features":
				in.Features = []string{"tools"}
			case "template":
				in.TemplateVersion = "other"
			case "question":
				in.QuestionCatalogueID = "other"
			case "question_version":
				in.QuestionCatalogueVersion = "other"
			case "question_classification":
				in.QuestionClassification = "public"
			case "classification":
				in.Classification = "public"
			case "limits":
				in.MaxTokens = 257
			case "actual_adapter":
				g.binding.Provider = "bedrock"
			}
			response := modelRequest(t, s, in, "/execute", "model.execute")
			if response.Code == 200 || g.calls != 0 || a.calls != 0 || a.completions != 0 {
				t.Fatalf("substitution reached authority/provider: HTTP=%d provider=%d auth=%d completed=%d", response.Code, g.calls, a.calls, a.completions)
			}
		})
	}
}
func TestQualificationStatusAndCompletedIdentity(t *testing.T) {
	s, g, a := modelFixture(t)
	in := qualifiedGeneration()
	if w := modelRequest(t, s, in, "/execute", "model.execute"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := modelRequest(t, s, in, "/status", "model.execute"); w.Code != 401 {
		t.Fatal("execute capability became status", w.Code)
	}
	if w := modelRequest(t, s, in, "/execute", "model.status"); w.Code != 401 {
		t.Fatal("status capability became execute", w.Code)
	}
	if w := modelRequest(t, s, in, "/status", "model.status"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if g.calls != 1 || a.calls != 1 || a.completions != 2 {
		t.Fatal("completed lookup repeated effect", g.calls, a.calls, a.completions)
	}
}
func TestQualificationProviderMismatchAndExpiredPeerRemainUnknown(t *testing.T) {
	for _, mode := range []string{"result_identity", "peer_expires", "custody_lost"} {
		t.Run(mode, func(t *testing.T) {
			s, g, a := modelFixture(t)
			in := qualifiedGeneration()
			expired := false
			s.PeerCheck = func(*http.Request) error {
				if expired {
					return errors.New("expired peer")
				}
				return nil
			}
			switch mode {
			case "result_identity":
				g.result = &contracts.GenerationResult{Text: "synthetic", Provider: "bedrock", ModelID: "other"}
			case "peer_expires":
				a.onAuthorize = func() { expired = true }
			case "custody_lost":
				a.onAuthorize = func() { s.Receipts.Close() }
			}
			w := modelRequest(t, s, in, "/execute", "model.execute")
			if w.Code == 200 || a.completions != 0 {
				t.Fatal("unverified result completed", w.Code, a.completions)
			}
			if _, e := s.Receipts.Inspect(in.OperationID, contracts.ExecutionDigest(in)); !errors.Is(e, broker.ErrUnknown) {
				t.Fatal("uncertain state was not retained", e)
			}
			expired = false
			g.result = nil
			if w = modelRequest(t, s, in, "/execute", "model.execute"); w.Code == 200 {
				t.Fatal("unknown effect retried")
			}
			expected := 0
			if mode == "result_identity" {
				expected = 1
			}
			if g.calls != expected || a.calls != 1 {
				t.Fatal("unknown effect repeated", g.calls, a.calls)
			}
		})
	}
}
func TestQualificationLivenessIsNotDependencyReadiness(t *testing.T) {
	s, _, a := modelFixture(t)
	a.readyError = errors.New("guard signer identity unavailable")
	health := httptest.NewRecorder()
	s.Handler().ServeHTTP(health, httptest.NewRequest("GET", "/healthz", nil))
	if health.Code != 200 {
		t.Fatal(health.Code)
	}
	ready := httptest.NewRecorder()
	s.Handler().ServeHTTP(ready, httptest.NewRequest("GET", "/readyz", nil))
	if ready.Code != 503 {
		t.Fatal("dependency failure reported ready", ready.Code)
	}
	s.PeerCheck = nil
	if w := modelRequest(t, s, qualifiedGeneration(), "/execute", "model.execute"); w.Code != 403 {
		t.Fatal("missing verified peer admitted", w.Code)
	}
}
func TestSupportedProfilesNeverConstructLiveProvider(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "synthetic-fixture-only")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "synthetic-fixture-only")
	for _, profile := range []string{"development", qualificationProfile} {
		if _, e := ConfiguredGenerator(profile, "bedrock"); e == nil {
			t.Fatal("live provider admitted", profile)
		}
		generator, e := ConfiguredGenerator(profile, "development")
		if e != nil {
			t.Fatal(e)
		}
		if _, ok := generator.(SyntheticGenerator); !ok {
			t.Fatal("non-synthetic provider selected")
		}
	}
	if _, e := ConfiguredGenerator("production", "development"); e == nil {
		t.Fatal("production opened")
	}
}

func TestQualificationRejectsActualSDKAdapterBeforeConverse(t *testing.T) {
	s, _, authority := modelFixture(t)
	provider := &converseStub{}
	s.Generator = &Bedrock{Client: provider, Region: "us-gov-west-1", ModelARN: "arn:aws-us-gov:bedrock:us-gov-west-1::foundation-model/synthetic-test-model-v1"}
	response := modelRequest(t, s, qualifiedGeneration(), "/execute", "model.execute")
	if response.Code == 200 || provider.calls != 0 || authority.calls != 0 {
		t.Fatal("SDK adapter reached from synthetic profile", response.Code, provider.calls, authority.calls)
	}
}

func TestReadinessRechecksRequesterAfterDependency(t *testing.T) {
	s, _, a := modelFixture(t)
	expired := false
	s.PeerCheck = func(*http.Request) error {
		if expired {
			return errors.New("expired")
		}
		return nil
	}
	a.onReady = func() { expired = true }
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/readyz", nil))
	if response.Code != 503 {
		t.Fatal("expired requester received readiness", response.Code)
	}
}
