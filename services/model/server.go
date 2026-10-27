package model

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"

	"net/http"
	"strings"
)

type Generator interface {
	Generate(context.Context, contracts.Generation) (contracts.GenerationResult, error)
}
type SyntheticGenerator struct{}

func (SyntheticGenerator) Generate(ctx context.Context, in contracts.Generation) (contracts.GenerationResult, error) {
	if in.MaxTokens < 1 || in.MaxTokens > 256 || len(in.Prompt) == 0 || len(in.Prompt) > 6000 || in.Classification == "restricted" {
		return contracts.GenerationResult{}, errors.New("request limits exceeded")
	}
	// Deterministic and labeled. It deliberately never interprets document text as
	// executable instructions or claims to provide real model reasoning.
	citation := ""
	if start := strings.Index(in.Prompt, "Cite ["); start >= 0 {
		remaining := in.Prompt[start+6:]
		if end := strings.Index(remaining, "]"); end >= 0 {
			citation = "[" + remaining[:end+1]
		}
	}
	return contracts.GenerationResult{Text: "SYNTHETIC DEVELOPMENT REVIEW: The sample record requires quarterly access reviews and independent approval before evidence export. " + citation, Provider: "development", ModelID: "deterministic-review-v1"}, nil
}

type Service struct {
	Key       []byte
	Generator Generator
	Receipts  broker.ReceiptStore
	Validate  broker.ExecutionAuthority
	Profile   string
	PeerCheck func(*http.Request) error
}

func (s *Service) peer(r *http.Request) error {
	if s.Profile != "" && s.Profile != "development" && s.Profile != qualificationProfile {
		return errors.New("unknown execution profile")
	}
	if e := r.Context().Err(); e != nil {
		return e
	}
	if s.Profile == qualificationProfile {
		if s.PeerCheck == nil {
			return errors.New("verified control peer required")
		}
		return s.PeerCheck(r)
	}
	return nil
}
func (s *Service) ready(r *http.Request) error {
	if e := s.peer(r); e != nil {
		return e
	}
	if s.Validate == nil || s.Generator == nil {
		return errors.New("receiver dependencies required")
	}
	if s.Profile == qualificationProfile {
		if e := s.Receipts.Ready(); e != nil {
			return e
		}
		bound, ok := s.Generator.(BoundGenerator)
		if !ok {
			return errors.New("bound generator required")
		}
		actual := bound.Binding()
		if actual.Provider != contracts.QualificationProvider || actual.Region != contracts.QualificationRegion || actual.ModelID != contracts.QualificationModelID || actual.EffectiveEndpoint != contracts.QualificationEndpoint || len(actual.Features) != 0 {
			return errors.New("synthetic generator required")
		}
		if e := s.Validate.Readiness(r.Context()); e != nil {
			return e
		}
		if e := s.Receipts.CheckCustody(); e != nil {
			return e
		}
		return s.peer(r)
	}
	return nil
}
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if s.peer(r) != nil {
			http.Error(w, "peer denied", 403)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if s.ready(r) != nil {
			http.Error(w, "receiver unavailable", 503)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	})
	execute := func(w http.ResponseWriter, r *http.Request) {
		if s.peer(r) != nil {
			http.Error(w, "peer denied", 403)
			return
		}
		var in contracts.Generation
		audience := "model.execute"
		if s.Profile == qualificationProfile && r.URL.Path == "/status" {
			audience = "model.status"
		}
		if !broker.ReadLimit(w, r, s.Key, audience, &in, 128*1024) {
			return
		}
		if in.RouteID != "dev-model" || in.OperationID == "" || in.TenantID == "" {
			outcome := broker.ErrNotStarted
			if s.Profile == qualificationProfile {
				outcome = broker.ErrUnknown
			}
			broker.WriteError(w, outcome)
			return
		}
		if s.Profile == qualificationProfile {
			if s.Receipts.Ready() != nil || validateQualificationBinding(in, s.Generator) != nil {
				broker.WriteError(w, broker.ErrUnknown)
				return
			}
		} else if in.ManifestVersion != 0 && in.ManifestVersion != 2 {
			broker.WriteError(w, broker.ErrNotStarted)
			return
		}
		if s.Validate == nil || s.Generator == nil {
			broker.WriteError(w, broker.ErrUnknown)
			return
		}
		digest := contracts.ExecutionDigest(in)
		if digest == "" {
			broker.WriteError(w, broker.ErrNotStarted)
			return
		}
		var out json.RawMessage
		var e error
		if r.URL.Path == "/status" {
			out, e = s.Receipts.Inspect(in.OperationID, digest)
		} else {
			out, e = s.Receipts.DoAuthorized(in.OperationID, digest, func() error { return s.Validate.AuthorizeEffect(r.Context(), in.OperationID, digest) }, func() (any, error) {
				if e := s.peer(r); e != nil {
					return nil, e
				}
				if s.Profile == qualificationProfile {
					if e := s.Receipts.CheckCustody(); e != nil {
						return nil, e
					}
					if e := validateQualificationBinding(in, s.Generator); e != nil {
						return nil, e
					}
				}
				result, e := s.Generator.Generate(r.Context(), in)
				if e == nil && s.Profile == qualificationProfile && (result.Provider != in.Provider || result.ModelID != in.ModelID) {
					return nil, errors.New("provider result identity differs from sealed route")
				}
				return result, e
			})
		}
		if e != nil {
			broker.WriteError(w, e)
			return
		}
		var result contracts.GenerationResult
		if json.Unmarshal(out, &result) != nil || (s.Profile == qualificationProfile && (result.Provider != in.Provider || result.ModelID != in.ModelID)) {
			broker.WriteError(w, broker.ErrUnknown)
			return
		}
		if s.peer(r) != nil {
			broker.WriteError(w, broker.ErrUnknown)
			return
		}
		if e = s.Validate.CompleteExecution(r.Context(), in.OperationID, digest, result); e != nil {
			broker.WriteError(w, broker.ErrUnknown)
			return
		}
		if s.peer(r) != nil {
			broker.WriteError(w, broker.ErrUnknown)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	}
	mux.HandleFunc("POST /execute", execute)
	mux.HandleFunc("POST /status", execute)
	return mux
}
