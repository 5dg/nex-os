package executor

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
	"net/http"
	"time"
)

type Service struct {
	Key       []byte
	Receipts  broker.ReceiptStore
	Validate  broker.ExecutionAuthority
	Profile   string
	PeerCheck func(*http.Request) error
}

func (s *Service) peer(r *http.Request) error {
	if s.Profile != "" && s.Profile != "development" && s.Profile != "synthetic-qualification" {
		return errors.New("unknown execution profile")
	}
	if e := r.Context().Err(); e != nil {
		return e
	}
	if s.Profile == "synthetic-qualification" {
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
	if s.Validate == nil {
		return errors.New("receiver dependency required")
	}
	if s.Profile == "synthetic-qualification" {
		if len(s.Key) != 32 {
			return errors.New("receiver capability key required")
		}
		if e := s.Receipts.Ready(); e != nil {
			return e
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
		if s.Profile == "synthetic-qualification" {
			if s.peer(r) != nil {
				http.Error(w, "peer denied", 403)
				return
			}
			w.Header().Set("Allow", "POST")
			http.Error(w, "authenticated readiness proof required", 405)
			return
		}
		if s.ready(r) != nil {
			http.Error(w, "receiver unavailable", 503)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	})
	mux.HandleFunc("POST /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		if s.Profile != "synthetic-qualification" {
			http.NotFound(w, r)
			return
		}
		if s.peer(r) != nil {
			http.Error(w, "peer denied", 403)
			return
		}
		if len(s.Key) != 32 {
			http.Error(w, "receiver configuration unavailable", 503)
			return
		}
		var in broker.ReadinessRequest
		if !broker.ReadLimit(w, r, s.Key, "export.ready", &in, 4096) {
			return
		}
		if !broker.ValidNonce(in.Nonce) {
			http.Error(w, "invalid readiness nonce", 400)
			return
		}
		if s.ready(r) != nil {
			http.Error(w, "receiver unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(broker.ReadinessResponse{Ready: true, Profile: s.Profile, Nonce: in.Nonce})
	})
	for _, path := range []string{"/execute", "/status"} {
		mux.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
			if s.peer(r) != nil {
				http.Error(w, "peer denied", 403)
				return
			}
			if s.Profile == "synthetic-qualification" && len(s.Key) != 32 {
				http.Error(w, "receiver configuration unavailable", 503)
				return
			}
			var in contracts.Export
			audience := "export.execute"
			if s.Profile == "synthetic-qualification" && r.URL.Path == "/status" {
				audience = "export.status"
			}
			if !broker.ReadLimit(w, r, s.Key, audience, &in, 128*1024) {
				return
			}
			if in.DestinationID != "local-evidence" || in.TenantID == "" || in.RequestDigest == "" || len(in.Content) == 0 || len(in.Content) > 13000 {
				outcome := broker.ErrNotStarted
				if s.Profile == "synthetic-qualification" {
					outcome = broker.ErrUnknown
				}
				broker.WriteError(w, outcome)
				return
			}
			if s.Profile == "synthetic-qualification" {
				if in.ManifestVersion != 3 || s.Receipts.Ready() != nil {
					broker.WriteError(w, broker.ErrUnknown)
					return
				}
			} else if in.ManifestVersion != 0 && in.ManifestVersion != 2 {
				broker.WriteError(w, broker.ErrNotStarted)
				return
			}
			if s.Validate == nil {
				broker.WriteError(w, broker.ErrUnknown)
				return
			}
			digest := contracts.ExecutionDigest(in)
			var out json.RawMessage
			var e error
			if r.URL.Path == "/status" {
				out, e = s.Receipts.Inspect(in.OperationID, digest)
			} else {
				out, e = s.Receipts.DoAuthorized(in.OperationID, digest, func() error {
					return s.Validate.AuthorizeEffect(r.Context(), in.OperationID, digest)
				}, func() (any, error) {
					if e := s.peer(r); e != nil {
						return nil, e
					}
					if s.Profile == "synthetic-qualification" {
						if e := s.Receipts.CheckCustody(); e != nil {
							return nil, e
						}
					}
					// The durable completed receipt is the local artifact. No caller URLs/paths.
					return map[string]any{"artifact_id": in.OperationID, "content_digest": broker.Hash([]byte(in.Content)), "content": in.Content}, nil
				})
			}
			if e != nil {
				broker.WriteError(w, e)
				return
			}
			var stored struct {
				contracts.ExportResult
				Content string `json:"content"`
			}
			if json.Unmarshal(out, &stored) != nil || stored.ArtifactID != in.OperationID || stored.Content != in.Content || stored.ContentDigest != broker.Hash([]byte(stored.Content)) {
				broker.WriteError(w, broker.ErrUnknown)
				return
			}
			if s.peer(r) != nil {
				broker.WriteError(w, broker.ErrUnknown)
				return
			}
			artifact := stored.ExportResult
			if e = s.Validate.CompleteExecution(r.Context(), in.OperationID, digest, artifact); e != nil {
				broker.WriteError(w, broker.ErrUnknown)
				return
			}
			if s.peer(r) != nil {
				broker.WriteError(w, broker.ErrUnknown)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(artifact)
		})
	}
	return mux
}
