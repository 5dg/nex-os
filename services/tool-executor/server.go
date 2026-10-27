package executor

import (
	"encoding/json"
	"errors"
	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
	"net/http"
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
		if s.peer(r) != nil || s.Validate == nil {
			http.Error(w, "receiver unavailable", 503)
			return
		}
		if s.Profile == "synthetic-qualification" && (s.Receipts.Ready() != nil || s.Validate.Readiness(r.Context()) != nil) {
			http.Error(w, "receiver unavailable", 503)
			return
		}
		if s.peer(r) != nil || (s.Profile == "synthetic-qualification" && s.Receipts.CheckCustody() != nil) {
			http.Error(w, "receiver unavailable", 503)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	})
	for _, path := range []string{"/execute", "/status"} {
		mux.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
			if s.peer(r) != nil {
				http.Error(w, "peer denied", 403)
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
