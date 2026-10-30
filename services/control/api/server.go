package api

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
	"github.com/5dg/nex-os/packages/trust"
	"github.com/5dg/nex-os/services/control/auth"
	"github.com/5dg/nex-os/services/control/guard"
	"github.com/5dg/nex-os/services/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Server struct {
	Profile            trust.Profile
	Trust              *trust.Config
	DB                 *pgxpool.Pool
	Auth               *auth.Verifier
	Policy             *guard.Client
	Model              model.Adapter
	Environment        string
	WorkerKey          []byte
	ModelRPC, ToolRPC  *broker.Client
	EvidenceRPC        *broker.Client
	EvidencePublic     []byte
	historySecretOnce  sync.Once
	historySecret      [32]byte
	historyPrevious    [32]byte
	historyHasPrevious bool
}

var errMembership = errors.New("registered tenant membership required")

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { respond(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		probe, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if s.qualification() && (s.Trust == nil || s.ModelRPC == nil || s.ToolRPC == nil || s.EvidenceRPC == nil || len(s.WorkerKey) != 32) {
			fail(w, 503, "CONFIGURATION_UNAVAILABLE", "Required qualification dependency absent")
			return
		}
		if s.dependenciesReady(probe) != nil {
			fail(w, 503, "DEPENDENCY_UNAVAILABLE", "Required dependency unavailable")
			return
		}
		if s.qualification() {
			if e := s.Trust.CheckPeer(r.TLS, []trust.Role{trust.Workspace}); e != nil {
				fail(w, 503, "IDENTITY_UNAVAILABLE", "Current qualification identity unavailable")
				return
			}
		}
		respond(w, 200, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]any{"environment": s.Environment, "profile": string(s.profile()), "model_provider": "development", "synthetic_data_only": true, "milestone": "local-review-export", "guard_runtime": "rust-grpc"})
	})
	mux.HandleFunc("GET /v1/me", s.me)
	mux.HandleFunc("POST /v1/actions/authorize", s.authorize)
	mux.HandleFunc("POST /v1/models/invoke", s.invoke)
	s.workflowRoutes(mux)
	handler := s.qualifiedHandler(mux)
	admission := make(chan struct{}, 32)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.qualification() {
			select {
			case admission <- struct{}{}:
				defer func() { <-admission }()
			default:
				fail(w, 503, "ADMISSION_LIMIT", "Service request capacity unavailable")
				return
			}
		}
		timeout := 60 * time.Second
		if s.qualification() && !strings.HasSuffix(r.URL.Path, "/step") {
			timeout = 15 * time.Second
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		fail(w, 415, "UNSUPPORTED_MEDIA_TYPE", "Use application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		fail(w, 400, "INVALID_REQUEST", "Invalid request schema")
		return false
	}
	if d.Decode(&struct{}{}) != io.EOF {
		fail(w, 400, "INVALID_REQUEST", "One JSON object required")
		return false
	}
	return true
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	if s.qualification() {
		fail(w, 404, "NOT_AVAILABLE", "Direct development route unavailable")
		return
	}
	identity, err := s.Auth.Verify(r)
	if err != nil {
		fail(w, 401, "UNAUTHENTICATED", "Valid bearer token required")
		return
	}
	var in contracts.ActionRequest
	if !decode(w, r, &in) {
		return
	}
	if in.DelegationID == "" || in.Action == "" || in.ResourceID == "" {
		fail(w, 400, "INVALID_REQUEST", "Action, delegation and resource required")
		return
	}
	d, err := s.decide(r.Context(), identity, in)
	if errors.Is(err, errMembership) {
		fail(w, 403, "MEMBERSHIP_REQUIRED", "Registered tenant membership required")
		return
	}
	if err != nil {
		fail(w, 503, "DEPENDENCY_UNAVAILABLE", "Authorization evidence could not be completed")
		return
	}
	status := 200
	if d.Effect == "deny" {
		status = 403
	}
	respond(w, status, d)
}

func (s *Server) invoke(w http.ResponseWriter, r *http.Request) {
	if s.Environment != "development" || s.qualification() {
		fail(w, 404, "NOT_AVAILABLE", "Direct development route unavailable")
		return
	}
	identity, err := s.Auth.Verify(r)
	if err != nil {
		fail(w, 401, "UNAUTHENTICATED", "Valid bearer token required")
		return
	}
	var in contracts.ModelInvocation
	if !decode(w, r, &in) {
		return
	}
	if in.ResourceID != "dev-model" || in.DelegationID == "" || len(in.Prompt) < 1 || len(in.Prompt) > 4096 || in.MaxOutputTokens < 1 || in.MaxOutputTokens > 256 {
		fail(w, 400, "INVALID_REQUEST", "Unknown development route or invalid limits")
		return
	}
	d, err := s.decide(r.Context(), identity, contracts.ActionRequest{DelegationID: in.DelegationID, Action: "model.invoke", ResourceID: in.ResourceID})
	if errors.Is(err, errMembership) {
		fail(w, 403, "MEMBERSHIP_REQUIRED", "Registered tenant membership required")
		return
	}
	if err != nil {
		fail(w, 503, "DEPENDENCY_UNAVAILABLE", "Authorization evidence could not be completed")
		return
	}
	if d.Effect != "allow" {
		respond(w, 403, d)
		return
	}
	out, err := s.Model.Invoke(in)
	if err != nil {
		fail(w, 502, "MODEL_UNAVAILABLE", "Model route unavailable")
		return
	}
	out.DecisionID = d.ID
	respond(w, 200, out)
}

func (s *Server) decide(ctx context.Context, id auth.Identity, req contracts.ActionRequest) (contracts.Decision, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return contracts.Decision{}, err
	}
	defer tx.Rollback(ctx)
	var actor guard.Actor
	err = tx.QueryRow(ctx, `SELECT id,tenant_id,permissions FROM users WHERE issuer=$1 AND subject=$2 FOR SHARE`, id.Issuer, id.Subject).Scan(&actor.ID, &actor.TenantID, &actor.Permissions)
	if errors.Is(err, pgx.ErrNoRows) {
		return contracts.Decision{}, errMembership
	}
	if err != nil {
		return contracts.Decision{}, err
	}
	input := guard.Input{Actor: actor, Action: req.Action, DataClassification: "public", DelegationPermissions: []string{}, Resource: guard.Resource{ReaderIDs: []string{}, ApprovedClassifications: []string{}}}
	var expiry time.Time
	var revoked *time.Time
	err = tx.QueryRow(ctx, `SELECT permissions,expires_at,revoked_at FROM delegations WHERE id=$1 AND tenant_id=$2 AND user_id=$3 FOR SHARE`, req.DelegationID, actor.TenantID, actor.ID).Scan(&input.DelegationPermissions, &expiry, &revoked)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return contracts.Decision{}, err
	}
	input.DelegationValid = err == nil && revoked == nil && time.Now().Before(expiry)
	err = tx.QueryRow(ctx, `SELECT tenant_id,kind,classification,reader_ids FROM resources WHERE tenant_id=$1 AND id=$2 FOR SHARE`, actor.TenantID, req.ResourceID).Scan(&input.Resource.TenantID, &input.Resource.Kind, &input.Resource.Classification, &input.Resource.ReaderIDs)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return contracts.Decision{}, err
	}
	decision, err := s.Policy.Evaluate(ctx, input)
	if err != nil {
		return contracts.Decision{}, err
	}
	decision.ID = rand.Text()
	b, _ := json.Marshal(decision)
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(id,tenant_id,actor_id,delegation_id,resource_id,action,decision) VALUES($1,$2,$3,$4,$5,$6,$7)`, decision.ID, actor.TenantID, actor.ID, req.DelegationID, req.ResourceID, req.Action, b); err != nil {
		return contracts.Decision{}, err
	}
	if err = s.anchor(ctx, tx, decision.ID); err != nil {
		return contracts.Decision{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return contracts.Decision{}, err
	}
	return decision, nil
}

func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, code, message string) {
	respond(w, status, contracts.Error{Code: code, Message: message, RequestID: rand.Text()})
}
