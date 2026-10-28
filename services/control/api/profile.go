package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
	"github.com/5dg/nex-os/packages/trust"
	"github.com/jackc/pgx/v5"
)

func (s *Server) qualification() bool { return s.Profile == trust.Qualification }
func (s *Server) profile() trust.Profile {
	if s.Profile == "" {
		return trust.Development
	}
	return s.Profile
}
func (s *Server) begin(ctx context.Context) (pgx.Tx, error) {
	if !s.qualification() {
		return s.DB.Begin(ctx)
	}
	if e := s.currentRequest(ctx); e != nil {
		return nil, e
	}
	acquire, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tx, e := s.DB.Begin(acquire)
	if e != nil {
		return nil, e
	}
	if e = s.currentRequest(ctx); e != nil {
		_ = tx.Rollback(ctx)
		return nil, e
	}
	return requestTx{Tx: tx, check: func() error { return s.currentRequest(ctx) }}, nil
}
func (s *Server) qualifiedHandler(next http.Handler) http.Handler {
	if !s.qualification() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Trust == nil || s.Trust.Profile != trust.Qualification || s.Trust.Role != trust.Control {
			fail(w, 503, "CONFIGURATION_UNAVAILABLE", "Qualification identity unavailable")
			return
		}
		var roles []trust.Role
		switch {
		case r.URL.Path == "/healthz": // Minimal liveness still requires mTLS.
		case strings.HasPrefix(r.URL.Path, "/internal/work/"):
			roles = []trust.Role{trust.Worker}
		default:
			roles = []trust.Role{trust.Workspace}
		}
		s.Trust.Middleware(roles, next).ServeHTTP(w, s.withRequestAuthority(r, roles))
	})
}
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	identity, e := s.Auth.Verify(r)
	if e != nil {
		fail(w, 401, "UNAUTHENTICATED", "Valid API credential required")
		return
	}
	tx, e := s.begin(r.Context())
	if e != nil {
		workflowError(w, e)
		return
	}
	defer tx.Rollback(r.Context())
	actor, e := actorFor(r.Context(), tx, identity)
	if e != nil {
		workflowError(w, e)
		return
	}
	var delegation string
	e = tx.QueryRow(r.Context(), `SELECT id FROM delegations WHERE tenant_id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>clock_timestamp() ORDER BY id LIMIT 1`, actor.TenantID, actor.ID).Scan(&delegation)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		workflowError(w, e)
		return
	}
	if e = tx.Commit(r.Context()); e != nil {
		workflowError(w, e)
		return
	}
	respond(w, 200, contracts.IdentityView{Issuer: identity.Issuer, Subject: identity.Subject, UserID: actor.ID, TenantID: actor.TenantID, DelegationID: delegation, Permissions: actor.Permissions})
}
func (s *Server) qualificationQuestion(ctx context.Context, tx pgx.Tx) (string, string, error) {
	var text, class string
	e := tx.QueryRow(ctx, `SELECT question,classification FROM question_catalogue WHERE id=$1 AND version=$2 AND enabled`, contracts.QualificationQuestionID, contracts.QualificationQuestionVersion).Scan(&text, &class)
	if errors.Is(e, pgx.ErrNoRows) {
		return "", "", errForbidden
	}
	if e != nil {
		return "", "", e
	}
	if text != contracts.QualificationQuestion || class != contracts.QualificationQuestionClassification {
		return "", "", errForbidden
	}
	return text, class, nil
}
func (s *Server) qualificationAdmission(ctx context.Context, tx pgx.Tx, j storedJob, content, class string) (string, error) {
	if j.ExecutionProfile != string(trust.Qualification) || j.QuestionCatalogueID != contracts.QualificationQuestionID || j.QuestionCatalogueVersion != contracts.QualificationQuestionVersion {
		return "", errForbidden
	}
	question, qclass, e := s.qualificationQuestion(ctx, tx)
	if e != nil {
		return "", e
	}
	if question != j.Question {
		return "", errForbidden
	}
	var admitted bool
	e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM document_admissions WHERE tenant_id=$1 AND resource_id=$2 AND version=$3 AND content_digest=$4 AND profile=$5)`, j.TenantID, j.DocumentID, j.DocumentVersion, broker.Hash([]byte(content)), string(trust.Qualification)).Scan(&admitted)
	if e != nil {
		return "", e
	}
	if !admitted {
		return "", errForbidden
	}
	return contracts.AggregateClassification(class, qclass)
}
