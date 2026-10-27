package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
	"github.com/5dg/nex-os/packages/evidence"
	"github.com/5dg/nex-os/services/control/guard"
	"github.com/jackc/pgx/v5"
	"net/http"
	"slices"
	"time"
)

func (s *Server) workflowRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/jobs", s.createJob)
	mux.HandleFunc("GET /v1/jobs/{id}", s.getJob)
	mux.HandleFunc("POST /v1/jobs/{id}/cancel", s.cancelJob)
	mux.HandleFunc("POST /v1/jobs/{id}/reconcile", s.reconcileJob)
	mux.HandleFunc("POST /v1/jobs/{id}/retry", s.retryJob)
	mux.HandleFunc("POST /v1/jobs/{id}/export", s.requestExport)
	mux.HandleFunc("GET /v1/jobs/{id}/events", s.jobEvents)
	mux.HandleFunc("GET /v1/approvals", s.listApprovals)
	mux.HandleFunc("POST /v1/approvals/{id}/decision", s.approve)
	mux.HandleFunc("GET /v1/documents", s.documents)
	mux.HandleFunc("POST /internal/work/claim", s.claim)
	mux.HandleFunc("POST /internal/work/{id}/step", s.step)

}
func workflowError(w http.ResponseWriter, e error) {
	if errors.Is(e, errForbidden) || errors.Is(e, guard.ErrDenied) {
		fail(w, 403, "DENIED_BY_POLICY", "Current identity, delegation or resource access does not permit this operation")
		return
	}
	if errors.Is(e, errConflict) {
		fail(w, 409, "STATE_CONFLICT", "Operation content or current state conflicts with this request")
		return
	}
	fail(w, 503, "DEPENDENCY_UNAVAILABLE", "Required operation or evidence dependency unavailable")
}
func (s *Server) userTx(w http.ResponseWriter, r *http.Request) (pgx.Tx, guard.Actor, bool) {
	id, e := s.Auth.Verify(r)
	if e != nil {
		fail(w, 401, "UNAUTHENTICATED", "Valid bearer token required")
		return nil, guard.Actor{}, false
	}
	tx, e := s.begin(r.Context())
	if e != nil {
		workflowError(w, e)
		return nil, guard.Actor{}, false
	}
	a, e := actorFor(r.Context(), tx, id)
	if e != nil {
		tx.Rollback(r.Context())
		workflowError(w, e)
		return nil, a, false
	}
	return tx, a, true
}
func (s *Server) createJob(w http.ResponseWriter, r *http.Request) {
	tx, a, ok := s.userTx(w, r)
	if !ok {
		return
	}
	defer tx.Rollback(r.Context())
	var in contracts.CreateJob
	if !decode(w, r, &in) {
		return
	}
	if s.qualification() {
		if in.Question != "" || in.QuestionCatalogueID != contracts.QualificationQuestionID {
			fail(w, 400, "INPUT_ADMISSION_REQUIRED", "Select the server-owned synthetic question")
			return
		}
		var e error
		in.Question, _, e = s.qualificationQuestion(r.Context(), tx)
		if e != nil {
			workflowError(w, e)
			return
		}
	} else if in.QuestionCatalogueID != "" {
		fail(w, 400, "INVALID_REQUEST", "Question catalogue requires qualification profile")
		return
	}
	if len(in.Question) < 1 || len(in.Question) > 1000 || len(in.IdempotencyKey) < 8 || len(in.IdempotencyKey) > 100 || in.DelegationID == "" || in.DocumentID == "" {
		fail(w, 400, "INVALID_REQUEST", "Question, document, delegation and bounded idempotency key required")
		return
	}
	b, _ := json.Marshal(in)
	digest := broker.Hash(b)
	// Serialize identical create keys before checking/inserting, including concurrent requests.
	if _, e := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, a.TenantID+"/"+a.ID+"/"+in.IdempotencyKey); e != nil {
		workflowError(w, e)
		return
	}
	var oldID, oldDigest string
	e := tx.QueryRow(r.Context(), `SELECT id,request_digest FROM jobs WHERE tenant_id=$1 AND owner_id=$2 AND idempotency_key=$3`, a.TenantID, a.ID, in.IdempotencyKey).Scan(&oldID, &oldDigest)
	if e == nil {
		if oldDigest != digest {
			workflowError(w, errConflict)
			return
		}
		tx.Commit(r.Context())
		r.SetPathValue("id", oldID)
		s.getJob(w, r)
		return
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		workflowError(w, e)
		return
	}
	j := storedJob{ReviewJob: contracts.ReviewJob{ID: rand.Text(), TenantID: a.TenantID, State: "queued", Phase: "review", DocumentID: in.DocumentID, Question: in.Question}, Owner: a.ID, Delegation: in.DelegationID, Operation: rand.Text(), ExecutionProfile: string(s.profile())}
	if s.qualification() {
		j.QuestionCatalogueID = contracts.QualificationQuestionID
		j.QuestionCatalogueVersion = contracts.QualificationQuestionVersion
	}
	if _, e = tx.Exec(r.Context(), `SELECT set_config('nex.job_id',$1,true)`, j.ID); e != nil {
		workflowError(w, e)
		return
	}
	d, e := s.evaluateTx(r.Context(), tx, a, j.Delegation, "document.read", j.DocumentID, "public", false)
	if e == nil && d.Effect != "allow" {
		e = errForbidden
	}
	if e != nil {
		workflowError(w, finishDenied(r.Context(), tx, e))
		return
	}
	e = tx.QueryRow(r.Context(), `SELECT r.version FROM resources r JOIN document_bodies b ON b.tenant_id=r.tenant_id AND b.resource_id=r.id WHERE r.tenant_id=$1 AND r.id=$2`, a.TenantID, in.DocumentID).Scan(&j.DocumentVersion)
	if e != nil {
		workflowError(w, errForbidden)
		return
	}
	if s.qualification() {
		var content, class string
		e = tx.QueryRow(r.Context(), `SELECT b.content,r.classification FROM document_bodies b JOIN resources r ON r.tenant_id=b.tenant_id AND r.id=b.resource_id WHERE b.tenant_id=$1 AND b.resource_id=$2 FOR SHARE OF b,r`, j.TenantID, j.DocumentID).Scan(&content, &class)
		if e == nil {
			_, e = s.qualificationAdmission(r.Context(), tx, j, content, class)
		}
		if e != nil {
			workflowError(w, e)
			return
		}
		_, e = tx.Exec(r.Context(), `INSERT INTO jobs(id,tenant_id,delegation_id,state,owner_id,document_id,document_version,question,idempotency_key,request_digest,operation_id,question_id,question_version,execution_profile) VALUES($1,$2,$3,'queued',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, j.ID, j.TenantID, j.Delegation, j.Owner, j.DocumentID, j.DocumentVersion, j.Question, in.IdempotencyKey, digest, j.Operation, j.QuestionCatalogueID, j.QuestionCatalogueVersion, j.ExecutionProfile)
	} else {
		_, e = tx.Exec(r.Context(), `INSERT INTO jobs(id,tenant_id,delegation_id,state,owner_id,document_id,document_version,question,idempotency_key,request_digest,operation_id) VALUES($1,$2,$3,'queued',$4,$5,$6,$7,$8,$9,$10)`, j.ID, j.TenantID, j.Delegation, j.Owner, j.DocumentID, j.DocumentVersion, j.Question, in.IdempotencyKey, digest, j.Operation)
	}
	if e == nil {
		e = s.record(r.Context(), tx, j, "job.created", "queued")
	}
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		workflowError(w, e)
		return
	}
	j.Citation = j.DocumentID + "@" + j.DocumentVersion
	respond(w, 202, j.ReviewJob)
}
func (s *Server) visibleJob(ctx context.Context, tx pgx.Tx, a guard.Actor, id string) (storedJob, error) {
	j, e := loadJob(ctx, tx, id)
	if e != nil {
		return j, e
	}
	if j.TenantID != a.TenantID || j.Owner != a.ID {
		return j, errForbidden
	}
	_, _, _, e = s.reviewAuthority(ctx, tx, j)
	return j, e
}
func (s *Server) getJob(w http.ResponseWriter, r *http.Request) {
	tx, a, ok := s.userTx(w, r)
	if !ok {
		return
	}
	defer tx.Rollback(r.Context())
	j, e := s.visibleJob(r.Context(), tx, a, r.PathValue("id"))
	if e != nil {
		workflowError(w, finishDenied(r.Context(), tx, e))
		return
	}
	if e = tx.Commit(r.Context()); e != nil {
		workflowError(w, e)
		return
	}
	respond(w, 200, j.ReviewJob)
}
func (s *Server) cancelJob(w http.ResponseWriter, r *http.Request) {
	tx, a, ok := s.userTx(w, r)
	if !ok {
		return
	}
	defer tx.Rollback(r.Context())
	j, e := s.visibleJob(r.Context(), tx, a, r.PathValue("id"))
	if e != nil {
		workflowError(w, finishDenied(r.Context(), tx, e))
		return
	}
	if j.State == "cancelled" {
		respond(w, 200, map[string]string{"state": "cancelled"})
		return
	}
	if j.Phase == "export" || j.ExportID != "" {
		workflowError(w, errConflict)
		return
	}
	_, e = tx.Exec(r.Context(), `UPDATE jobs SET state='cancelled',lease_token=NULL,lease_until=NULL WHERE id=$1`, j.ID)
	if e == nil {
		e = s.record(r.Context(), tx, j, "job.cancelled", "cancelled")
	}
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		workflowError(w, e)
		return
	}
	respond(w, 200, map[string]string{"state": "cancelled"})
}
func (s *Server) documents(w http.ResponseWriter, r *http.Request) {
	tx, a, ok := s.userTx(w, r)
	if !ok {
		return
	}
	defer tx.Rollback(r.Context())
	if !slices.Contains(a.Permissions, "document.read") {
		workflowError(w, errForbidden)
		return
	}
	rows, e := tx.Query(r.Context(), `SELECT r.id,r.version,r.classification FROM resources r JOIN document_bodies b ON b.tenant_id=r.tenant_id AND b.resource_id=r.id WHERE r.tenant_id=$1 AND $2=ANY(r.reader_ids) AND r.classification IN ('public','internal','confidential') ORDER BY r.id`, a.TenantID, a.ID)
	if e != nil {
		workflowError(w, e)
		return
	}
	defer rows.Close()
	out := []map[string]string{}
	for rows.Next() {
		var id, v, c string
		if e = rows.Scan(&id, &v, &c); e != nil {
			workflowError(w, e)
			return
		}
		out = append(out, map[string]string{"id": id, "version": v, "classification": c})
	}
	if e = rows.Err(); e != nil {
		workflowError(w, e)
		return
	}
	rows.Close()
	allowed := []map[string]string{}
	for _, resource := range out {
		d, err := s.evaluateTx(r.Context(), tx, a, "human", "document.read", resource["id"], "public", true)
		if err != nil {
			workflowError(w, err)
			return
		}
		if d.Effect == "allow" {
			allowed = append(allowed, resource)
		}
	}
	if e = tx.Commit(r.Context()); e != nil {
		workflowError(w, e)
		return
	}
	respond(w, 200, allowed)
}
func (s *Server) jobEvents(w http.ResponseWriter, r *http.Request) {
	tx, a, ok := s.userTx(w, r)
	if !ok {
		return
	}
	defer tx.Rollback(r.Context())
	j, e := s.visibleJob(r.Context(), tx, a, r.PathValue("id"))
	if e != nil {
		workflowError(w, finishDenied(r.Context(), tx, e))
		return
	}
	rows, e := tx.Query(r.Context(), `SELECT id,action,decision,created_at,actor_id,delegation_id,resource_id,integrity_reference FROM audit_events WHERE tenant_id=$1 AND job_id=$2 ORDER BY created_at,id`, a.TenantID, j.ID)
	if e != nil {
		workflowError(w, e)
		return
	}
	out := []map[string]any{}
	for rows.Next() {
		var id, action string
		var detail, rawProof json.RawMessage
		var actor, delegation, resource string
		var at time.Time
		if e = rows.Scan(&id, &action, &detail, &at, &actor, &delegation, &resource, &rawProof); e != nil {
			rows.Close()
			workflowError(w, e)
			return
		}
		var proof evidence.Proof
		verified := json.Unmarshal(rawProof, &proof) == nil && evidence.VerifyEvent(ed25519.PublicKey(s.EvidencePublic), proof, evidence.Event{ID: id, TenantID: j.TenantID, ActorID: actor, JobID: j.ID, Action: action, Detail: detail, ResourceID: resource, DelegationID: delegation, Timestamp: at.UnixMicro(), Producer: proof.Producer})
		out = append(out, map[string]any{"event_id": id, "action": action, "detail": detail, "timestamp": at, "integrity_reference": rawProof, "integrity_verified": verified, "producer": proof.Producer, "tenant_id": j.TenantID, "actor_id": actor, "job_id": j.ID, "resource_id": resource, "delegation_id": delegation, "timestamp_us": at.UnixMicro()})
	}
	e = rows.Err()
	rows.Close()
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		workflowError(w, e)
		return
	}
	respond(w, 200, out)
}
func (s *Server) workerAuthorized(w http.ResponseWriter, r *http.Request) bool {
	expected := "Bearer " + base64.RawURLEncoding.EncodeToString(s.WorkerKey)
	if len(s.WorkerKey) != 32 || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(expected)) != 1 {
		fail(w, 401, "SERVICE_IDENTITY_REQUIRED", "Worker identity required")
		return false
	}
	return true
}
func (s *Server) claim(w http.ResponseWriter, r *http.Request) {
	if !s.workerAuthorized(w, r) {
		return
	}
	ctx := r.Context()
	tx, e := s.begin(ctx)
	if e != nil {
		workflowError(w, e)
		return
	}
	defer tx.Rollback(ctx)
	var id string
	e = tx.QueryRow(ctx, `SELECT id FROM jobs WHERE (state='queued' OR (state='running' AND lease_until<now())) ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&id)
	if errors.Is(e, pgx.ErrNoRows) {
		w.WriteHeader(204)
		return
	}
	if e != nil {
		workflowError(w, e)
		return
	}
	lease := rand.Text()
	_, e = tx.Exec(ctx, `UPDATE jobs SET state='running',lease_token=$2,lease_until=now()+interval '90 seconds' WHERE id=$1`, id, lease)
	if e == nil {
		e = tx.Commit(ctx)
	}
	if e != nil {
		workflowError(w, e)
		return
	}
	respond(w, 200, contracts.Lease{JobID: id, Token: lease})
}
