package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
	"github.com/5dg/nex-os/packages/evidence"
	"github.com/jackc/pgx/v5"
)

// Retry is available only when the receiver positively reported no local effect
// and Rust still has a pending operation. Reuse its immutable manifest and ID.
func (s *Server) retryJob(w http.ResponseWriter, r *http.Request) {
	if !emptyRecoveryRequest(w, r) {
		return
	}
	tx, a, ok := s.userTx(w, r)
	if !ok {
		return
	}
	defer tx.Rollback(r.Context())
	j, e := s.visibleJob(r.Context(), tx, a, r.PathValue("id"))
	if e != nil {
		workflowError(w, e)
		return
	}
	if j.State != "failed" || !strings.HasSuffix(j.ErrorCode, "_NOT_STARTED") {
		workflowError(w, errConflict)
		return
	}
	var pending bool
	e = tx.QueryRow(r.Context(), `SELECT o.status='pending' AND m.expires_at>clock_timestamp() FROM execution_operations o LEFT JOIN execution_manifests m ON m.operation_id=o.id WHERE o.id=$1 AND o.job_id=$2 AND o.tenant_id=$3`, j.Operation, j.ID, j.TenantID).Scan(&pending)
	if errors.Is(e, pgx.ErrNoRows) && strings.HasSuffix(j.ErrorCode, "_PREPARATION_NOT_STARTED") {
		pending = true
		e = nil
	}
	if e != nil || !pending {
		workflowError(w, errConflict)
		return
	}
	_, e = tx.Exec(r.Context(), `UPDATE jobs SET state='queued',error_code='' WHERE id=$1`, j.ID)
	if e == nil {
		e = s.record(r.Context(), tx, j, "job.retry_requested", "same_pending_operation")
	}
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		workflowError(w, e)
		return
	}
	respond(w, 200, map[string]string{"state": "queued"})
}

// Reconciliation queries an authenticated receiver's durable receipt. It never
// invokes execution and never accepts a client-supplied result or completion bit.
func (s *Server) reconcileJob(w http.ResponseWriter, r *http.Request) {
	if !emptyRecoveryRequest(w, r) {
		return
	}
	tx, a, ok := s.userTx(w, r)
	if !ok {
		return
	}
	defer tx.Rollback(r.Context())
	j, e := s.visibleJob(r.Context(), tx, a, r.PathValue("id"))
	if e != nil {
		workflowError(w, e)
		return
	}
	if j.State != "failed" {
		workflowError(w, errConflict)
		return
	}
	var payload json.RawMessage
	var kind string
	e = tx.QueryRow(r.Context(), `SELECT m.payload,o.kind FROM execution_operations o JOIN execution_manifests m ON m.operation_id=o.id WHERE o.id=$1 AND o.job_id=$2 AND o.tenant_id=$3`, j.Operation, j.ID, j.TenantID).Scan(&payload, &kind)
	if e != nil {
		workflowError(w, e)
		return
	}
	if e = tx.Commit(r.Context()); e != nil {
		workflowError(w, e)
		return
	}
	rpc := s.ToolRPC
	var in any
	var out any
	if kind == "model" {
		rpc = s.ModelRPC
		var x contracts.Generation
		e = json.Unmarshal(payload, &x)
		in = x
		out = &contracts.GenerationResult{}
	} else if kind == "export" {
		var x contracts.Export
		e = json.Unmarshal(payload, &x)
		in = x
		out = &contracts.ExportResult{}
	} else {
		workflowError(w, errConflict)
		return
	}
	if e != nil || rpc == nil {
		workflowError(w, errConflict)
		return
	}
	statusClient := *rpc
	if s.qualification() {
		scoped, err := rpc.StatusClient()
		if err != nil {
			workflowError(w, err)
			return
		}
		statusClient = *scoped
	}
	u, e := url.Parse(statusClient.URL)
	if e != nil {
		workflowError(w, e)
		return
	}
	u.Path = "/status"
	statusClient.URL = u.String()
	if e = s.beforeDispatch(r.Context()); e != nil {
		workflowError(w, e)
		return
	}
	statusErr := statusClient.Call(r.Context(), in, out)
	if current := s.afterDispatch(r.Context()); current != nil {
		workflowError(w, current)
		return
	}
	// The receiver call may have taken long enough for the bearer token, user,
	// delegation, or document authority to change. Revalidate before recording
	// a successful reconciliation and lock the current authority with the job.
	id, e := s.Auth.Verify(r)
	if e != nil {
		fail(w, 401, "UNAUTHENTICATED", "Valid bearer token required")
		return
	}
	done, e := s.begin(r.Context())
	if e != nil {
		workflowError(w, e)
		return
	}
	defer done.Rollback(r.Context())
	currentActor, e := actorFor(r.Context(), done, id)
	if e != nil {
		workflowError(w, e)
		return
	}
	current, e := s.visibleJob(r.Context(), done, currentActor, j.ID)
	if e != nil {
		workflowError(w, e)
		return
	}
	if current.Operation != j.Operation || current.State != "failed" || current.TenantID != j.TenantID {
		workflowError(w, errConflict)
		return
	}
	if statusErr != nil {
		// The receiver status is sensitive to the original job owner too. Do
		// not disclose it if authority expired or changed during the RPC.
		if e = s.reconcileCurrentAuthority(r, done, current); e == nil {
			e = done.Commit(r.Context())
		}
		if e != nil {
			workflowError(w, e)
			return
		}
		state := "unknown"
		if errors.Is(statusErr, broker.ErrNotStarted) {
			state = "not_started"
		}
		if errors.Is(statusErr, broker.ErrInProgress) {
			state = "in_progress"
		}
		respond(w, 200, map[string]string{"state": state})
		return
	}
	var status, digest string
	var protected json.RawMessage
	e = done.QueryRow(r.Context(), protectedResultQuery, j.Operation, j.ID, j.TenantID).Scan(&status, &digest, &protected)
	if e != nil || status != "completed" || !validReconciledResult(current, kind, in, out, digest, protected) {
		workflowError(w, errConflict)
		return
	}
	_, e = done.Exec(r.Context(), `UPDATE jobs SET state='completed',error_code='' WHERE id=$1`, j.ID)
	if e == nil {
		// The external signer commits before this transaction, so its event
		// describes the verified attempt rather than claiming SQL committed.
		// The outbox below captures the transition in this transaction. It is
		// not independently durable or signed evidence of the commit.
		e = s.record(r.Context(), done, current, "job.reconciliation_attempt", "protected_result_verified")
	}
	if e == nil {
		e = evidence.EnqueueCommittedReconciliation(r.Context(), done, evidence.CommittedReconciliationScope{
			TenantID: current.TenantID, ActorID: current.Owner, JobID: current.ID,
			ResourceID: current.DocumentID, DelegationID: current.Delegation,
			OperationID: current.Operation, Kind: kind, RequestDigest: digest, ProtectedResult: protected,
		})
	}
	if e == nil {
		e = s.reconcileCurrentAuthority(r, done, current)
	}
	if e == nil {
		e = done.Commit(r.Context())
	}
	if e != nil {
		workflowError(w, e)
		return
	}
	respond(w, 200, map[string]string{"state": "completed"})
}

// Row locks protect against concurrent revocation or identity edits, but do not
// stop time. Recheck token and delegation freshness after all policy and
// evidence RPCs, immediately before commit, using the database clock.
func (s *Server) reconcileCurrentAuthority(r *http.Request, tx pgx.Tx, j storedJob) error {
	id, e := s.Auth.Verify(r)
	if e != nil {
		return errForbidden
	}
	var current bool
	e = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM delegations d JOIN users u ON u.tenant_id=d.tenant_id AND u.id=d.user_id WHERE d.id=$1 AND d.tenant_id=$2 AND d.user_id=$3 AND u.issuer=$4 AND u.subject=$5 AND d.revoked_at IS NULL AND d.expires_at>clock_timestamp())`, j.Delegation, j.TenantID, j.Owner, id.Issuer, id.Subject).Scan(&current)
	if e != nil {
		return e
	}
	if !current {
		return errForbidden
	}
	return nil
}

// A successful status response is only an acknowledgement. Completion must
// match Guard's protected result and the locked job, just as the initial
// dispatch does. Never promote an unverified or cross-operation result.
func validReconciledResult(j storedJob, kind string, input, acknowledgement any, digest string, protected json.RawMessage) bool {
	if digest == "" {
		return false
	}
	switch kind {
	case "model":
		in, ok := input.(contracts.Generation)
		out, outOK := acknowledgement.(*contracts.GenerationResult)
		var result contracts.GenerationResult
		return ok && outOK && out != nil && contracts.ExecutionDigest(in) == digest && j.Phase == "review" && in.OperationID == j.Operation && in.TenantID == j.TenantID &&
			json.Unmarshal(protected, &result) == nil && result == *out && result.Text != "" && len(result.Text) <= 12000 && result.Provider != "" && j.Answer == result.Text && j.Provider == result.Provider
	case "export":
		in, ok := input.(contracts.Export)
		out, outOK := acknowledgement.(*contracts.ExportResult)
		var result contracts.ExportResult
		return ok && outOK && out != nil && contracts.ExecutionDigest(in) == digest && j.Phase == "export" && in.OperationID == j.Operation && in.TenantID == j.TenantID &&
			json.Unmarshal(protected, &result) == nil && result == *out && result.ArtifactID == j.Operation && result.ContentDigest == broker.Hash([]byte(in.Content)) && j.ExportID == result.ArtifactID
	default:
		return false
	}
}

// Recovery has no caller-supplied result, state override, route or new payload.
func emptyRecoveryRequest(w http.ResponseWriter, r *http.Request) bool {
	if r.Body == nil || r.ContentLength == 0 {
		return true
	}
	var empty struct{}
	return decode(w, r, &empty)
}
