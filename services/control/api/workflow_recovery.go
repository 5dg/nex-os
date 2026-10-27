package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
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
	} else {
		var x contracts.Export
		e = json.Unmarshal(payload, &x)
		in = x
		out = &contracts.ExportResult{}
	}
	if e != nil || rpc == nil {
		workflowError(w, errConflict)
		return
	}
	statusClient := *rpc
	u, e := url.Parse(statusClient.URL)
	if e != nil {
		workflowError(w, e)
		return
	}
	u.Path = "/status"
	statusClient.URL = u.String()
	if e = statusClient.Call(r.Context(), in, out); e != nil {
		state := "unknown"
		if errors.Is(e, broker.ErrNotStarted) {
			state = "not_started"
		}
		if errors.Is(e, broker.ErrInProgress) {
			state = "in_progress"
		}
		respond(w, 200, map[string]string{"state": state})
		return
	}
	done, e := s.DB.Begin(r.Context())
	if e != nil {
		workflowError(w, e)
		return
	}
	defer done.Rollback(r.Context())
	current, e := loadJob(r.Context(), done, j.ID)
	if e != nil {
		workflowError(w, e)
		return
	}
	var completed bool
	e = done.QueryRow(r.Context(), `SELECT status='completed' FROM execution_operations WHERE id=$1`, j.Operation).Scan(&completed)
	if e != nil || !completed || current.Operation != j.Operation || current.State != "failed" {
		workflowError(w, errConflict)
		return
	}
	_, e = done.Exec(r.Context(), `UPDATE jobs SET state='completed',error_code='' WHERE id=$1`, j.ID)
	if e == nil {
		e = s.record(r.Context(), done, current, "job.reconciled", "durable_executor_receipt")
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

// Recovery has no caller-supplied result, state override, route or new payload.
func emptyRecoveryRequest(w http.ResponseWriter, r *http.Request) bool {
	if r.Body == nil || r.ContentLength == 0 {
		return true
	}
	var empty struct{}
	return decode(w, r, &empty)
}
