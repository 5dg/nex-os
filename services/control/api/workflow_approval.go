package api

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
	"github.com/5dg/nex-os/services/control/guard"
	"github.com/jackc/pgx/v5"
	"net/http"
	"slices"
	"strconv"
	"time"
)

func bindingDigest(j storedJob, approval, destination, content string, expires time.Time) string {
	fields := []string{approval, j.ID, j.TenantID, j.Owner, j.Delegation, "document.export", j.DocumentID, j.DocumentVersion, broker.Hash([]byte(content)), broker.Hash([]byte(j.Answer)), destination, guard.Digest(), strconv.FormatInt(expires.Unix(), 10)}
	encoded := []byte("nex.export.v1\x00")
	for _, field := range fields {
		encoded = binary.BigEndian.AppendUint64(encoded, uint64(len([]byte(field))))
		encoded = append(encoded, []byte(field)...)
	}
	return broker.Hash(encoded)
}

func (s *Server) requestExport(w http.ResponseWriter, r *http.Request) {
	tx, a, ok := s.userTx(w, r)
	if !ok {
		return
	}
	defer tx.Rollback(r.Context())
	var in contracts.ExportRequest
	if !decode(w, r, &in) {
		return
	}
	j, e := s.visibleJob(r.Context(), tx, a, r.PathValue("id"))
	if e != nil {
		workflowError(w, finishDenied(r.Context(), tx, e))
		return
	}
	if j.State != "completed" || j.Phase != "review" || j.ApprovalID != "" || len(j.Answer) == 0 {
		workflowError(w, errConflict)
		return
	}
	var enabled bool
	e = tx.QueryRow(r.Context(), `SELECT enabled FROM export_destinations WHERE tenant_id=$1 AND id=$2 FOR SHARE`, a.TenantID, in.DestinationID).Scan(&enabled)
	if e != nil || !enabled {
		workflowError(w, errForbidden)
		return
	}
	d, e := s.evaluateTx(r.Context(), tx, a, j.Delegation, "document.export", j.DocumentID, "public", false)
	if e == nil && d.Effect != "require_approval" {
		e = errForbidden
	}
	if e != nil {
		workflowError(w, finishDenied(r.Context(), tx, e))
		return
	}
	_, content, _, e := s.reviewAuthority(r.Context(), tx, j)
	if e != nil {
		workflowError(w, finishDenied(r.Context(), tx, e))
		return
	}
	id := rand.Text()
	expiry := time.Now().UTC().Truncate(time.Second).Add(5 * time.Minute)
	digest := bindingDigest(j, id, in.DestinationID, content, expiry)
	operation := rand.Text()
	_, e = tx.Exec(r.Context(), `INSERT INTO approvals(id,tenant_id,job_id,request_digest,destination_id,expires_at,policy_digest) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, j.TenantID, j.ID, digest, in.DestinationID, expiry, guard.Digest())
	if e == nil {
		e = tx.QueryRow(r.Context(), `UPDATE jobs SET state='approval_required',approval_id=$2,operation_id=$3 WHERE id=$1 RETURNING approval_id,operation_id,state`, j.ID, id, operation).Scan(&j.ApprovalID, &j.Operation, &j.State)
	}
	if e == nil {
		// RETURNING resolves event context from the newly persisted transition.
		e = s.record(r.Context(), tx, j, "approval.requested", "approval_required")
	}
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		workflowError(w, e)
		return
	}
	respond(w, 201, contracts.ApprovalView{ID: id, JobID: j.ID, RequestDigest: digest, DestinationID: in.DestinationID, ExpiresAt: expiry.Format(time.RFC3339), Status: "pending"})
}
func (s *Server) listApprovals(w http.ResponseWriter, r *http.Request) {
	tx, a, ok := s.userTx(w, r)
	if !ok {
		return
	}
	defer tx.Rollback(r.Context())
	if !slices.Contains(a.Permissions, "approval.decide") {
		workflowError(w, errForbidden)
		return
	}
	rows, e := tx.Query(r.Context(), `SELECT a.id,a.job_id,a.request_digest,a.destination_id,a.expires_at,a.approved_at,a.rejected_at,a.consumed_at FROM approvals a JOIN jobs j ON j.tenant_id=a.tenant_id AND j.id=a.job_id JOIN resources d ON d.tenant_id=j.tenant_id AND d.id=j.document_id WHERE a.tenant_id=$1 AND $2=ANY(d.reader_ids) AND j.owner_id<>$2 ORDER BY a.expires_at DESC LIMIT 100`, a.TenantID, a.ID)
	if e != nil {
		workflowError(w, e)
		return
	}
	defer rows.Close()
	out := []contracts.ApprovalView{}
	for rows.Next() {
		var v contracts.ApprovalView
		var expiry time.Time
		var approved, rejected, consumed *time.Time
		if e = rows.Scan(&v.ID, &v.JobID, &v.RequestDigest, &v.DestinationID, &expiry, &approved, &rejected, &consumed); e != nil {
			workflowError(w, e)
			return
		}
		v.ExpiresAt = expiry.Format(time.RFC3339)
		v.Status = "pending"
		if approved != nil {
			v.Status = "approved"
		}
		if rejected != nil {
			v.Status = "rejected"
		}
		if consumed != nil {
			v.Status = "consumed"
		}
		if consumed == nil && time.Now().After(expiry) {
			v.Status = "expired"
		}
		out = append(out, v)
	}
	if e = rows.Err(); e != nil {
		workflowError(w, e)
		return
	}
	rows.Close()
	visible := []contracts.ApprovalView{}
	for _, v := range out {
		j, err := loadJob(r.Context(), tx, v.JobID)
		if err != nil {
			workflowError(w, err)
			return
		}
		_, _, _, err = s.reviewAuthority(r.Context(), tx, j)
		if errors.Is(err, errForbidden) {
			continue
		}
		if err != nil {
			workflowError(w, err)
			return
		}
		d, err := s.evaluateTx(r.Context(), tx, a, "human", "approval.decide", j.DocumentID, "public", true)
		if err != nil {
			workflowError(w, err)
			return
		}
		if d.Effect != "allow" {
			continue
		}
		v.RequesterID = j.Owner
		v.DocumentID = j.DocumentID
		v.DocumentVersion = j.DocumentVersion
		v.ExportPreview = j.Answer + "\n\nSource: " + j.DocumentID + "@" + j.DocumentVersion
		visible = append(visible, v)
	}
	if e = tx.Commit(r.Context()); e != nil {
		workflowError(w, e)
		return
	}
	respond(w, 200, visible)
}
func (s *Server) approve(w http.ResponseWriter, r *http.Request) {
	tx, a, ok := s.userTx(w, r)
	if !ok {
		return
	}
	defer tx.Rollback(r.Context())
	var in struct {
		Approve       *bool  `json:"approve"`
		RequestDigest string `json:"request_digest"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Approve == nil || in.RequestDigest == "" {
		fail(w, 400, "INVALID_REQUEST", "Explicit approval decision and request digest required")
		return
	}
	if e := tx.Commit(r.Context()); e != nil {
		workflowError(w, e)
		return
	}
	allowed, e := s.Policy.DecideApproval(r.Context(), r.PathValue("id"), in.RequestDigest, a.ID, a.TenantID, *in.Approve)
	if e != nil {
		workflowError(w, e)
		return
	}
	if !allowed {
		workflowError(w, errForbidden)
		return
	}
	respond(w, 200, map[string]bool{"approved": *in.Approve})
}

func (s *Server) exportPayload(ctx context.Context, tx pgx.Tx, j storedJob) (contracts.Export, error) {
	a, content, _, e := s.reviewAuthority(ctx, tx, j)
	if e != nil {
		return contracts.Export{}, e
	}
	d, e := s.evaluateTx(ctx, tx, a, j.Delegation, "document.export", j.DocumentID, "public", false)
	if e != nil {
		return contracts.Export{}, e
	}
	if d.Effect != "require_approval" {
		return contracts.Export{}, errForbidden
	}
	var destination, digest, policy, approver string
	var expiry time.Time
	var approved, rejected, consumed *time.Time
	e = tx.QueryRow(ctx, `SELECT destination_id,request_digest,policy_digest,coalesce(approver_id,''),expires_at,approved_at,rejected_at,consumed_at FROM approvals WHERE tenant_id=$1 AND id=$2 AND job_id=$3 FOR UPDATE`, j.TenantID, j.ApprovalID, j.ID).Scan(&destination, &digest, &policy, &approver, &expiry, &approved, &rejected, &consumed)
	if e != nil {
		return contracts.Export{}, e
	}
	if !time.Now().Before(expiry) || approved == nil || rejected != nil || policy != guard.Digest() || approver == j.Owner || digest != bindingDigest(j, j.ApprovalID, destination, content, expiry) {
		return contracts.Export{}, errForbidden
	}
	human, e := actorID(ctx, tx, j.TenantID, approver)
	if e != nil {
		return contracts.Export{}, e
	}
	permission, e := s.evaluateTx(ctx, tx, human, "human", "approval.decide", j.DocumentID, "public", true)
	if e != nil {
		return contracts.Export{}, e
	}
	if permission.Effect != "allow" {
		return contracts.Export{}, errForbidden
	}
	var enabled bool
	e = tx.QueryRow(ctx, `SELECT enabled FROM export_destinations WHERE tenant_id=$1 AND id=$2 FOR SHARE`, j.TenantID, destination).Scan(&enabled)
	if e != nil || !enabled {
		return contracts.Export{}, errForbidden
	}

	return contracts.Export{OperationID: j.Operation, TenantID: j.TenantID, DestinationID: destination, Content: j.Answer + "\n\nSource: " + j.DocumentID + "@" + j.DocumentVersion, RequestDigest: digest}, nil
}
