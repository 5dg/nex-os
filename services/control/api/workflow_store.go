package api

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
	"github.com/5dg/nex-os/services/control/auth"
	"github.com/5dg/nex-os/services/control/guard"
	"github.com/jackc/pgx/v5"
	"time"
)

var errForbidden = errors.New("operation not permitted")
var errConflict = errors.New("operation state conflict")

type storedJob struct {
	contracts.ReviewJob
	Owner, Delegation, Operation, Lease string
	LeaseUntil                          *time.Time
}

func actorFor(ctx context.Context, tx pgx.Tx, id auth.Identity) (guard.Actor, error) {
	var a guard.Actor
	e := tx.QueryRow(ctx, `SELECT id,tenant_id,permissions FROM users WHERE issuer=$1 AND subject=$2 FOR SHARE`, id.Issuer, id.Subject).Scan(&a.ID, &a.TenantID, &a.Permissions)
	if errors.Is(e, pgx.ErrNoRows) {
		return a, errForbidden
	}
	return a, e
}
func actorID(ctx context.Context, tx pgx.Tx, tenant, id string) (guard.Actor, error) {
	var a guard.Actor
	e := tx.QueryRow(ctx, `SELECT id,tenant_id,permissions FROM users WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&a.ID, &a.TenantID, &a.Permissions)
	if errors.Is(e, pgx.ErrNoRows) {
		return a, errForbidden
	}
	return a, e
}
func loadJob(ctx context.Context, tx pgx.Tx, id string) (storedJob, error) {
	var j storedJob
	e := tx.QueryRow(ctx, `SELECT id,tenant_id,state,phase,document_id,document_version,question,answer,provider,error_code,coalesce(approval_id,''),export_id,owner_id,delegation_id,operation_id,coalesce(lease_token,''),lease_until FROM jobs WHERE id=$1 FOR UPDATE`, id).Scan(&j.ID, &j.TenantID, &j.State, &j.Phase, &j.DocumentID, &j.DocumentVersion, &j.Question, &j.Answer, &j.Provider, &j.ErrorCode, &j.ApprovalID, &j.ExportID, &j.Owner, &j.Delegation, &j.Operation, &j.Lease, &j.LeaseUntil)
	if errors.Is(e, pgx.ErrNoRows) {
		return j, errForbidden
	}
	if e == nil {
		_, e = tx.Exec(ctx, `SELECT set_config('nex.job_id',$1,true)`, j.ID)
	}
	j.Citation = j.DocumentID + "@" + j.DocumentVersion
	return j, e
}
func (s *Server) record(ctx context.Context, tx pgx.Tx, j storedJob, event, outcome string) error {
	id := rand.Text()
	b, _ := json.Marshal(map[string]string{"event_type": event, "outcome": outcome, "job_id": j.ID, "policy_digest": guard.Digest(), "operation_id": j.Operation, "document_id": j.DocumentID, "document_version": j.DocumentVersion, "approval_id": j.ApprovalID, "model_provider": j.Provider, "artifact_id": j.ExportID, "answer_digest": broker.Hash([]byte(j.Answer))})
	_, e := tx.Exec(ctx, `INSERT INTO audit_events(id,tenant_id,actor_id,delegation_id,resource_id,action,decision,job_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, id, j.TenantID, j.Owner, j.Delegation, j.DocumentID, event, b, j.ID)
	if e == nil {
		e = s.anchor(ctx, tx, id)
	}
	return e
}
func (s *Server) evaluateTx(ctx context.Context, tx pgx.Tx, a guard.Actor, delegation, action, resource, class string, human bool) (contracts.Decision, error) {
	in := guard.Input{Actor: a, Action: action, DataClassification: class, DelegationPermissions: []string{}, Resource: guard.Resource{ReaderIDs: []string{}, ApprovedClassifications: []string{}}}
	if human {
		in.DelegationValid = true
		in.DelegationPermissions = a.Permissions
	} else {
		var expiry time.Time
		var revoked *time.Time
		e := tx.QueryRow(ctx, `SELECT permissions,expires_at,revoked_at FROM delegations WHERE id=$1 AND tenant_id=$2 AND user_id=$3 FOR SHARE`, delegation, a.TenantID, a.ID).Scan(&in.DelegationPermissions, &expiry, &revoked)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return contracts.Decision{}, e
		}
		in.DelegationValid = e == nil && revoked == nil && time.Now().Before(expiry)
	}
	e := tx.QueryRow(ctx, `SELECT tenant_id,kind,classification,reader_ids FROM resources WHERE tenant_id=$1 AND id=$2 FOR SHARE`, a.TenantID, resource).Scan(&in.Resource.TenantID, &in.Resource.Kind, &in.Resource.Classification, &in.Resource.ReaderIDs)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return contracts.Decision{}, e
	}
	if in.Resource.Kind == "model" {
		e = tx.QueryRow(ctx, `SELECT approved_classifications FROM model_routes WHERE tenant_id=$1 AND id=$2`, a.TenantID, resource).Scan(&in.Resource.ApprovedClassifications)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return contracts.Decision{}, e
		}
	}
	d, e := s.Policy.Evaluate(ctx, in)
	if e != nil {
		return d, e
	}
	d.ID = rand.Text()
	b, _ := json.Marshal(d)
	_, e = tx.Exec(ctx, `INSERT INTO audit_events(id,tenant_id,actor_id,delegation_id,resource_id,action,decision,job_id) VALUES($1,$2,$3,$4,$5,$6,$7,nullif(current_setting('nex.job_id',true),''))`, d.ID, a.TenantID, a.ID, delegation, resource, action, b)
	if e == nil {
		e = s.anchor(ctx, tx, d.ID)
	}
	return d, e
}
func (s *Server) reviewAuthority(ctx context.Context, tx pgx.Tx, j storedJob) (guard.Actor, string, string, error) {
	a, e := actorID(ctx, tx, j.TenantID, j.Owner)
	if e != nil {
		return a, "", "", e
	}
	d, e := s.evaluateTx(ctx, tx, a, j.Delegation, "document.read", j.DocumentID, "public", false)
	if e != nil {
		return a, "", "", e
	}
	if d.Effect != "allow" {
		return a, "", "", errForbidden
	}
	var content, digest, version, class string
	e = tx.QueryRow(ctx, `SELECT b.content,b.content_digest,r.version,r.classification FROM document_bodies b JOIN resources r ON r.tenant_id=b.tenant_id AND r.id=b.resource_id WHERE b.tenant_id=$1 AND b.resource_id=$2 FOR SHARE OF b,r`, j.TenantID, j.DocumentID).Scan(&content, &digest, &version, &class)
	if e != nil {
		return a, "", "", e
	}
	if version != j.DocumentVersion || digest != broker.Hash([]byte(content)) {
		return a, "", "", errForbidden
	}
	return a, content, class, nil
}

func finishDenied(ctx context.Context, tx pgx.Tx, e error) error {
	if errors.Is(e, errForbidden) || errors.Is(e, errConflict) {
		if commit := tx.Commit(ctx); commit != nil {
			return commit
		}
	}
	return e
}
