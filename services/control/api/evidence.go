package api

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/5dg/nex-os/packages/evidence"
	"github.com/jackc/pgx/v5"
	"net/http"
	"strings"
	"time"
)

func (s *Server) evidenceReady(ctx context.Context) error {
	if s.EvidenceRPC == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	request, e := http.NewRequestWithContext(ctx, "GET", strings.TrimSuffix(s.EvidenceRPC.URL, "/append/control")+"/healthz", nil)
	if e != nil {
		return e
	}
	response, e := s.EvidenceRPC.HTTP.Do(request)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("evidence unavailable")
	}
	return nil
}

func (s *Server) anchor(ctx context.Context, tx pgx.Tx, id string) error {
	if s.EvidenceRPC == nil {
		return nil
	} // Legacy test fixtures explicitly exercise DB-only mode.
	var event evidence.Event
	var detail []byte
	var timestamp time.Time
	e := tx.QueryRow(ctx, `SELECT id,tenant_id,actor_id,coalesce(job_id,''),action,decision,resource_id,delegation_id,created_at FROM audit_events WHERE id=$1`, id).Scan(&event.ID, &event.TenantID, &event.ActorID, &event.JobID, &event.Action, &detail, &event.ResourceID, &event.DelegationID, &timestamp)
	if e != nil {
		return e
	}
	event.Detail = detail
	event.Timestamp = timestamp.UnixMicro()
	event.Producer = "control"
	var proof evidence.Proof
	if e = s.EvidenceRPC.Call(ctx, event, &proof); e != nil {
		return e
	}
	if !evidence.VerifyEvent(ed25519.PublicKey(s.EvidencePublic), proof, event) {
		return errors.New("evidence signature invalid")
	}
	b, _ := json.Marshal(proof)
	_, e = tx.Exec(ctx, `UPDATE audit_events SET integrity_reference=$2 WHERE id=$1`, id, b)
	return e
}
