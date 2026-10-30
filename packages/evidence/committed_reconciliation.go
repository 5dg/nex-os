package evidence

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// CommittedReconciliationScope is derived from the already locked and
// independently authorized job and protected result, not from the caller.
type CommittedReconciliationScope struct {
	TenantID, ActorID, JobID, ResourceID, DelegationID, OperationID, Kind, RequestDigest string
	ProtectedResult                                                                      []byte
}

// EnqueueCommittedReconciliation writes a new immutable event within the same
// transaction as the reconciled job transition. Its bytes must only be sent to
// the journal after that transaction commits. This does not deliver a proof,
// provide an independent anchor, or authorize downstream execution.
func EnqueueCommittedReconciliation(ctx context.Context, tx pgx.Tx, scope CommittedReconciliationScope) error {
	if ctx == nil || !validOutboxDependency(tx) || ctx.Err() != nil || !validOutboxDigest(scope.RequestDigest) || (scope.Kind != "model" && scope.Kind != "export") || len(scope.ProtectedResult) == 0 || len(scope.ProtectedResult) > 128*1024 || !json.Valid(scope.ProtectedResult) {
		return ErrOutboxUnknown
	}
	for _, value := range []string{scope.TenantID, scope.ActorID, scope.JobID, scope.ResourceID, scope.DelegationID, scope.OperationID} {
		if value == "" || len(value) > 128 || !utf8.ValidString(value) {
			return ErrOutboxUnknown
		}
	}
	if _, err := tx.Exec(ctx, "SET LOCAL synchronous_commit=on"); err != nil {
		return ErrOutboxUnknown
	}
	var replica bool
	var timestamp int64
	if tx.QueryRow(ctx, "SELECT pg_is_in_recovery(), (extract(epoch FROM clock_timestamp())*1000000)::bigint").Scan(&replica, &timestamp) != nil || replica || timestamp <= 0 {
		return ErrOutboxUnknown
	}
	resultHash := sha256.Sum256(scope.ProtectedResult)
	detail, err := json.Marshal(map[string]string{"operation_id": scope.OperationID, "kind": scope.Kind, "request_digest": scope.RequestDigest, "protected_result_sha256": hex.EncodeToString(resultHash[:])})
	if err != nil {
		return ErrOutboxUnknown
	}
	event := Event{ID: "reconciled-" + rand.Text(), TenantID: scope.TenantID, ActorID: scope.ActorID, JobID: scope.JobID, ResourceID: scope.ResourceID, DelegationID: scope.DelegationID, Producer: "control", Action: "job.reconciliation.committed", Timestamp: timestamp, Detail: detail}
	canonical, err := json.Marshal(normalized(event))
	if err != nil || len(canonical) > 128*1024 {
		return ErrOutboxUnknown
	}
	hash := sha256.Sum256(canonical)
	_, err = tx.Exec(ctx, `INSERT INTO committed_reconciliation_outbox(event_id,tenant_id,job_id,operation_id,event_bytes,event_sha256) VALUES($1,$2,$3,$4,$5,$6)`, event.ID, scope.TenantID, scope.JobID, scope.OperationID, canonical, hex.EncodeToString(hash[:]))
	if err != nil || ctx.Err() != nil {
		return ErrOutboxUnknown
	}
	return nil
}
