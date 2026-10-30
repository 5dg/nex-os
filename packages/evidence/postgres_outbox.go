package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrOutboxUnknown = errors.New("candidate evidence unavailable or unauthorized")
var outboxID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var outboxVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// CandidateEvidenceScope must be derived from independently authenticated
// Guard state, never from an untrusted caller's identity or digest fields.
type CandidateEvidenceScope struct {
	EventID, TenantID, ActorID, JobID, ResourceID, ResourceVersion, DelegationID, OperationID, PayloadDigest, ContextDigest string
}

// OutboxFence must deny admission after failover/restore until the journal and
// any potentially lost writes have been independently reconciled. A callback
// check is not a distributed or effect-spanning fence on its own.
type OutboxFence interface{ Check(context.Context) error }

// OutboxAuthority independently authenticates the dispatching workload and
// current actor/session/delegation for the exact protected scope. It must
// honor context cancellation and recheck current authority, not a stale token.
type OutboxAuthority interface {
	AuthorizeDispatch(context.Context, CandidateEvidenceScope) error
	AuthorizeRelease(context.Context, CandidateEvidenceScope) error
}

// OutboxAppender must authenticate the evidence service and append precisely
// these canonical bytes under a stable event ID. Identical retries must return
// the same proof; altered content under an existing ID must be rejected.
type OutboxAppender interface {
	AppendExact(context.Context, []byte) ([]byte, error)
}

// OutboxProofVerifier independently verifies the service signature, trust
// anchor and exact event binding. No production algorithm or key is selected.
type OutboxProofVerifier interface {
	VerifyExact(context.Context, []byte, []byte) error
}

// CandidateEvidenceOutbox is an unwired transactional precursor. Candidate
// prompt release remains unavailable until trusted authorities and durable,
// nonrollback journal/fence behavior are independently established.
type CandidateEvidenceOutbox struct {
	db       *pgxpool.Pool
	fence    OutboxFence
	verifier OutboxProofVerifier
}

func validOutboxDependency(v any) bool {
	if v == nil {
		return false
	}
	x := reflect.ValueOf(v)
	switch x.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return !x.IsNil()
	default:
		return true
	}
}

func NewCandidateEvidenceOutbox(db *pgxpool.Pool, fence OutboxFence, verifier OutboxProofVerifier) (*CandidateEvidenceOutbox, error) {
	if db == nil || !validOutboxDependency(fence) || !validOutboxDependency(verifier) {
		return nil, ErrOutboxUnknown
	}
	return &CandidateEvidenceOutbox{db: db, fence: fence, verifier: verifier}, nil
}

func validOutboxDigest(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == value
}
func validOutboxScope(s CandidateEvidenceScope) bool {
	for _, v := range []string{s.EventID, s.TenantID, s.ActorID, s.JobID, s.ResourceID, s.DelegationID, s.OperationID} {
		if !outboxID.MatchString(v) {
			return false
		}
	}
	return len(s.EventID) >= 8 && len(s.OperationID) >= 8 && outboxVersion.MatchString(s.ResourceVersion) && validOutboxDigest(s.PayloadDigest) && validOutboxDigest(s.ContextDigest)
}

// uniqueObject rejects duplicate bound keys instead of silently accepting the
// last JSON value. Other event details are preserved in the canonical bytes.
func uniqueObject(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return nil, ErrOutboxUnknown
	}
	values := map[string]json.RawMessage{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, ErrOutboxUnknown
		}
		name, ok := token.(string)
		if !ok {
			return nil, ErrOutboxUnknown
		}
		if _, found := values[name]; found {
			return nil, ErrOutboxUnknown
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, ErrOutboxUnknown
		}
		values[name] = value
	}
	last, err := d.Token()
	if err != nil || last != json.Delim('}') || d.Decode(new(any)) != io.EOF {
		return nil, ErrOutboxUnknown
	}
	return values, nil
}
func rawString(value json.RawMessage) string {
	var out string
	if json.Unmarshal(value, &out) != nil {
		return ""
	}
	return out
}

func canonicalCandidateEvent(scope CandidateEvidenceScope, event Event) ([]byte, error) {
	if !validOutboxScope(scope) || event.ID != scope.EventID || event.TenantID != scope.TenantID || event.ActorID != scope.ActorID || event.JobID != scope.JobID || event.ResourceID != scope.ResourceID || event.DelegationID != scope.DelegationID || event.Producer != "kernel" || event.Action != "model.prepared" || event.Timestamp <= 0 {
		return nil, ErrOutboxUnknown
	}
	if !utf8.Valid(event.Detail) || !utf8.ValidString(event.ResourceID) || !utf8.ValidString(event.DelegationID) {
		return nil, ErrOutboxUnknown
	}
	detail, err := uniqueObject(event.Detail)
	if err != nil || rawString(detail["operation_id"]) != scope.OperationID || rawString(detail["document_id"]) != scope.ResourceID || rawString(detail["document_version"]) != scope.ResourceVersion || rawString(detail["candidate_context_digest"]) != scope.ContextDigest {
		return nil, ErrOutboxUnknown
	}
	provenance, err := uniqueObject(detail["provenance"])
	if err != nil || rawString(provenance["payload_digest"]) != scope.PayloadDigest {
		return nil, ErrOutboxUnknown
	}
	canonical, err := json.Marshal(normalized(event))
	if err != nil || len(canonical) < 2 || len(canonical) > 128*1024 {
		return nil, ErrOutboxUnknown
	}
	return canonical, nil
}

type outboxRow struct {
	scope        CandidateEvidenceScope
	event, proof []byte
	hash, state  string
}

func sameOutboxRow(a, b outboxRow) bool {
	return a.scope == b.scope && a.hash == b.hash && bytes.Equal(a.event, b.event)
}
func (s *CandidateEvidenceOutbox) begin(ctx context.Context) (pgx.Tx, error) {
	if ctx == nil || s == nil || s.db == nil || !validOutboxDependency(s.fence) || !validOutboxDependency(s.verifier) || s.fence.Check(ctx) != nil {
		return nil, ErrOutboxUnknown
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, ErrOutboxUnknown
	}
	if _, err = tx.Exec(ctx, "SET LOCAL synchronous_commit=on"); err != nil {
		rollbackOutbox(tx)
		return nil, ErrOutboxUnknown
	}
	var replica bool
	if tx.QueryRow(ctx, "SELECT pg_is_in_recovery()").Scan(&replica) != nil || replica {
		rollbackOutbox(tx)
		return nil, ErrOutboxUnknown
	}
	return tx, nil
}
func rollbackOutbox(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
func scanOutbox(ctx context.Context, tx pgx.Tx, id string, lock bool) (outboxRow, error) {
	var r outboxRow
	q := "SELECT event_id,tenant_id,actor_id,job_id,resource_id,resource_version,delegation_id,operation_id,payload_digest,context_digest,event_bytes,event_sha256,state,proof_bytes FROM nex_candidate_evidence.outbox WHERE event_id=$1"
	if lock {
		q += " FOR UPDATE"
	}
	if tx.QueryRow(ctx, q, id).Scan(&r.scope.EventID, &r.scope.TenantID, &r.scope.ActorID, &r.scope.JobID, &r.scope.ResourceID, &r.scope.ResourceVersion, &r.scope.DelegationID, &r.scope.OperationID, &r.scope.PayloadDigest, &r.scope.ContextDigest, &r.event, &r.hash, &r.state, &r.proof) != nil {
		return outboxRow{}, ErrOutboxUnknown
	}
	if !validOutboxScope(r.scope) || len(r.event) == 0 || len(r.event) > 128*1024 || !validOutboxDigest(r.hash) {
		return outboxRow{}, ErrOutboxUnknown
	}
	h := sha256.Sum256(r.event)
	if hex.EncodeToString(h[:]) != r.hash {
		return outboxRow{}, ErrOutboxUnknown
	}
	var event Event
	if json.Unmarshal(r.event, &event) != nil {
		return outboxRow{}, ErrOutboxUnknown
	}
	canonical, err := canonicalCandidateEvent(r.scope, event)
	if err != nil || !bytes.Equal(canonical, r.event) || (r.state == "pending" && r.proof != nil) || (r.state == "emitted" && (len(r.proof) == 0 || len(r.proof) > 16*1024)) || (r.state != "pending" && r.state != "emitted") {
		return outboxRow{}, ErrOutboxUnknown
	}
	return r, nil
}

// Enqueue writes the immutable canonical event into the caller's existing
// transaction. The caller must atomically insert the authenticated candidate
// context and outbox entry in the SAME authoritative database transaction.
// This method never calls an evidence service and never releases a prompt.
func (s *CandidateEvidenceOutbox) Enqueue(ctx context.Context, tx pgx.Tx, scope CandidateEvidenceScope, event Event) error {
	if ctx == nil || !validOutboxDependency(tx) || s == nil || s.db == nil || !validOutboxDependency(s.fence) || !validOutboxDependency(s.verifier) || s.fence.Check(ctx) != nil {
		return ErrOutboxUnknown
	}
	if _, err := tx.Exec(ctx, "SET LOCAL synchronous_commit=on"); err != nil {
		return ErrOutboxUnknown
	}
	var replica bool
	if tx.QueryRow(ctx, "SELECT pg_is_in_recovery()").Scan(&replica) != nil || replica {
		return ErrOutboxUnknown
	}
	canonical, err := canonicalCandidateEvent(scope, event)
	if err != nil {
		return ErrOutboxUnknown
	}
	h := sha256.Sum256(canonical)
	hash := hex.EncodeToString(h[:])
	q := `INSERT INTO nex_candidate_evidence.outbox(event_id,tenant_id,actor_id,job_id,resource_id,resource_version,delegation_id,operation_id,payload_digest,context_digest,event_bytes,event_sha256,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pending') ON CONFLICT(event_id) DO NOTHING`
	if _, err := tx.Exec(ctx, q, scope.EventID, scope.TenantID, scope.ActorID, scope.JobID, scope.ResourceID, scope.ResourceVersion, scope.DelegationID, scope.OperationID, scope.PayloadDigest, scope.ContextDigest, canonical, hash); err != nil {
		return ErrOutboxUnknown
	}
	actual, err := scanOutbox(ctx, tx, scope.EventID, true)
	if err != nil || !sameOutboxRow(actual, outboxRow{scope: scope, event: canonical, hash: hash}) {
		return ErrOutboxUnknown
	}
	return nil
}

func (s *CandidateEvidenceOutbox) read(ctx context.Context, scope CandidateEvidenceScope) (outboxRow, error) {
	if !validOutboxScope(scope) {
		return outboxRow{}, ErrOutboxUnknown
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return outboxRow{}, ErrOutboxUnknown
	}
	defer rollbackOutbox(tx)
	r, err := scanOutbox(ctx, tx, scope.EventID, false)
	if err != nil || r.scope != scope || tx.Commit(ctx) != nil {
		return outboxRow{}, ErrOutboxUnknown
	}
	return r, nil
}

// Dispatch performs at most one append attempt per call. Retrying the same
// immutable event is safe only when the independently trusted fence proves the
// evidence journal has not lost or forked acknowledged entries. Any ambiguous
// response, signature, DB commit or fence state remains unknown.
func (s *CandidateEvidenceOutbox) Dispatch(ctx context.Context, scope CandidateEvidenceScope, auth OutboxAuthority, appender OutboxAppender) error {
	if !validOutboxDependency(auth) || !validOutboxDependency(appender) {
		return ErrOutboxUnknown
	}
	r, err := s.read(ctx, scope)
	if err != nil || auth.AuthorizeDispatch(ctx, scope) != nil || s.fence.Check(ctx) != nil {
		return ErrOutboxUnknown
	}
	if r.state == "emitted" {
		if s.verifier.VerifyExact(ctx, append([]byte(nil), r.event...), append([]byte(nil), r.proof...)) != nil || auth.AuthorizeDispatch(ctx, scope) != nil || s.fence.Check(ctx) != nil || ctx.Err() != nil {
			return ErrOutboxUnknown
		}
		return nil
	}
	proof, err := appender.AppendExact(ctx, append([]byte(nil), r.event...))
	if err != nil || len(proof) == 0 || len(proof) > 16*1024 {
		return ErrOutboxUnknown
	}
	proof = append([]byte(nil), proof...)
	if s.verifier.VerifyExact(ctx, append([]byte(nil), r.event...), append([]byte(nil), proof...)) != nil || auth.AuthorizeDispatch(ctx, scope) != nil || s.fence.Check(ctx) != nil || ctx.Err() != nil {
		return ErrOutboxUnknown
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return ErrOutboxUnknown
	}
	defer rollbackOutbox(tx)
	current, err := scanOutbox(ctx, tx, scope.EventID, true)
	if err != nil || !sameOutboxRow(r, current) {
		return ErrOutboxUnknown
	}
	if current.state == "pending" {
		result, err := tx.Exec(ctx, `UPDATE nex_candidate_evidence.outbox SET state='emitted',proof_bytes=$2 WHERE event_id=$1 AND state='pending'`, scope.EventID, proof)
		if err != nil || result.RowsAffected() != 1 {
			return ErrOutboxUnknown
		}
	} else if current.state != "emitted" || !bytes.Equal(current.proof, proof) {
		return ErrOutboxUnknown
	}
	if tx.Commit(ctx) != nil || s.fence.Check(ctx) != nil || ctx.Err() != nil {
		return ErrOutboxUnknown
	}
	return nil
}

// ReadyForRelease never returns prompt data. The caller must recheck the
// authenticated original session and policy at the actual release boundary;
// this function cannot make a remote session check atomic with a client read.
func (s *CandidateEvidenceOutbox) ReadyForRelease(ctx context.Context, scope CandidateEvidenceScope, auth OutboxAuthority) error {
	if !validOutboxDependency(auth) {
		return ErrOutboxUnknown
	}
	r, err := s.read(ctx, scope)
	if err != nil || r.state != "emitted" || s.verifier.VerifyExact(ctx, append([]byte(nil), r.event...), append([]byte(nil), r.proof...)) != nil || auth.AuthorizeRelease(ctx, scope) != nil || s.fence.Check(ctx) != nil {
		return ErrOutboxUnknown
	}
	again, err := s.read(ctx, scope)
	if err != nil || again.state != "emitted" || !sameOutboxRow(r, again) || !bytes.Equal(r.proof, again.proof) || auth.AuthorizeRelease(ctx, scope) != nil || s.fence.Check(ctx) != nil || ctx.Err() != nil {
		return ErrOutboxUnknown
	}
	return nil
}
