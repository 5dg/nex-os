package broker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

// ReceiptPhase distinguishes current-authority checks. The first handoff is
// to the authenticated receiver completing Guard, not a user result release.
// The zero value is invalid. These values do not enable any runtime profile.
type ReceiptPhase uint8

const (
	ReceiptDispatchPreflight ReceiptPhase = iota + 1
	ReceiptDispatchEffect
	ReceiptReceiverHandoff
	ReceiptCompletedRead
)

// ReceiptClaim is generated inside the store. Fields cannot be changed by a
// caller; the nonce is available only to trusted Guard/receiver integration.
// A nonce alone is not an identity, distributed fence, or authorization proof.
type ReceiptClaim struct{ operation, digest, nonce string }

func (c ReceiptClaim) OperationID() string { return c.operation }
func (c ReceiptClaim) Digest() string      { return c.digest }
func (c ReceiptClaim) Nonce() string       { return c.nonce }

// ReceiptPhaseAuthorizer must independently authenticate the receiver and
// current original user, bind the requested phase/tenant/operation/digest,
// and enforce Guard's matching phase/status policy. For dispatch and handoff
// it must bind the exact live claimant to authenticated receiver identity.
// Callback checks are not a linearizable fence across databases or effects.
type ReceiptPhaseAuthorizer interface {
	CheckReceiptPhase(context.Context, ReceiptPhase, ReceiptClaim) (guardStatus string, err error)
}

func receiptPhaseStatusAllowed(phase ReceiptPhase, status string) bool {
	switch phase {
	case ReceiptDispatchPreflight:
		return status == "pending"
	case ReceiptDispatchEffect, ReceiptReceiverHandoff:
		return status == "started"
	case ReceiptCompletedRead:
		return status == "completed"
	default:
		return false
	}
}

func (s *PostgresReceiptStore) checkPhase(ctx context.Context, phase ReceiptPhase, claim ReceiptClaim, auth ReceiptPhaseAuthorizer) error {
	if auth == nil || phase < ReceiptDispatchPreflight || phase > ReceiptCompletedRead {
		return ErrUnknown
	}
	v := reflect.ValueOf(auth)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		if v.IsNil() {
			return ErrUnknown
		}
	}
	return s.access(ctx, claim.operation, claim.digest, func(ctx context.Context, _, _ string) error {
		status, err := auth.CheckReceiptPhase(ctx, phase, claim)
		if err != nil || !receiptPhaseStatusAllowed(phase, status) {
			return ErrUnknown
		}
		return nil
	})
}

// ownedState binds the phase to the claimant nonce and durable receiver state.
// This is an additional check; it cannot itself fence a stale process across
// promotion/restore or span an external provider call.
func (s *PostgresReceiptStore) ownedState(ctx context.Context, claim ReceiptClaim, state string, expected []byte) error {
	if claim.nonce == "" {
		return ErrUnknown
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return ErrUnknown
	}
	defer receiptRollback(tx)
	var storedDigest, storedNonce, storedState string
	var result []byte
	q := fmt.Sprintf("SELECT request_digest,owner_nonce,state,result_bytes FROM %s WHERE operation_id=$1", s.table)
	if tx.QueryRow(ctx, q, claim.operation).Scan(&storedDigest, &storedNonce, &storedState, &result) != nil || storedDigest != claim.digest || storedNonce != claim.nonce || storedState != state || !bytes.Equal(result, expected) || tx.Commit(ctx) != nil {
		return ErrUnknown
	}
	return nil
}

// DoPhasedAuthorized performs one effect and returns its completed receipt
// only to the original authenticated receiver for Guard completion. Completed
// receipts are not replayed here: use ReadPhasedCompleted after Guard has
// independently completed the operation. Unknown/abandoned state never retries.
// If a completed receipt's handoff is denied or its response is lost, the
// result cannot automatically advance Guard; separately authorized, audited
// reconciliation is required, with no automatic redispatch or result release.
// Actual deployment must provide a proven effect-spanning recovery fence and
// independently authenticated phase authorizer; this method is not wired into
// production and does not itself supply either dependency. Existing unphased
// receipt methods must not be exposed as alternate production paths.
func (s *PostgresReceiptStore) DoPhasedAuthorized(ctx context.Context, id, digest string, auth ReceiptPhaseAuthorizer, authorize func(context.Context, ReceiptClaim) error, effect func(context.Context) (any, error)) (json.RawMessage, error) {
	claim := ReceiptClaim{operation: id, digest: digest}
	if !validID(id) || !validReceiptDigest(digest) || authorize == nil || effect == nil || s.checkPhase(ctx, ReceiptDispatchPreflight, claim, auth) != nil {
		return nil, ErrUnknown
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, ErrUnknown
	}
	claim.nonce = hex.EncodeToString(random[:])
	_, claimed, err := s.claim(ctx, id, digest, claim.nonce)
	if err != nil || !claimed {
		return nil, ErrUnknown
	}
	if err = authorize(ctx, claim); err != nil {
		if errors.Is(err, ErrNotStarted) && s.transition(ctx, id, digest, claim.nonce, "prepared", "not_started", nil) == nil && s.checkPhase(ctx, ReceiptDispatchPreflight, ReceiptClaim{operation: id, digest: digest}, auth) == nil {
			return nil, ErrNotStarted
		}
		return nil, ErrUnknown
	}
	if s.transition(ctx, id, digest, claim.nonce, "prepared", "started", nil) != nil || s.ownedState(ctx, claim, "started", nil) != nil || s.checkPhase(ctx, ReceiptDispatchEffect, claim, auth) != nil || s.ownedState(ctx, claim, "started", nil) != nil || s.fence.Check(ctx) != nil {
		return nil, ErrUnknown
	}
	value, err := effect(ctx)
	if err != nil {
		return nil, ErrUnknown
	}
	result, err := json.Marshal(value)
	if err != nil || !validReceiptResult(result) || s.fence.Check(ctx) != nil || s.transition(ctx, id, digest, claim.nonce, "started", "completed", result) != nil {
		return nil, ErrUnknown
	}
	if s.ownedState(ctx, claim, "completed", result) != nil || s.checkPhase(ctx, ReceiptReceiverHandoff, claim, auth) != nil || s.ownedState(ctx, claim, "completed", result) != nil || s.fence.Check(ctx) != nil {
		return nil, ErrUnknown
	}
	return append(json.RawMessage(nil), result...), nil
}

// ReadPhasedCompleted permits only the independently authorized completed-read
// phase; it never returns not_started as a completed result and never dispatches.
func (s *PostgresReceiptStore) ReadPhasedCompleted(ctx context.Context, id, digest string, auth ReceiptPhaseAuthorizer) (json.RawMessage, error) {
	claim := ReceiptClaim{operation: id, digest: digest}
	result, err := s.Inspect(ctx, id, digest, func(ctx context.Context, _, _ string) error {
		return s.checkPhase(ctx, ReceiptCompletedRead, claim, auth)
	})
	if err != nil {
		return nil, ErrUnknown
	}
	return result, nil
}
