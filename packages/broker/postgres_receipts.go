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
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresReceiptStore is an isolated production building block. Its two
// fixed domains require separate least-privilege database roles. It is not wired
// into any runtime profile and does not migrate historical filesystem receipts.
// A deployment must additionally prove that an acknowledged receipt cannot be
// lost during failover/restore, or prevent admission until every potentially
// lost external effect has been independently reconciled.
type PostgresReceiptStore struct {
	db    *pgxpool.Pool
	table string
	fence ReceiptRecoveryFence
}

// ReceiptRecoveryFence is supplied by trusted deployment wiring. It must deny
// admission during failover or restore until any potentially lost receipts and
// in-flight external effects have been independently reconciled. These checks
// alone do not provide a linearizable fence spanning provider dispatch and
// cannot cancel an external call already in flight.
type ReceiptRecoveryFence interface {
	Check(context.Context) error
}

// ReceiptAccess must authenticate the current caller and check its current
// authority for the given operation, digest, tenant and result scope. Callers
// obtain tenant/actor identity from their trusted request context. This is
// separate from, and must not consume, the one-shot effect authorization.
type ReceiptAccess func(context.Context, string, string) error

func NewPostgresReceiptStore(db *pgxpool.Pool, domain string, fence ReceiptRecoveryFence) (*PostgresReceiptStore, error) {
	if db == nil || fence == nil {
		return nil, errors.New("receipt database and recovery fence required")
	}
	v := reflect.ValueOf(fence)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		if v.IsNil() {
			return nil, errors.New("receipt database and recovery fence required")
		}
	}
	table := ""
	switch domain {
	case "model":
		table = "nex_model_receipts.operations"
	case "export":
		table = "nex_export_receipts.operations"
	default:
		return nil, errors.New("fixed receiver domain required")
	}
	return &PostgresReceiptStore{db: db, table: table, fence: fence}, nil
}

func (s *PostgresReceiptStore) access(ctx context.Context, id, digest string, authenticate ReceiptAccess) error {
	if ctx == nil || s == nil || s.db == nil || s.fence == nil || authenticate == nil || s.fence.Check(ctx) != nil || authenticate(ctx, id, digest) != nil {
		return ErrUnknown
	}
	return nil
}

func validReceiptDigest(digest string) bool {
	b, err := hex.DecodeString(digest)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == digest
}

func receiptRollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

func (s *PostgresReceiptStore) begin(ctx context.Context) (pgx.Tx, error) {
	if s == nil || s.db == nil {
		return nil, ErrUnknown
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, ErrUnknown
	}
	if _, err = tx.Exec(ctx, "SET LOCAL synchronous_commit = on"); err != nil {
		receiptRollback(tx)
		return nil, ErrUnknown
	}
	var replica bool
	if err = tx.QueryRow(ctx, "SELECT pg_is_in_recovery()").Scan(&replica); err != nil || replica {
		receiptRollback(tx)
		return nil, ErrUnknown
	}
	return tx, nil
}

func validReceiptResult(b []byte) bool {
	return len(b) > 0 && len(b) <= 128*1024 && json.Valid(b) && !bytes.Equal(bytes.TrimSpace(b), []byte("null"))
}

// Inspect never dispatches an effect. Missing, inaccessible or ambiguous state
// is unknown: an absent row alone cannot prove no prior effect after data loss.
func (s *PostgresReceiptStore) Inspect(ctx context.Context, id, digest string, authenticate ReceiptAccess) (json.RawMessage, error) {
	if !validID(id) || !validReceiptDigest(digest) || s.access(ctx, id, digest, authenticate) != nil {
		return nil, ErrUnknown
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, ErrUnknown
	}
	defer receiptRollback(tx)
	var storedDigest, state string
	var result []byte
	err = tx.QueryRow(ctx, fmt.Sprintf("SELECT request_digest, state, result_bytes FROM %s WHERE operation_id=$1", s.table), id).Scan(&storedDigest, &state, &result)
	if err != nil || storedDigest != digest {
		return nil, ErrUnknown
	}
	switch state {
	case "completed":
		if !validReceiptResult(result) {
			return nil, ErrUnknown
		}
		if tx.Commit(ctx) != nil {
			return nil, ErrUnknown
		}
		if s.access(ctx, id, digest, authenticate) != nil {
			return nil, ErrUnknown
		}
		return append(json.RawMessage(nil), result...), nil
	case "not_started":
		if result == nil && tx.Commit(ctx) == nil {
			if s.access(ctx, id, digest, authenticate) != nil {
				return nil, ErrUnknown
			}
			return nil, ErrNotStarted
		}
	}
	return nil, ErrUnknown
}

// claim commits a prepared marker before asking Guard for authorization.
// Only a completed result or a Guard-attested not_started marker may be reused;
// abandoned prepared/started rows always stay unknown.
func (s *PostgresReceiptStore) claim(ctx context.Context, id, digest, nonce string) (json.RawMessage, bool, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, false, ErrUnknown
	}
	defer receiptRollback(tx)
	insert := fmt.Sprintf("INSERT INTO %s(operation_id,request_digest,owner_nonce,state) VALUES($1,$2,$3,'prepared') ON CONFLICT(operation_id) DO NOTHING", s.table)
	result, err := tx.Exec(ctx, insert, id, digest, nonce)
	if err != nil {
		return nil, false, ErrUnknown
	}
	if result.RowsAffected() == 1 {
		if tx.Commit(ctx) != nil {
			return nil, false, ErrUnknown
		}
		return nil, true, nil
	}
	var oldDigest, state string
	var oldResult []byte
	query := fmt.Sprintf("SELECT request_digest,state,result_bytes FROM %s WHERE operation_id=$1 FOR UPDATE", s.table)
	if tx.QueryRow(ctx, query, id).Scan(&oldDigest, &state, &oldResult) != nil || oldDigest != digest {
		return nil, false, ErrUnknown
	}
	switch state {
	case "completed":
		if !validReceiptResult(oldResult) || tx.Commit(ctx) != nil {
			return nil, false, ErrUnknown
		}
		return append(json.RawMessage(nil), oldResult...), false, nil
	case "not_started":
		if oldResult != nil {
			return nil, false, ErrUnknown
		}
		update := fmt.Sprintf("UPDATE %s SET state='prepared',owner_nonce=$2 WHERE operation_id=$1 AND state='not_started'", s.table)
		changed, err := tx.Exec(ctx, update, id, nonce)
		if err != nil || changed.RowsAffected() != 1 || tx.Commit(ctx) != nil {
			return nil, false, ErrUnknown
		}
		return nil, true, nil
	default:
		return nil, false, ErrUnknown
	}
}

func (s *PostgresReceiptStore) transition(ctx context.Context, id, digest, nonce, from, to string, result []byte) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return ErrUnknown
	}
	defer receiptRollback(tx)
	query := fmt.Sprintf("UPDATE %s SET state=$5,result_bytes=$6 WHERE operation_id=$1 AND request_digest=$2 AND owner_nonce=$3 AND state=$4", s.table)
	changed, err := tx.Exec(ctx, query, id, digest, nonce, from, to, result)
	if err != nil || changed.RowsAffected() != 1 || tx.Commit(ctx) != nil {
		return ErrUnknown
	}
	return nil
}

// DoAuthorized requires an authenticated Guard decision. A durable started
// marker is committed before dispatch. Uncertain authorization, DB commits,
// provider calls, serialization and completion remain unknown and never retry.
func (s *PostgresReceiptStore) DoAuthorized(ctx context.Context, id, digest string, authenticate ReceiptAccess, authorize func(context.Context) error, effect func(context.Context) (any, error)) (json.RawMessage, error) {
	if !validID(id) || !validReceiptDigest(digest) || authorize == nil || effect == nil || s.access(ctx, id, digest, authenticate) != nil {
		return nil, ErrUnknown
	}
	var nonceBytes [16]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		return nil, ErrUnknown
	}
	nonce := hex.EncodeToString(nonceBytes[:])
	old, claimed, err := s.claim(ctx, id, digest, nonce)
	if err != nil {
		return nil, err
	}
	if !claimed {
		if s.access(ctx, id, digest, authenticate) != nil {
			return nil, ErrUnknown
		}
		return old, nil
	}
	if err = authorize(ctx); err != nil {
		if errors.Is(err, ErrNotStarted) && s.transition(ctx, id, digest, nonce, "prepared", "not_started", nil) == nil {
			if s.access(ctx, id, digest, authenticate) != nil {
				return nil, ErrUnknown
			}
			return nil, ErrNotStarted
		}
		return nil, ErrUnknown
	}
	if s.transition(ctx, id, digest, nonce, "prepared", "started", nil) != nil {
		return nil, ErrUnknown
	}
	if s.access(ctx, id, digest, authenticate) != nil {
		return nil, ErrUnknown
	}
	value, err := effect(ctx)
	if err != nil {
		return nil, ErrUnknown
	}
	result, err := json.Marshal(value)
	if err != nil || !validReceiptResult(result) {
		return nil, ErrUnknown
	}
	if s.fence.Check(ctx) != nil {
		return nil, ErrUnknown
	}
	if s.transition(ctx, id, digest, nonce, "started", "completed", result) != nil {
		return nil, ErrUnknown
	}
	if s.access(ctx, id, digest, authenticate) != nil {
		return nil, ErrUnknown
	}
	return result, nil
}
