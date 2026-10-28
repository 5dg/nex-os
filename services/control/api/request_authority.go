package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/5dg/nex-os/packages/trust"
	"github.com/jackc/pgx/v5"
)

type requestAuthorityKey struct{}

// This private snapshot is created only from the incoming verified TLS state.
// No HTTP header or browser claim can create it.
type requestAuthority struct {
	original   context.Context
	current    func() error
	accounting bool
}

var errRequestAuthority = errors.New("verified qualification request context required")
var errRequestOutcomeUnavailable = errors.New("request no longer current after dispatch; outcome unavailable")

func (s *Server) withRequestAuthority(r *http.Request, roles []trust.Role) *http.Request {
	authority := requestAuthority{original: r.Context(), current: func() error {
		return s.Trust.CheckPeer(r.TLS, roles)
	}}
	return r.WithContext(context.WithValue(r.Context(), requestAuthorityKey{}, authority))
}

func (s *Server) currentRequest(ctx context.Context) error {
	if !s.qualification() {
		return nil
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	authority, ok := ctx.Value(requestAuthorityKey{}).(requestAuthority)
	if !ok {
		return errRequestAuthority
	}
	if authority.accounting {
		return nil
	}
	if authority.original == nil || authority.current == nil {
		return errRequestAuthority
	}
	if e := authority.original.Err(); e != nil {
		return e
	}
	if e := authority.current(); e != nil {
		return errForbidden
	}
	return nil
}

func (s *Server) beforeDispatch(ctx context.Context) error {
	if s.qualification() {
		if authority, ok := ctx.Value(requestAuthorityKey{}).(requestAuthority); ok && authority.accounting {
			return errRequestAuthority
		}
	}
	return s.currentRequest(ctx)
}

// A late caller failure does not establish whether an already dispatched RPC
// committed. Do not turn that ambiguity into denial or no-effect evidence.
func (s *Server) afterDispatch(ctx context.Context) error {
	if e := s.currentRequest(ctx); e != nil {
		return errRequestOutcomeUnavailable
	}
	return nil
}

// Only preExecutionFailure uses this mode, after releasing the resolver
// transaction. Its SQL still locks and fences the already accepted job/lease;
// signing remains authenticated separately. New protected dispatch is forbidden.
func operationalAccounting(ctx context.Context) context.Context {
	return context.WithValue(ctx, requestAuthorityKey{}, requestAuthority{accounting: true})
}

type requestTx struct {
	pgx.Tx
	check func() error
}

func (tx requestTx) Commit(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := tx.check(); e != nil {
		return e
	}
	return tx.Tx.Commit(ctx)
}

func (tx requestTx) Begin(ctx context.Context) (pgx.Tx, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := tx.check(); e != nil {
		return nil, e
	}
	nested, e := tx.Tx.Begin(ctx)
	if e != nil {
		return nil, e
	}
	return requestTx{Tx: nested, check: func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		return tx.check()
	}}, nil
}
