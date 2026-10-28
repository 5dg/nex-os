package api

import (
	"context"
	"errors"
	"testing"

	"github.com/5dg/nex-os/packages/trust"
	"github.com/jackc/pgx/v5"
)

type admissionTx struct {
	pgx.Tx
	commits int
	nested  *admissionTx
}

func (tx *admissionTx) Commit(context.Context) error { tx.commits++; return nil }
func (tx *admissionTx) Begin(context.Context) (pgx.Tx, error) {
	tx.nested = &admissionTx{}
	return tx.nested, nil
}

func TestOriginalRequestCannotBeReplacedAtCommit(t *testing.T) {
	for _, test := range []struct {
		name   string
		expire bool
		cancel bool
		want   error
	}{{name: "valid"}, {name: "expired", expire: true, want: errForbidden}, {name: "cancelled", cancel: true, want: context.Canceled}} {
		t.Run(test.name, func(t *testing.T) {
			s := &Server{Profile: trust.Qualification}
			original, cancel := context.WithCancel(context.Background())
			defer cancel()
			identity := true
			ctx := context.WithValue(original, requestAuthorityKey{}, requestAuthority{original: original, current: func() error {
				if !identity {
					return trust.ErrIdentity
				}
				return nil
			}})
			underlying := &admissionTx{}
			tx := requestTx{Tx: underlying, check: func() error { return s.currentRequest(ctx) }}
			identity = !test.expire
			if test.cancel {
				cancel()
			}
			err := tx.Commit(context.Background())
			if !errors.Is(err, test.want) {
				t.Fatalf("replacement commit context returned %v, want %v", err, test.want)
			}
			wantCommits := 0
			if test.want == nil {
				wantCommits = 1
			}
			if underlying.commits != wantCommits {
				t.Fatal("replacement commit context bypassed original request authority")
			}
		})
	}
}

func TestNestedTransactionRetainsItsCancellation(t *testing.T) {
	s := &Server{Profile: trust.Qualification}
	root := context.WithValue(context.Background(), requestAuthorityKey{}, requestAuthority{original: context.Background(), current: func() error { return nil }})
	child, cancel := context.WithCancel(root)
	defer cancel()
	underlying := &admissionTx{}
	tx := requestTx{Tx: underlying, check: func() error { return s.currentRequest(root) }}
	nested, err := tx.Begin(child)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if e := nested.Commit(context.Background()); !errors.Is(e, context.Canceled) || underlying.nested.commits != 0 {
		t.Fatal("replacement context bypassed nested transaction cancellation")
	}
}

func TestOperationalAccountingCannotDispatchProtectedWork(t *testing.T) {
	s := &Server{Profile: trust.Qualification}
	if s.currentRequest(context.Background()) == nil {
		t.Fatal("qualification accepted a missing original request snapshot")
	}
	ctx := operationalAccounting(context.Background())
	underlying := &admissionTx{}
	tx := requestTx{Tx: underlying, check: func() error { return s.currentRequest(ctx) }}
	if e := tx.Commit(ctx); e != nil || underlying.commits != 1 {
		t.Fatal("bounded fenced accounting could not commit")
	}
	if s.beforeDispatch(ctx) == nil {
		t.Fatal("operational accounting permitted a new protected dispatch")
	}
	original, cancel := context.WithCancel(context.Background())
	cancel()
	if s.currentRequest(operationalAccounting(original)) == nil {
		t.Fatal("accounting ignored its own bounded context")
	}
}
