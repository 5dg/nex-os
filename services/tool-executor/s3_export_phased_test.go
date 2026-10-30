package executor

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
)

// This seam models receipt decisions only. It is not claimant or fence proof;
// actual PostgreSQL custody and mTLS Guard tests run separately.
type phasedReceiptFixture struct {
	result         json.RawMessage
	completed      bool
	reads          int
	denySecondRead bool
	refuseDispatch bool
}

func (f *phasedReceiptFixture) DoPhasedAuthorized(ctx context.Context, _, _ string, auth broker.ReceiptPhaseAuthorizer, authorize func(context.Context, broker.ReceiptClaim) error, effect func(context.Context) (any, error)) (json.RawMessage, error) {
	if f.refuseDispatch || f.result != nil || auth == nil {
		return nil, broker.ErrUnknown
	}
	if authorize(ctx, broker.ReceiptClaim{}) != nil {
		return nil, broker.ErrUnknown
	}
	v, err := effect(ctx)
	if err != nil {
		return nil, broker.ErrUnknown
	}
	f.result, err = json.Marshal(v)
	if err != nil {
		return nil, broker.ErrUnknown
	}
	return append(json.RawMessage(nil), f.result...), nil
}
func (f *phasedReceiptFixture) ReadPhasedCompleted(_ context.Context, _, _ string, auth broker.ReceiptPhaseAuthorizer) (json.RawMessage, error) {
	f.reads++
	if auth == nil || !f.completed || f.result == nil || (f.denySecondRead && f.reads%2 == 0) {
		return nil, broker.ErrUnknown
	}
	return append(json.RawMessage(nil), f.result...), nil
}

type fixturePhasedAuthority struct{}

func (fixturePhasedAuthority) CheckReceiptPhase(context.Context, broker.ReceiptPhase, broker.ReceiptClaim) (string, error) {
	return "", nil
}

func TestS3PhasedHandoffAndCompletedRead(t *testing.T) {
	s, server := newS3Fixture(t)
	in := fixtureExport()
	digest := contracts.ExecutionDigest(in)
	receipts := &phasedReceiptFixture{}
	grants := 0
	authorize := func(context.Context, broker.ReceiptClaim) error { grants++; return nil }
	result, err := s.executePhased(context.Background(), in, digest, receipts, fixturePhasedAuthority{}, authorize)
	if err != nil || result.ArtifactID != in.OperationID || grants != 1 {
		t.Fatal("receiver handoff failed")
	}
	if body, err := s.retrievePhased(context.Background(), in, digest, receipts, fixturePhasedAuthority{}); err == nil || body != nil {
		t.Fatal("uncompleted Guard operation released content")
	}
	if _, err := s.executePhased(context.Background(), in, digest, receipts, fixturePhasedAuthority{}, authorize); !errors.Is(err, broker.ErrUnknown) {
		t.Fatal("completed receipt was replayed as an effect")
	}
	server.mu.Lock()
	puts := 0
	for _, request := range server.requests {
		if strings.HasPrefix(request, "PUT ") {
			puts++
		}
	}
	server.mu.Unlock()
	if puts != 1 || grants != 1 {
		t.Fatal("completed effect was repeated")
	}
	receipts.completed = true
	content, err := s.retrievePhased(context.Background(), in, digest, receipts, fixturePhasedAuthority{})
	if err != nil || string(content) != in.Content {
		t.Fatal("completed phased read failed")
	}
	receipts.reads = 0
	receipts.denySecondRead = true
	if content, err = s.retrievePhased(context.Background(), in, digest, receipts, fixturePhasedAuthority{}); err == nil || content != nil {
		t.Fatal("revoked access released fetched bytes")
	}
}

func TestS3PhasedDenialDoesNotFallbackOrContactProvider(t *testing.T) {
	s, server := newS3Fixture(t)
	in := fixtureExport()
	digest := contracts.ExecutionDigest(in)
	_, err := s.executePhased(context.Background(), in, digest, &phasedReceiptFixture{refuseDispatch: true}, fixturePhasedAuthority{}, func(context.Context, broker.ReceiptClaim) error { t.Error("denied dispatch invoked Guard"); return nil })
	server.mu.Lock()
	requests := len(server.requests)
	server.mu.Unlock()
	if !errors.Is(err, broker.ErrUnknown) || requests != 0 {
		t.Fatal("denied phased dispatch fell back or contacted provider")
	}
}
