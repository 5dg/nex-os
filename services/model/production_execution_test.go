package model

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
)

type modelManifestFunc func(context.Context, contracts.Generation) (string, error)

func (f modelManifestFunc) AuthorizedModelDigest(ctx context.Context, in contracts.Generation) (string, error) {
	return f(ctx, in)
}

type modelPhaseFixture struct{}

func (modelPhaseFixture) CheckReceiptPhase(context.Context, broker.ReceiptPhase, broker.ReceiptClaim) (string, error) {
	return "", nil
}

type modelReceiptFixture struct {
	result                             json.RawMessage
	started, completed, denySecondRead bool
	reads                              int
}

func (f *modelReceiptFixture) DoPhasedAuthorized(ctx context.Context, _, _ string, _ broker.ReceiptPhaseAuthorizer, authorize func(context.Context, broker.ReceiptClaim) error, effect func(context.Context) (any, error)) (json.RawMessage, error) {
	if f.started || authorize(ctx, broker.ReceiptClaim{}) != nil {
		return nil, broker.ErrUnknown
	}
	f.started = true
	value, err := effect(ctx)
	if err != nil {
		return nil, broker.ErrUnknown
	}
	f.result, err = json.Marshal(value)
	return append(json.RawMessage(nil), f.result...), err
}
func (f *modelReceiptFixture) ReadPhasedCompleted(context.Context, string, string, broker.ReceiptPhaseAuthorizer) (json.RawMessage, error) {
	f.reads++
	if !f.completed || f.result == nil || (f.denySecondRead && f.reads == 2) {
		return nil, broker.ErrUnknown
	}
	return append(json.RawMessage(nil), f.result...), nil
}

func modelCoordinatorFixture() (*ProductionModelCoordinator, contracts.Generation, *converseStub, *modelReceiptFixture) {
	in, adapter, policy := productionBindingFixture()
	provider := adapter.route.client.(*converseStub)
	receipts := &modelReceiptFixture{}
	c := &ProductionModelCoordinator{adapter: adapter, policy: policy, receipts: receipts, manifest: modelManifestFunc(func(_ context.Context, in contracts.Generation) (string, error) {
		return contracts.ExecutionDigest(in), nil
	}), phase: modelPhaseFixture{}, authorize: func(context.Context, broker.ReceiptClaim) error { return nil }, timeout: time.Second}
	return c, in, provider, receipts
}

func TestModelCoordinatorHandoffAndCompletedRead(t *testing.T) {
	c, in, provider, receipts := modelCoordinatorFixture()
	result, err := c.Execute(context.Background(), in)
	if err != nil || result.Text != "synthetic provider response" || provider.calls != 1 {
		t.Fatal("authenticated receiver handoff failed")
	}
	if result, err = c.ReadCompleted(context.Background(), in); err == nil || result.Text != "" {
		t.Fatal("uncompleted result was released")
	}
	if _, err = c.Execute(context.Background(), in); !errors.Is(err, broker.ErrUnknown) || provider.calls != 1 {
		t.Fatal("completed or uncertain effect was repeated")
	}
	receipts.completed = true
	receipts.reads = 0
	if result, err = c.ReadCompleted(context.Background(), in); err != nil || result.Text != "synthetic provider response" || provider.calls != 1 {
		t.Fatal("completed read failed or invoked provider")
	}
	receipts.reads = 0
	receipts.denySecondRead = true
	if result, err = c.ReadCompleted(context.Background(), in); err == nil || result.Text != "" {
		t.Fatal("revoked completed read returned content")
	}
}

func TestModelCoordinatorDeniesUntrustedManifestAndAmbiguousProvider(t *testing.T) {
	c, in, provider, _ := modelCoordinatorFixture()
	c.manifest = modelManifestFunc(func(context.Context, contracts.Generation) (string, error) { return strings.Repeat("0", 64), nil })
	if _, err := c.Execute(context.Background(), in); !errors.Is(err, broker.ErrUnknown) || provider.calls != 0 {
		t.Fatal("wrong Guard digest reached provider")
	}
	c, in, provider, _ = modelCoordinatorFixture()
	provider.failure = true
	if _, err := c.Execute(context.Background(), in); !errors.Is(err, broker.ErrUnknown) || provider.calls != 1 {
		t.Fatal("ambiguous provider outcome was not unknown")
	}
	if _, err := c.Execute(context.Background(), in); !errors.Is(err, broker.ErrUnknown) || provider.calls != 1 {
		t.Fatal("ambiguous provider call was retried")
	}
}

func TestModelCoordinatorRequiresBoundedTrustedDependencies(t *testing.T) {
	in, adapter, policy := productionBindingFixture()
	manifest := modelManifestFunc(func(_ context.Context, in contracts.Generation) (string, error) {
		return contracts.ExecutionDigest(in), nil
	})
	grant := func(context.Context, broker.ReceiptClaim) error { return nil }
	for _, timeout := range []time.Duration{0, -1, 5*time.Minute + 1} {
		if _, err := NewProductionModelCoordinator(adapter, policy, &broker.PostgresReceiptStore{}, manifest, modelPhaseFixture{}, grant, timeout); err == nil {
			t.Fatal("unbounded timeout accepted")
		}
	}
	if _, err := NewProductionModelCoordinator(nil, policy, &broker.PostgresReceiptStore{}, manifest, modelPhaseFixture{}, grant, time.Second); err == nil {
		t.Fatal("unsealed adapter accepted")
	}
	var nilManifest modelManifestFunc
	if _, err := NewProductionModelCoordinator(adapter, policy, &broker.PostgresReceiptStore{}, nilManifest, modelPhaseFixture{}, grant, time.Second); err == nil {
		t.Fatal("nil manifest authority accepted")
	}
	c, err := NewProductionModelCoordinator(adapter, policy, &broker.PostgresReceiptStore{}, manifest, modelPhaseFixture{}, grant, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	policy.AllowedClassifications[1] = "restricted"
	bounded, cancel, _, _, err := c.prepare(context.Background(), in)
	if err != nil || bounded == nil {
		t.Fatal("trusted policy changed through caller-owned slice")
	}
	cancel()
	c, in, _, _ = modelCoordinatorFixture()
	c.timeout = 20 * time.Millisecond
	c.manifest = modelManifestFunc(func(ctx context.Context, _ contracts.Generation) (string, error) { <-ctx.Done(); return "", ctx.Err() })
	if _, err := c.Execute(context.Background(), in); !errors.Is(err, broker.ErrUnknown) {
		t.Fatal("manifest deadline did not fail closed")
	}
}

func TestModelCoordinatorRejectsMalformedReceipt(t *testing.T) {
	_, in, _, _ := modelCoordinatorFixture()
	valid, err := json.Marshal(contracts.GenerationResult{Text: "a", Provider: in.Provider, ModelID: in.ModelID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeProductionModelResult(valid, in); err != nil {
		t.Fatal("valid receipt rejected")
	}
	duplicate := fmt.Sprintf(`{"text":"a","text":"b","provider":%q,"model_id":%q}`, in.Provider, in.ModelID)
	extra := fmt.Sprintf(`{"text":"a","provider":%q,"model_id":%q,"extra":1}`, in.Provider, in.ModelID)
	for _, raw := range []string{`null`, duplicate, extra, `{"text":"a"} trailing`, string([]byte{0xff})} {
		if _, err := decodeProductionModelResult(json.RawMessage(raw), in); !errors.Is(err, broker.ErrUnknown) {
			t.Fatal("malformed or mismatched receipt accepted")
		}
	}
}
