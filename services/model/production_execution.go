package model

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"
	"unicode/utf8"

	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
)

// ProductionModelManifestAuthority obtains the exact v3 digest from an
// independently authenticated Guard authority. It must verify the current
// caller, tenant and operation; a digest copied from a request is insufficient.
type ProductionModelManifestAuthority interface {
	AuthorizedModelDigest(context.Context, contracts.Generation) (string, error)
}

type phasedModelReceipts interface {
	DoPhasedAuthorized(context.Context, string, string, broker.ReceiptPhaseAuthorizer, func(context.Context, broker.ReceiptClaim) error, func(context.Context) (any, error)) (json.RawMessage, error)
	ReadPhasedCompleted(context.Context, string, string, broker.ReceiptPhaseAuthorizer) (json.RawMessage, error)
}

// ProductionModelCoordinator composes a sealed Bedrock route and phase-aware
// receipts. No runtime profile constructs it. The injected authorities must
// authenticate the real caller/claim, and custody must supply an independently
// proven effect-spanning fence before a production integration is possible.
// All injected authorities must honor context cancellation and deadlines;
// a callback that ignores context can block beyond the configured timeout.
type ProductionModelCoordinator struct {
	adapter   *AccountBoundBedrock
	policy    ProductionModelPolicy
	receipts  phasedModelReceipts
	manifest  ProductionModelManifestAuthority
	phase     broker.ReceiptPhaseAuthorizer
	authorize func(context.Context, broker.ReceiptClaim) error
	timeout   time.Duration
}

func nonNilDependency(value any) bool {
	if value == nil {
		return false
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return !v.IsNil()
	default:
		return true
	}
}

// NewProductionModelCoordinator requires explicit trusted configuration and
// a concrete PostgreSQL receipt store. timeout is operator-supplied; it must
// be positive and no greater than five minutes, with no implicit default.
func NewProductionModelCoordinator(adapter *AccountBoundBedrock, policy ProductionModelPolicy, receipts *broker.PostgresReceiptStore, manifest ProductionModelManifestAuthority, phase broker.ReceiptPhaseAuthorizer, authorize func(context.Context, broker.ReceiptClaim) error, timeout time.Duration) (*ProductionModelCoordinator, error) {
	if !adapter.validAccountBinding() || receipts == nil || !nonNilDependency(manifest) || !nonNilDependency(phase) || authorize == nil || timeout <= 0 || timeout > 5*time.Minute {
		return nil, errors.New("sealed model route and complete bounded authority required")
	}
	policy.AllowedClassifications = append([]string(nil), policy.AllowedClassifications...)
	return &ProductionModelCoordinator{adapter: adapter, policy: policy, receipts: receipts, manifest: manifest, phase: phase, authorize: authorize, timeout: timeout}, nil
}

func (c *ProductionModelCoordinator) prepare(ctx context.Context, in contracts.Generation) (context.Context, context.CancelFunc, contracts.Generation, string, error) {
	if c == nil || ctx == nil || !c.adapter.validAccountBinding() || !nonNilDependency(c.receipts) || !nonNilDependency(c.manifest) || !nonNilDependency(c.phase) || c.authorize == nil || c.timeout <= 0 || c.timeout > 5*time.Minute {
		return nil, nil, contracts.Generation{}, "", broker.ErrUnknown
	}
	in.Features = append([]string(nil), in.Features...)
	bounded, cancel := context.WithTimeout(ctx, c.timeout)
	digest, err := c.manifest.AuthorizedModelDigest(bounded, in)
	if err != nil || bounded.Err() != nil {
		cancel()
		return nil, nil, contracts.Generation{}, "", broker.ErrUnknown
	}
	if _, err := ValidateProductionModelBinding(in, c.adapter.base, c.policy, digest); err != nil {
		cancel()
		return nil, nil, contracts.Generation{}, "", broker.ErrUnknown
	}
	return bounded, cancel, in, digest, nil
}

func decodeProductionModelResult(raw json.RawMessage, in contracts.Generation) (contracts.GenerationResult, error) {
	if !utf8.Valid(raw) {
		return contracts.GenerationResult{}, broker.ErrUnknown
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return contracts.GenerationResult{}, broker.ErrUnknown
	}
	fields := map[string]string{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return contracts.GenerationResult{}, broker.ErrUnknown
		}
		name, ok := token.(string)
		if !ok || (name != "text" && name != "provider" && name != "model_id") {
			return contracts.GenerationResult{}, broker.ErrUnknown
		}
		if _, exists := fields[name]; exists {
			return contracts.GenerationResult{}, broker.ErrUnknown
		}
		var value string
		if decoder.Decode(&value) != nil {
			return contracts.GenerationResult{}, broker.ErrUnknown
		}
		fields[name] = value
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim('}') || decoder.Decode(new(any)) != io.EOF || len(fields) != 3 {
		return contracts.GenerationResult{}, broker.ErrUnknown
	}
	out := contracts.GenerationResult{Text: fields["text"], Provider: fields["provider"], ModelID: fields["model_id"]}
	if out.Text == "" || len(out.Text) > 12000 || !utf8.ValidString(out.Text) || out.Provider != in.Provider || out.ModelID != in.ModelID {
		return contracts.GenerationResult{}, broker.ErrUnknown
	}
	return out, nil
}

// Execute hands a fresh result only to the authenticated receiver so it can
// complete Guard. It never replays a completed/uncertain effect or falls back.
func (c *ProductionModelCoordinator) Execute(ctx context.Context, in contracts.Generation) (contracts.GenerationResult, error) {
	bounded, cancel, in, digest, err := c.prepare(ctx, in)
	if err != nil {
		return contracts.GenerationResult{}, err
	}
	defer cancel()
	raw, err := c.receipts.DoPhasedAuthorized(bounded, in.OperationID, digest, c.phase, c.authorize, func(effectCtx context.Context) (any, error) {
		return c.adapter.Generate(effectCtx, in)
	})
	if err != nil {
		return contracts.GenerationResult{}, err
	}
	if bounded.Err() != nil {
		return contracts.GenerationResult{}, broker.ErrUnknown
	}
	return decodeProductionModelResult(raw, in)
}

// ReadCompleted returns only a completed Guard/receipt result after fresh
// manifest and phase authorization. It never calls the provider.
func (c *ProductionModelCoordinator) ReadCompleted(ctx context.Context, in contracts.Generation) (contracts.GenerationResult, error) {
	bounded, cancel, in, digest, err := c.prepare(ctx, in)
	if err != nil {
		return contracts.GenerationResult{}, err
	}
	defer cancel()
	raw, err := c.receipts.ReadPhasedCompleted(bounded, in.OperationID, digest, c.phase)
	if err != nil {
		return contracts.GenerationResult{}, err
	}
	result, err := decodeProductionModelResult(raw, in)
	if err != nil {
		return contracts.GenerationResult{}, err
	}
	current, err := c.receipts.ReadPhasedCompleted(bounded, in.OperationID, digest, c.phase)
	if err != nil || bounded.Err() != nil || !bytes.Equal(raw, current) {
		return contracts.GenerationResult{}, broker.ErrUnknown
	}
	return result, nil
}
