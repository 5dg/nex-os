package executor

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
)

// This private seam permits failure and ordering tests; exported operations
// require the concrete PostgreSQL store. Trusted production wiring must still
// supply an authenticated phase/claim authority and an effect-spanning fence.
type phasedExportReceipts interface {
	DoPhasedAuthorized(context.Context, string, string, broker.ReceiptPhaseAuthorizer, func(context.Context, broker.ReceiptClaim) error, func(context.Context) (any, error)) (json.RawMessage, error)
	ReadPhasedCompleted(context.Context, string, string, broker.ReceiptPhaseAuthorizer) (json.RawMessage, error)
}

// ExecutePhased performs a single export and hands its metadata to the
// authenticated receiver for Guard completion. It cannot replay a completed
// receipt or fall back to the legacy unphased path. Production wiring remains
// disabled pending real claimant identity and provider-spanning fencing.
func (s *S3ExportStore) ExecutePhased(ctx context.Context, in contracts.Export, digest string, receipts *broker.PostgresReceiptStore, auth broker.ReceiptPhaseAuthorizer, authorize func(context.Context, broker.ReceiptClaim) error) (contracts.ExportResult, error) {
	if receipts == nil {
		return contracts.ExportResult{}, invalidExport
	}
	return s.executePhased(ctx, in, digest, receipts, auth, authorize)
}

func (s *S3ExportStore) executePhased(ctx context.Context, in contracts.Export, digest string, receipts phasedExportReceipts, auth broker.ReceiptPhaseAuthorizer, authorize func(context.Context, broker.ReceiptClaim) error) (contracts.ExportResult, error) {
	var empty contracts.ExportResult
	if ctx == nil || receipts == nil || auth == nil || authorize == nil {
		return empty, invalidExport
	}
	key, contentDigest, err := s.validate(in, digest)
	if err != nil {
		return empty, invalidExport
	}
	ctx, cancel := s.boundedContext(ctx)
	defer cancel()
	raw, err := receipts.DoPhasedAuthorized(ctx, in.OperationID, digest, auth, authorize, func(effectCtx context.Context) (any, error) {
		rec, _, err := s.putVerified(effectCtx, in, digest, key, contentDigest)
		if err != nil {
			return nil, broker.ErrUnknown
		}
		return rec, nil
	})
	if err != nil {
		return empty, err
	}
	rec, err := s.decodeS3Receipt(raw, in.OperationID, key, contentDigest)
	if err != nil {
		return empty, invalidExport
	}
	return contracts.ExportResult{ArtifactID: rec.ArtifactID, ContentDigest: rec.ContentDigest}, nil
}

// RetrievePhased releases only a completed Guard/receipt result. It checks
// current authority again after reading and validating the exact object.
func (s *S3ExportStore) RetrievePhased(ctx context.Context, in contracts.Export, digest string, receipts *broker.PostgresReceiptStore, auth broker.ReceiptPhaseAuthorizer) ([]byte, error) {
	if receipts == nil {
		return nil, invalidExport
	}
	return s.retrievePhased(ctx, in, digest, receipts, auth)
}

func (s *S3ExportStore) retrievePhased(ctx context.Context, in contracts.Export, digest string, receipts phasedExportReceipts, auth broker.ReceiptPhaseAuthorizer) ([]byte, error) {
	if ctx == nil || receipts == nil || auth == nil {
		return nil, invalidExport
	}
	key, contentDigest, err := s.validate(in, digest)
	if err != nil {
		return nil, invalidExport
	}
	ctx, cancel := s.boundedContext(ctx)
	defer cancel()
	raw, err := receipts.ReadPhasedCompleted(ctx, in.OperationID, digest, auth)
	if err != nil {
		return nil, err
	}
	rec, err := s.decodeS3Receipt(raw, in.OperationID, key, contentDigest)
	if err != nil {
		return nil, invalidExport
	}
	client, err := s.authenticatedClient(ctx)
	if err != nil {
		return nil, invalidExport
	}
	content, err := s.readExact(ctx, client, in, digest, rec)
	if err != nil {
		return nil, invalidExport
	}
	current, err := receipts.ReadPhasedCompleted(ctx, in.OperationID, digest, auth)
	if err != nil || !bytes.Equal(current, raw) {
		return nil, invalidExport
	}
	return content, nil
}
