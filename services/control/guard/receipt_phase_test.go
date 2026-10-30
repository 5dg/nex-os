package guard

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/5dg/nex-os/packages/broker"
	pb "github.com/5dg/nex-os/packages/contracts/gen/guardv1"
)

func TestReceiptPhaseParametersRequireExactScope(t *testing.T) {
	operation, digest, nonce := "operation-123", strings.Repeat("a", 64), strings.Repeat("b", 32)
	for _, tc := range []struct {
		phase  broker.ReceiptPhase
		nonce  string
		wire   pb.ReceiptPhase
		status string
	}{
		{broker.ReceiptDispatchPreflight, "", pb.ReceiptPhase_RECEIPT_DISPATCH_PREFLIGHT, "pending"},
		{broker.ReceiptDispatchEffect, nonce, pb.ReceiptPhase_RECEIPT_DISPATCH_EFFECT, "started"},
		{broker.ReceiptReceiverHandoff, nonce, pb.ReceiptPhase_RECEIPT_RECEIVER_HANDOFF, "started"},
		{broker.ReceiptCompletedRead, "", pb.ReceiptPhase_RECEIPT_COMPLETED_READ, "completed"},
	} {
		mapped, status, ok := phaseParameters(tc.phase, operation, digest, tc.nonce)
		if !ok || mapped != tc.wire || status != tc.status {
			t.Fatalf("phase %d mapped incorrectly", tc.phase)
		}
	}
	for _, tc := range []struct {
		phase             broker.ReceiptPhase
		op, digest, nonce string
	}{
		{0, operation, digest, ""}, {broker.ReceiptDispatchPreflight, operation, digest, nonce},
		{broker.ReceiptDispatchEffect, operation, digest, ""}, {broker.ReceiptReceiverHandoff, operation, digest, strings.Repeat("A", 32)},
		{broker.ReceiptCompletedRead, "bad/id", digest, ""}, {broker.ReceiptCompletedRead, operation, strings.Repeat("A", 64), ""},
	} {
		if _, _, ok := phaseParameters(tc.phase, tc.op, tc.digest, tc.nonce); ok {
			t.Fatalf("invalid phase/scope accepted: %+v", tc)
		}
	}
}

func TestReceiptPhaseAdapterFailsClosedWithoutAuthenticatedTransport(t *testing.T) {
	var client *Client
	if _, err := client.ReceiptPhaseAuthorizer([]byte("fixture"), nil); !errors.Is(err, broker.ErrUnknown) {
		t.Fatal("nil client accepted")
	}
	var adapter *receiptPhaseAuthorizer
	if _, err := adapter.CheckReceiptPhase(context.Background(), broker.ReceiptDispatchPreflight, broker.ReceiptClaim{}); !errors.Is(err, broker.ErrUnknown) {
		t.Fatal("nil adapter accepted")
	}
}
