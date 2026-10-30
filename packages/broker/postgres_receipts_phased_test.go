package broker

import "testing"

func TestReceiptPhasesRejectWrongGuardStates(t *testing.T) {
	statuses := []string{"", "pending", "started", "completed", "unknown", "denied", "future-status"}
	want := map[ReceiptPhase]string{
		ReceiptDispatchPreflight: "pending",
		ReceiptDispatchEffect:    "started",
		ReceiptReceiverHandoff:   "started",
		ReceiptCompletedRead:     "completed",
	}
	for phase, valid := range want {
		for _, status := range statuses {
			if got := receiptPhaseStatusAllowed(phase, status); got != (status == valid) {
				t.Fatalf("phase %d status %q accepted=%v", phase, status, got)
			}
		}
	}
	for _, phase := range []ReceiptPhase{0, ReceiptCompletedRead + 1, 255} {
		for _, status := range statuses {
			if receiptPhaseStatusAllowed(phase, status) {
				t.Fatalf("unknown phase %d accepted %q", phase, status)
			}
		}
	}
}
