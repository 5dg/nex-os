package evidence

import (
	"encoding/json"
	"os"
	"testing"
)

// This is the same fixture consumed by the Rust transaction bridge. The
// expected bytes are checked independently against the Go journal encoding.
func TestCandidateOutboxCrossLanguageCanonicalVector(t *testing.T) {
	var vectors []struct {
		Scope struct {
			EventID         string `json:"event_id"`
			TenantID        string `json:"tenant_id"`
			ActorID         string `json:"actor_id"`
			JobID           string `json:"job_id"`
			ResourceID      string `json:"resource_id"`
			ResourceVersion string `json:"resource_version"`
			DelegationID    string `json:"delegation_id"`
			OperationID     string `json:"operation_id"`
			PayloadDigest   string `json:"payload_digest"`
			ContextDigest   string `json:"context_digest"`
		} `json:"scope"`
		Event     Event  `json:"event"`
		Canonical string `json:"canonical"`
	}
	bytes, err := os.ReadFile("candidate-outbox-vectors.json")
	if err != nil || json.Unmarshal(bytes, &vectors) != nil || len(vectors) != 1 {
		t.Fatal("invalid candidate vector")
	}
	for _, v := range vectors {
		s := CandidateEvidenceScope{EventID: v.Scope.EventID, TenantID: v.Scope.TenantID, ActorID: v.Scope.ActorID, JobID: v.Scope.JobID, ResourceID: v.Scope.ResourceID, ResourceVersion: v.Scope.ResourceVersion, DelegationID: v.Scope.DelegationID, OperationID: v.Scope.OperationID, PayloadDigest: v.Scope.PayloadDigest, ContextDigest: v.Scope.ContextDigest}
		actual, err := canonicalCandidateEvent(s, v.Event)
		if err != nil || string(actual) != v.Canonical {
			t.Fatal("Go candidate event bytes differ from shared vector")
		}
	}
}
