package evidence

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func candidateEvidenceFixture() (CandidateEvidenceScope, Event) {
	s := CandidateEvidenceScope{EventID: "event-001", TenantID: "tenant-a", ActorID: "alice", JobID: "job-0001", ResourceID: "document", ResourceVersion: "v1", DelegationID: "delegation", OperationID: "operation-001", PayloadDigest: strings.Repeat("a", 64), ContextDigest: strings.Repeat("b", 64)}
	detail := json.RawMessage(fmt.Sprintf(`{"operation_id":%q,"document_id":%q,"document_version":%q,"candidate_context_digest":%q,"provenance":{"payload_digest":%q}}`, s.OperationID, s.ResourceID, s.ResourceVersion, s.ContextDigest, s.PayloadDigest))
	return s, Event{ID: s.EventID, TenantID: s.TenantID, ActorID: s.ActorID, JobID: s.JobID, Producer: "kernel", Action: "model.prepared", Timestamp: 123, ResourceID: s.ResourceID, DelegationID: s.DelegationID, Detail: detail}
}

func TestCandidateEvidenceEventBindsExactScopeAndRejectsAmbiguity(t *testing.T) {
	s, event := candidateEvidenceFixture()
	first, err := canonicalCandidateEvent(s, event)
	if err != nil {
		t.Fatal(err)
	}
	second, err := canonicalCandidateEvent(s, event)
	if err != nil || string(first) != string(second) {
		t.Fatal("canonical event changed")
	}
	for _, mutate := range []func(*CandidateEvidenceScope){func(x *CandidateEvidenceScope) { x.TenantID = "other" }, func(x *CandidateEvidenceScope) { x.ActorID = "other" }, func(x *CandidateEvidenceScope) { x.JobID = "job-other" }, func(x *CandidateEvidenceScope) { x.ResourceID = "other-document" }, func(x *CandidateEvidenceScope) { x.ResourceID = "" }, func(x *CandidateEvidenceScope) { x.ResourceVersion = "v2" }, func(x *CandidateEvidenceScope) { x.ResourceVersion = "" }, func(x *CandidateEvidenceScope) { x.DelegationID = "other-delegation" }, func(x *CandidateEvidenceScope) { x.DelegationID = "" }, func(x *CandidateEvidenceScope) { x.OperationID = "operation-other" }, func(x *CandidateEvidenceScope) { x.PayloadDigest = strings.Repeat("c", 64) }, func(x *CandidateEvidenceScope) { x.ContextDigest = strings.Repeat("d", 64) }} {
		changed := s
		mutate(&changed)
		if _, err := canonicalCandidateEvent(changed, event); err == nil {
			t.Fatal("mismatched scope accepted")
		}
	}
	for _, mutate := range []func(*Event){func(x *Event) { x.ResourceID = "other-document" }, func(x *Event) { x.ResourceID = "" }, func(x *Event) { x.DelegationID = "other-delegation" }, func(x *Event) { x.DelegationID = "" }} {
		changed := event
		mutate(&changed)
		if _, err := canonicalCandidateEvent(s, changed); err == nil {
			t.Fatal("substituted or empty event authority accepted")
		}
	}
	for _, raw := range []string{
		fmt.Sprintf(`{"operation_id":%q,"operation_id":%q,"document_id":%q,"document_version":%q,"candidate_context_digest":%q,"provenance":{"payload_digest":%q}}`, s.OperationID, s.OperationID, s.ResourceID, s.ResourceVersion, s.ContextDigest, s.PayloadDigest),
		fmt.Sprintf(`{"operation_id":%q,"document_id":%q,"document_version":%q,"candidate_context_digest":%q,"provenance":{"payload_digest":%q,"payload_digest":%q}}`, s.OperationID, s.ResourceID, s.ResourceVersion, s.ContextDigest, s.PayloadDigest, s.PayloadDigest),
		fmt.Sprintf(`{"operation_id":%q,"document_id":"other","document_version":%q,"candidate_context_digest":%q,"provenance":{"payload_digest":%q}}`, s.OperationID, s.ResourceVersion, s.ContextDigest, s.PayloadDigest),
		fmt.Sprintf(`{"operation_id":%q,"document_id":%q,"document_version":"v2","candidate_context_digest":%q,"provenance":{"payload_digest":%q}}`, s.OperationID, s.ResourceID, s.ContextDigest, s.PayloadDigest),
	} {
		changed := event
		changed.Detail = json.RawMessage(raw)
		if _, err := canonicalCandidateEvent(s, changed); err == nil {
			t.Fatal("duplicate bound JSON accepted")
		}
	}
}
