package api

import (
	"encoding/json"
	"testing"

	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
)

func TestReconciledResultMustMatchProtectedOperation(t *testing.T) {
	j := storedJob{ReviewJob: contracts.ReviewJob{TenantID: "tenant-a", Phase: "review", Answer: "answer", Provider: "provider"}, Operation: "operation-a"}
	in := contracts.Generation{OperationID: j.Operation, TenantID: j.TenantID, RouteID: "route", Classification: "confidential", Prompt: "prompt", MaxTokens: 10}
	result := contracts.GenerationResult{Text: j.Answer, Provider: j.Provider, ModelID: "model"}
	protected, _ := json.Marshal(result)
	digest := contracts.ExecutionDigest(in)
	if digest == "" || !validReconciledResult(j, "model", in, &result, digest, protected) {
		t.Fatal("valid protected model result rejected")
	}
	for name, check := range map[string]func() bool{
		"substituted response": func() bool {
			forged := result
			forged.Text = "forged"
			return validReconciledResult(j, "model", in, &forged, digest, protected)
		},
		"wrong digest": func() bool {
			return validReconciledResult(j, "model", in, &result, broker.Hash([]byte("wrong")), protected)
		},
		"different tenant": func() bool {
			changed := j
			changed.TenantID = "other"
			return validReconciledResult(changed, "model", in, &result, digest, protected)
		},
		"different operation": func() bool {
			changed := j
			changed.Operation = "other"
			return validReconciledResult(changed, "model", in, &result, digest, protected)
		},
		"different phase": func() bool {
			changed := j
			changed.Phase = "export"
			return validReconciledResult(changed, "model", in, &result, digest, protected)
		},
		"different job answer": func() bool {
			changed := j
			changed.Answer = "other"
			return validReconciledResult(changed, "model", in, &result, digest, protected)
		},
		"missing protected result": func() bool { return validReconciledResult(j, "model", in, &result, digest, nil) },
		"unknown kind":             func() bool { return validReconciledResult(j, "other", in, &result, digest, protected) },
	} {
		t.Run(name, func(t *testing.T) {
			if check() {
				t.Fatal("unverified result accepted")
			}
		})
	}
}

func TestReconciledExportMustMatchProtectedArtifact(t *testing.T) {
	j := storedJob{ReviewJob: contracts.ReviewJob{TenantID: "tenant-a", Phase: "export", ExportID: "operation-a"}, Operation: "operation-a"}
	in := contracts.Export{OperationID: j.Operation, TenantID: j.TenantID, DestinationID: "destination", Content: "evidence", RequestDigest: broker.Hash([]byte("request"))}
	result := contracts.ExportResult{ArtifactID: j.Operation, ContentDigest: broker.Hash([]byte(in.Content))}
	protected, _ := json.Marshal(result)
	digest := contracts.ExecutionDigest(in)
	if digest == "" || !validReconciledResult(j, "export", in, &result, digest, protected) {
		t.Fatal("valid protected export rejected")
	}
	for name, check := range map[string]func() bool{
		"substituted response": func() bool {
			forged := result
			forged.ContentDigest = broker.Hash([]byte("other"))
			return validReconciledResult(j, "export", in, &forged, digest, protected)
		},
		"wrong job artifact": func() bool {
			changed := j
			changed.ExportID = "other"
			return validReconciledResult(changed, "export", in, &result, digest, protected)
		},
		"wrong operation": func() bool {
			changed := j
			changed.Operation = "other"
			return validReconciledResult(changed, "export", in, &result, digest, protected)
		},
		"wrong digest": func() bool {
			return validReconciledResult(j, "export", in, &result, broker.Hash([]byte("other")), protected)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if check() {
				t.Fatal("unverified export accepted")
			}
		})
	}
}
