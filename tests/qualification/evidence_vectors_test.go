package qualification_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/evidence"
)

// These fixed goldens came from the existing Go v1 journal writer before the
// Rust parity fix. Expected bytes/heads are not recomputed by a test-side copy
// of the proposed Rust canonicalizer. Signatures use a public test-only seed.
func TestEvidenceV1GoldenVectorsPreserveExistingGoProofs(t *testing.T) {
	raw, err := os.ReadFile("../../packages/evidence/event-v1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name          string         `json:"name"`
		EventJSON     string         `json:"event_json"`
		CanonicalJSON string         `json:"canonical_json"`
		Previous      string         `json:"previous"`
		Head          string         `json:"head"`
		Public        string         `json:"public_key"`
		Proof         evidence.Proof `json:"proof"`
	}
	if json.Unmarshal(raw, &vectors) != nil || len(vectors) != 6 {
		t.Fatal("six fixed existing-format golden cases are required")
	}
	previous := ""
	for i, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			public, err := base64.RawURLEncoding.DecodeString(vector.Public)
			if err != nil || len(public) != ed25519.PublicKeySize {
				t.Fatal("invalid golden public test key")
			}
			if !json.Valid([]byte(vector.CanonicalJSON)) || broker.Hash([]byte(vector.CanonicalJSON)) != vector.Head {
				t.Fatal("fixed canonical bytes do not match the fixed head")
			}
			if vector.Previous != previous || vector.Proof.Previous != previous || vector.Proof.Sequence != i+1 || vector.Proof.Head != vector.Head {
				t.Fatal("golden previous link/sequence changed")
			}
			var event evidence.Event
			if json.Unmarshal([]byte(vector.EventJSON), &event) != nil {
				t.Fatal("invalid golden outbound event")
			}
			event.Producer = "kernel" // Authenticated /append/kernel assignment.
			if !evidence.VerifyProof(public, vector.Proof) || !evidence.VerifyEvent(public, vector.Proof, event) {
				t.Fatal("existing Go verifier rejected its historical v1 golden")
			}
			originalAction := event.Action
			event.Action += ".changed"
			if evidence.VerifyEvent(public, vector.Proof, event) {
				t.Fatal("valid original signature authenticated altered content")
			}
			event.Action = originalAction
			changedLink := vector.Proof
			changedLink.Previous = "different previous link"
			if !evidence.VerifyProof(public, changedLink) || evidence.VerifyEvent(public, changedLink, event) {
				t.Fatal("link/content binding or signature-domain semantics changed")
			}
		})
		previous = vector.Head
	}
}
