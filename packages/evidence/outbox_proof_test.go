package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestPinnedOutboxProofVerifier(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewPinnedOutboxProofVerifier(public)
	if err != nil {
		t.Fatal(err)
	}
	_, event := candidateEvidenceFixture()
	raw, err := json.Marshal(normalized(event))
	if err != nil {
		t.Fatal(err)
	}
	journal := &Journal{Directory: t.TempDir(), Private: private}
	proof, err := journal.Append(event)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	// The constructor must snapshot its trust anchor instead of retaining a
	// caller-owned mutable key slice.
	public[0] ^= 1
	if verifier.VerifyExact(context.Background(), raw, encoded) != nil {
		t.Fatal("valid proof rejected after caller mutated its key")
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := NewPinnedOutboxProofVerifier(other)
	if err != nil || wrongKey.VerifyExact(context.Background(), raw, encoded) == nil {
		t.Fatal("wrong trust anchor accepted")
	}
	if _, err := NewPinnedOutboxProofVerifier(nil); err == nil {
		t.Fatal("missing key accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if verifier.VerifyExact(ctx, raw, encoded) == nil {
		t.Fatal("cancelled verification accepted")
	}

	tests := map[string]struct{ event, proof []byte }{
		"altered event":         {[]byte(strings.Replace(string(raw), `"tenant-a"`, `"tenant-b"`, 1)), encoded},
		"noncanonical event":    {append([]byte(" "), raw...), encoded},
		"duplicate proof field": {raw, []byte(strings.Replace(string(encoded), `"sequence":1`, `"sequence":1,"sequence":1`, 1))},
		"null previous":         {raw, []byte(strings.Replace(string(encoded), `"previous":""`, `"previous":null`, 1))},
		"unknown proof field":   {raw, append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(`,"extra":1}`)...)},
		"bad signature":         {raw, []byte(strings.Replace(string(encoded), proof.Signature, strings.Repeat("A", len(proof.Signature)), 1))},
		"wrong sequence":        {raw, []byte(strings.Replace(string(encoded), `"sequence":1`, `"sequence":0`, 1))},
		"oversized proof":       {raw, make([]byte, 16*1024+1)},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if verifier.VerifyExact(context.Background(), tc.event, tc.proof) == nil {
				t.Fatal("invalid proof accepted")
			}
		})
	}
	proof.Sequence = 2
	proof.Previous = strings.Repeat("a", 64)
	proof.Head = hashEvent(event, proof.Previous)
	proof.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message(proof)))
	encoded, err = json.Marshal(proof)
	if err != nil || verifier.VerifyExact(context.Background(), raw, encoded) != nil {
		t.Fatal("valid later-sequence proof rejected")
	}
}
