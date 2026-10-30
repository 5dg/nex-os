package evidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
)

// PinnedOutboxProofVerifier checks the existing evidence-v1 proof format with
// one explicitly pinned key. It authenticates the event and proof, but cannot
// establish independent key custody, journal continuity, or rollback safety.
type PinnedOutboxProofVerifier struct {
	public ed25519.PublicKey
}

var _ OutboxProofVerifier = (*PinnedOutboxProofVerifier)(nil)

func NewPinnedOutboxProofVerifier(public ed25519.PublicKey) (*PinnedOutboxProofVerifier, error) {
	if len(public) != ed25519.PublicKeySize {
		return nil, ErrOutboxUnknown
	}
	return &PinnedOutboxProofVerifier{public: append(ed25519.PublicKey(nil), public...)}, nil
}

// VerifyExact rejects ambiguous or noncanonical event bytes, malformed proof
// fields, and a signature that is not bound to these exact event contents.
func (v *PinnedOutboxProofVerifier) VerifyExact(ctx context.Context, raw, proofBytes []byte) error {
	if ctx == nil || ctx.Err() != nil || v == nil || len(v.public) != ed25519.PublicKeySize || len(raw) == 0 || len(raw) > 128*1024 || len(proofBytes) == 0 || len(proofBytes) > 16*1024 {
		return ErrOutboxUnknown
	}
	fields, err := uniqueObject(proofBytes)
	if err != nil || len(fields) != 6 {
		return ErrOutboxUnknown
	}
	for _, key := range []string{"producer", "previous", "sequence", "head", "signature", "event_id"} {
		if _, ok := fields[key]; !ok {
			return ErrOutboxUnknown
		}
	}
	for _, key := range []string{"producer", "previous", "head", "signature", "event_id"} {
		var value string
		if len(fields[key]) < 2 || fields[key][0] != '"' || json.Unmarshal(fields[key], &value) != nil {
			return ErrOutboxUnknown
		}
	}
	var proof Proof
	var event Event
	if json.Unmarshal(proofBytes, &proof) != nil || json.Unmarshal(raw, &event) != nil {
		return ErrOutboxUnknown
	}
	canonical, err := json.Marshal(normalized(event))
	if err != nil || !bytes.Equal(raw, canonical) || event.Producer != "kernel" || event.Action != "model.prepared" || event.ID == "" || proof.Sequence < 1 || !validOutboxDigest(proof.Head) || (proof.Sequence == 1 && proof.Previous != "") || (proof.Sequence > 1 && !validOutboxDigest(proof.Previous)) {
		return ErrOutboxUnknown
	}
	sig, err := base64.RawURLEncoding.DecodeString(proof.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(sig) != proof.Signature || !VerifyEvent(v.public, proof, event) || ctx.Err() != nil {
		return ErrOutboxUnknown
	}
	return nil
}
