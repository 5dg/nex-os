package guard

import (
	"context"
	"encoding/hex"
	"reflect"
	"time"

	"github.com/5dg/nex-os/packages/broker"
	pb "github.com/5dg/nex-os/packages/contracts/gen/guardv1"
	"github.com/5dg/nex-os/packages/trust"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
)

// ReceiptPhaseProofSource is trusted service wiring. Each proof must be signed
// by an independently trusted signer for the approved issuer and audience,
// carry bounded issued-at/not-before/expiry and revocation semantics, and bind
// verified receiver instance, exact user/tenant/operation/digest, phase,
// receipt state and fence. It must not replay across sessions or fence epochs.
// Production key custody and lifecycle implementations are not supplied here.
// Implementations must honor the bounded context and avoid detached work; the
// context deadline cannot fence a provider effect or cancel work already sent.
type ReceiptPhaseProofSource interface {
	Proof(context.Context, broker.ReceiptPhase, broker.ReceiptClaim) ([]byte, error)
}

type receiptPhaseAuthorizer struct {
	rpc        *RPC
	role       trust.Role
	capability []byte
	proofs     ReceiptPhaseProofSource
}

// ReceiptPhaseAuthorizer returns a phase-aware adapter for the synthetic mTLS
// transport. It requires separately trusted proof issuance and does not enable
// production or create an effect-spanning fence. Browser tokens are forbidden.
func (c *Client) ReceiptPhaseAuthorizer(capability []byte, proofs ReceiptPhaseProofSource) (broker.ReceiptPhaseAuthorizer, error) {
	if c == nil || c.RPC == nil || c.RPC.client == nil || c.RPC.trust == nil || c.RPC.trust.Profile != trust.Qualification || (c.RPC.trust.Role != trust.Model && c.RPC.trust.Role != trust.Export) || c.RPC.trust.CheckOwn() != nil || len(capability) == 0 || len(capability) > 16*1024 || proofs == nil {
		return nil, broker.ErrUnknown
	}
	v := reflect.ValueOf(proofs)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		if v.IsNil() {
			return nil, broker.ErrUnknown
		}
	}
	return &receiptPhaseAuthorizer{rpc: c.RPC, role: c.RPC.trust.Role, capability: append([]byte(nil), capability...), proofs: proofs}, nil
}

func phaseParameters(phase broker.ReceiptPhase, operation, requestDigest, claimantNonce string) (pb.ReceiptPhase, string, bool) {
	var mapped pb.ReceiptPhase
	var expected string
	switch phase {
	case broker.ReceiptDispatchPreflight:
		mapped, expected = pb.ReceiptPhase_RECEIPT_DISPATCH_PREFLIGHT, "pending"
	case broker.ReceiptDispatchEffect:
		mapped, expected = pb.ReceiptPhase_RECEIPT_DISPATCH_EFFECT, "started"
	case broker.ReceiptReceiverHandoff:
		mapped, expected = pb.ReceiptPhase_RECEIPT_RECEIVER_HANDOFF, "started"
	case broker.ReceiptCompletedRead:
		mapped, expected = pb.ReceiptPhase_RECEIPT_COMPLETED_READ, "completed"
	default:
		return 0, "", false
	}
	if len(operation) < 8 || len(operation) > 100 || len(requestDigest) != 64 {
		return 0, "", false
	}
	for _, b := range []byte(operation) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_') {
			return 0, "", false
		}
	}
	digest, err := hex.DecodeString(requestDigest)
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != requestDigest {
		return 0, "", false
	}
	needsClaim := phase == broker.ReceiptDispatchEffect || phase == broker.ReceiptReceiverHandoff
	if needsClaim {
		nonce, err := hex.DecodeString(claimantNonce)
		if err != nil || len(nonce) != 16 || hex.EncodeToString(nonce) != claimantNonce {
			return 0, "", false
		}
	} else if claimantNonce != "" {
		return 0, "", false
	}
	return mapped, expected, true
}

func (a *receiptPhaseAuthorizer) CheckReceiptPhase(ctx context.Context, phase broker.ReceiptPhase, claim broker.ReceiptClaim) (string, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || a.rpc == nil || a.rpc.client == nil || a.rpc.trust == nil || a.rpc.trust.Profile != trust.Qualification || a.rpc.trust.Role != a.role || (a.role != trust.Model && a.role != trust.Export) || a.rpc.trust.CheckOwn() != nil || len(a.capability) == 0 || a.proofs == nil {
		return "", broker.ErrUnknown
	}
	mapped, expected, ok := phaseParameters(phase, claim.OperationID(), claim.Digest(), claim.Nonce())
	if !ok {
		return "", broker.ErrUnknown
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	proof, err := a.proofs.Proof(ctx, phase, claim)
	if err != nil || len(proof) == 0 || len(proof) > 16*1024 || ctx.Err() != nil {
		return "", broker.ErrUnknown
	}
	request := &pb.ReceiptPhaseRequest{OperationId: claim.OperationID(), RequestDigest: claim.Digest(), ServiceCapability: append([]byte(nil), a.capability...), Phase: mapped, ClaimantNonce: claim.Nonce(), AuthorityProof: append([]byte(nil), proof...)}
	var remote peer.Peer
	out, err := a.rpc.client.CheckReceiptPhase(a.rpc.outgoing(ctx), request, grpc.Peer(&remote))
	if err != nil || a.rpc.trust.Profile != trust.Qualification || a.rpc.trust.Role != a.role || a.rpc.trust.CheckOwn() != nil || a.rpc.after(remote) != nil || out == nil || !out.Allowed || out.State != expected || ctx.Err() != nil {
		return "", broker.ErrUnknown
	}
	return out.State, nil
}
