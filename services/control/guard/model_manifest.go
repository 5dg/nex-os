package guard

import (
	"context"
	"encoding/hex"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
	pb "github.com/5dg/nex-os/packages/contracts/gen/guardv1"
	"github.com/5dg/nex-os/packages/trust"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
)

func validModelManifestScope(operation, digest string) bool {
	if len(operation) < 8 || len(operation) > 100 || len(digest) != 64 {
		return false
	}
	for _, b := range []byte(operation) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_') {
			return false
		}
	}
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == digest
}

// ModelManifestAuthority asks authenticated Guard to validate the exact v3
// operation and semantic digest against Guard-owned state and current caller
// authority. It does not grant an effect, attest receipt status, or fence a
// provider. The synthetic mTLS path is supported; production remains closed.
type ModelManifestAuthority struct {
	rpc        *RPC
	capability []byte
}

// ModelManifestAuthority captures immutable assertion bytes and the original
// authenticated RPC. Browser tokens are not service assertions and must never
// be forwarded. The caller must supply independently issued service capability.
func (c *Client) ModelManifestAuthority(capability []byte) (*ModelManifestAuthority, error) {
	if c == nil || c.RPC == nil || c.RPC.client == nil || c.RPC.trust == nil || c.RPC.trust.Profile != trust.Qualification || c.RPC.trust.Role != trust.Model || c.RPC.trust.CheckOwn() != nil || len(capability) == 0 || len(capability) > 16*1024 {
		return nil, broker.ErrUnknown
	}
	// Capture the RPC and public profile/role values by value, so later changes
	// to the caller's Client or Config cannot relabel this authority. Private
	// TLS material remains owned by the trust package.
	rpcCopy := *c.RPC
	trustCopy := *c.RPC.trust
	rpcCopy.trust = &trustCopy
	return &ModelManifestAuthority{rpc: &rpcCopy, capability: append([]byte(nil), capability...)}, nil
}

func (a *ModelManifestAuthority) AuthorizedModelDigest(ctx context.Context, in contracts.Generation) (string, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || a.rpc == nil || a.rpc.client == nil || a.rpc.trust == nil || a.rpc.trust.Profile != trust.Qualification || a.rpc.trust.Role != trust.Model || a.rpc.trust.CheckOwn() != nil || len(a.capability) == 0 || in.ManifestVersion != 3 || len(in.Features) != 0 || in.MaxTokens < 1 || in.MaxTokens > 256 || len(in.Prompt) == 0 || len(in.Prompt) > 6000 || !utf8.ValidString(in.Prompt) {
		return "", broker.ErrUnknown
	}
	for _, value := range []string{in.TenantID, in.RouteID, in.Provider, in.Region, in.ModelID, in.EffectiveEndpoint, in.TemplateVersion, in.QuestionCatalogueID, in.QuestionCatalogueVersion, in.QuestionClassification, in.Classification} {
		if value == "" || len(value) > 512 || !utf8.ValidString(value) {
			return "", broker.ErrUnknown
		}
		for _, r := range value {
			if unicode.IsControl(r) || unicode.IsSpace(r) {
				return "", broker.ErrUnknown
			}
		}
	}
	digest := contracts.ExecutionDigest(in)
	// Guard enforces the same operation/digest syntax. Validate locally before
	// transmitting capability bytes.
	if !validModelManifestScope(in.OperationID, digest) {
		return "", broker.ErrUnknown
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	request := &pb.ResultAccessRequest{OperationId: in.OperationID, RequestDigest: digest, ServiceCapability: append([]byte(nil), a.capability...)}
	var remote peer.Peer
	out, err := a.rpc.client.CheckResultAccess(a.rpc.outgoing(bounded), request, grpc.Peer(&remote))
	if err != nil || bounded.Err() != nil || a.rpc.trust.Profile != trust.Qualification || a.rpc.trust.Role != trust.Model || a.rpc.trust.CheckOwn() != nil || a.rpc.after(remote) != nil || out == nil || !out.Allowed {
		return "", broker.ErrUnknown
	}
	return digest, nil
}
