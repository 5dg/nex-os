package guard

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
	pb "github.com/5dg/nex-os/packages/contracts/gen/guardv1"
	"github.com/5dg/nex-os/packages/trust"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"net"
	"time"
)

var ErrDenied = errors.New("Rust Guard denied the operation")

func rpcError(e error) error {
	if status.Code(e) == codes.PermissionDenied || status.Code(e) == codes.Unauthenticated {
		return ErrDenied
	}
	return e
}
func (c *Client) AuthorizeExecution(ctx context.Context, operation, digest string) (bool, error) {
	if c.RPC == nil {
		return false, errors.New("Rust execution boundary required")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ctx = c.RPC.outgoing(ctx)
	var remote peer.Peer
	out, e := c.RPC.client.AuthorizeExecution(ctx, &pb.ExecutionRequest{OperationId: operation, RequestDigest: digest}, grpc.Peer(&remote))
	if e == nil {
		e = c.RPC.after(remote)
	}
	if e != nil {
		return false, rpcError(e)
	}
	return out.Allowed, nil
}
func (c *Client) DecideApproval(ctx context.Context, id, digest, actor, tenant string, approve bool) (bool, error) {
	if c.RPC == nil {
		return false, errors.New("Rust approval boundary required")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ctx = c.RPC.outgoing(ctx)
	var remote peer.Peer
	out, e := c.RPC.client.DecideApproval(ctx, &pb.ApprovalRequest{ApprovalId: id, RequestDigest: digest, ActorId: actor, TenantId: tenant, Approve: approve}, grpc.Peer(&remote))
	if e == nil {
		e = c.RPC.after(remote)
	}
	if e != nil {
		return false, rpcError(e)
	}
	return out.Allowed, nil
}

type RPC struct {
	client     pb.GuardClient
	connection *grpc.ClientConn
	token      string
	trust      *trust.Config
}

func NewRPC(address string, key []byte, development bool) (*Client, error) {
	if !development {
		return nil, errors.New("production gRPC requires an approved TLS/workload-identity configuration")
	}
	if address == "" || len(key) != 32 {
		return nil, errors.New("Guard address and 32-byte service identity required")
	}
	connection, e := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(256*1024), grpc.MaxCallSendMsgSize(256*1024)))
	if e != nil {
		return nil, e
	}
	return &Client{RPC: &RPC{client: pb.NewGuardClient(connection), connection: connection, token: hex.EncodeToString(key)}}, nil
}
func (c *Client) Close() error {
	if c.RPC != nil {
		return c.RPC.connection.Close()
	}
	return nil
}
func (r *RPC) evaluate(ctx context.Context, in Input) (contracts.Decision, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ctx = r.outgoing(ctx)
	var remote peer.Peer
	out, e := r.client.Evaluate(ctx, &pb.EvaluateRequest{Actor: &pb.Actor{Id: in.Actor.ID, TenantId: in.Actor.TenantID, Permissions: in.Actor.Permissions}, Resource: &pb.Resource{TenantId: in.Resource.TenantID, Kind: in.Resource.Kind, Classification: in.Resource.Classification, ReaderIds: in.Resource.ReaderIDs, ApprovedClassifications: in.Resource.ApprovedClassifications}, Action: in.Action, DelegationValid: in.DelegationValid, DelegationPermissions: in.DelegationPermissions, DataClassification: in.DataClassification}, grpc.Peer(&remote))
	if e == nil {
		e = r.after(remote)
	}
	if e != nil {
		return contracts.Decision{}, e
	}
	if out.PolicyDigest != Digest() || out.PolicyVersion != "alpha-guard-v1" || out.ReasonCode == "" {
		return contracts.Decision{}, errors.New("Guard policy contract mismatch")
	}
	effect := ""
	switch out.Effect {
	case pb.Effect_DENY:
		effect = "deny"
	case pb.Effect_ALLOW:
		effect = "allow"
	case pb.Effect_REQUIRE_APPROVAL:
		effect = "require_approval"
	default:
		return contracts.Decision{}, errors.New("unspecified Guard effect")
	}
	return contracts.Decision{Effect: effect, Reason: out.ReasonCode, PolicyVersion: out.PolicyVersion, PolicyDigest: out.PolicyDigest}, nil
}

// PrepareExecution asks Rust to resolve and seal the exact operation payload.
func (c *Client) PrepareExecution(ctx context.Context, job, operation string) (json.RawMessage, string, error) {
	if c.RPC == nil {
		return nil, "", errors.New("Rust preparation boundary required")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ctx = c.RPC.outgoing(ctx)
	var remote peer.Peer
	out, e := c.RPC.client.PrepareExecution(ctx, &pb.PrepareRequest{JobId: job, OperationId: operation}, grpc.Peer(&remote))
	if e == nil {
		e = c.RPC.after(remote)
	}
	if e != nil {
		return nil, "", rpcError(e)
	}
	return json.RawMessage(out.PayloadJson), out.RequestDigest, nil
}
func (c *Client) CompleteExecution(ctx context.Context, operation, digest string, result any) error {
	if c.RPC == nil {
		return errors.New("Rust outcome boundary required")
	}
	b, e := json.Marshal(result)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ctx = c.RPC.outgoing(ctx)
	var remote peer.Peer
	out, e := c.RPC.client.CompleteExecution(ctx, &pb.CompletionRequest{OperationId: operation, RequestDigest: digest, ResultJson: string(b)}, grpc.Peer(&remote))
	if e == nil {
		e = c.RPC.after(remote)
	}
	if e != nil {
		return rpcError(e)
	}
	if !out.Allowed {
		return ErrDenied
	}
	return nil
}

// ExecutionState is an authenticated observation, never an execution grant.
func (c *Client) ExecutionState(ctx context.Context, operation, digest string) (string, error) {
	if c.RPC == nil {
		return "", errors.New("Rust state boundary required")
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ctx = c.RPC.outgoing(ctx)
	var remote peer.Peer
	out, e := c.RPC.client.ExecutionState(ctx, &pb.ExecutionRequest{OperationId: operation, RequestDigest: digest}, grpc.Peer(&remote))
	if e == nil {
		e = c.RPC.after(remote)
	}
	if e != nil {
		return "", rpcError(e)
	}
	return out.State, nil
}

// An authorization transport failure may hide a committed grant. Only a fresh
// pending state proves no previous authorization/effect for this exact operation.
func (c *Client) AuthorizeEffect(ctx context.Context, operation, digest string) error {
	allowed, e := c.AuthorizeExecution(ctx, operation, digest)
	if e == nil && allowed {
		return nil
	}
	state, stateErr := c.ExecutionState(ctx, operation, digest)
	if stateErr == nil && state == "pending" {
		return broker.ErrNotStarted
	}
	return broker.ErrUnknown
}

func (r *RPC) outgoing(ctx context.Context) context.Context {
	if r.trust != nil && r.trust.Profile == trust.Qualification {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+r.token)
}

// NewRPCWithTrust cannot downgrade a qualification caller to the legacy key path.
func NewRPCWithTrust(address string, legacyKey []byte, cfg *trust.Config) (*Client, error) {
	if cfg == nil {
		return nil, trust.ErrIdentity
	}
	if cfg.Profile == trust.Development {
		return NewRPC(address, legacyKey, true)
	}
	if cfg.Profile != trust.Qualification {
		return nil, trust.ErrIdentity
	}
	host, _, e := net.SplitHostPort(address)
	if e != nil || host == "" {
		return nil, errors.New("qualification Guard host:port required")
	}
	tlsConfig, e := cfg.GRPCClientTLS(trust.Guard, host)
	if e != nil {
		return nil, e
	}
	connection, e := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)), grpc.WithPerRPCCredentials(cfg.PerRPCCredentials(trust.Guard)), grpc.WithDisableRetry(), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(256*1024), grpc.MaxCallSendMsgSize(256*1024)))
	if e != nil {
		return nil, e
	}
	return &Client{RPC: &RPC{client: pb.NewGuardClient(connection), connection: connection, trust: cfg}}, nil
}
func (c *Client) Readiness(ctx context.Context) error {
	if c.RPC == nil {
		return errors.New("Guard readiness boundary required")
	}
	if c.RPC.trust == nil || c.RPC.trust.Profile == trust.Development {
		return c.Health(ctx)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var remote peer.Peer
	out, e := c.RPC.client.CheckReadiness(ctx, &pb.ReadinessRequest{}, grpc.Peer(&remote))
	if e == nil {
		e = c.RPC.after(remote)
	}
	if e != nil {
		return rpcError(e)
	}
	if !out.Ready || out.Profile != string(trust.Qualification) {
		return errors.New("qualification Guard dependencies not ready")
	}
	return nil
}

func (r *RPC) after(remote peer.Peer) error {
	if r.trust == nil || r.trust.Profile == trust.Development {
		return nil
	}
	state, ok := remote.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return trust.ErrIdentity
	}
	return r.trust.CheckPeer(&state.State, []trust.Role{trust.Guard})
}
