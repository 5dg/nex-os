package broker

import (
	"context"
	"errors"
	"reflect"
	"time"
	"unicode"
	"unicode/utf8"
)

// ResultCapabilityClaims are assertions signed by an independently trusted
// control-service credential. They are not browser bearer tokens. SessionID is
// a non-secret, independently authenticated session reference (such as an IdP
// sid or control-signed assertion), never a browser session handle or cookie.
type ResultCapabilityClaims struct {
	Type, Issuer, Audience                           string
	UserIssuer, UserSubject, SessionID               string
	ActorID, TenantID, DelegationID                  string
	OperationID, RequestDigest, Scope                string
	ControlWorkload, ReceiverWorkload, GuardWorkload string
	IssuedAt, NotBefore, ExpiresAt                   time.Time
}

// ResultCapabilityVerifier must validate the complete cryptographic signature
// and return signerIdentity from the trusted key/certificate, not from claims.
// Production algorithms and trust anchors are deployment decisions.
type ResultCapabilityVerifier interface {
	Verify(context.Context, []byte) (claims ResultCapabilityClaims, signerIdentity string, err error)
}

// GuardResultContext must be obtained from independently protected Guard-owned
// state, not request fields. Original issuer, subject and session are required;
// existing v2/v3 manifests do not yet contain this production identity binding.
type GuardResultContext struct {
	UserIssuer, UserSubject, SessionID string
	ActorID, TenantID, DelegationID    string
	OperationID, RequestDigest, Kind   string
}

// GuardResultAuthority must look up exact immutable operation context and
// atomically recheck the stored binding and current actor/tenant/delegation/
// session/result authority. Its actual database and identity implementation
// remains a production prerequisite.
type GuardResultAuthority interface {
	Lookup(context.Context, string, string) (GuardResultContext, error)
	CheckCurrent(context.Context, GuardResultContext) error
}

// ResultWorkloadAuthenticator must derive peer identities from authenticated
// workload transport and the Guard's own validated identity, not request data.
type ResultWorkloadAuthenticator interface {
	AuthenticatedWorkloads(context.Context) (receiver, guard string, err error)
}

type ResultCapabilityPolicy struct {
	Issuer, Audience, UserIssuer                     string
	ControlWorkload, ReceiverWorkload, GuardWorkload string
	Scope                                            string
	MaxLifetime                                      time.Duration
}

// The deployment may choose a shorter lifetime but cannot authorize a
// result-access assertion for more than fifteen minutes.
const maxResultCapabilityLifetime = 15 * time.Minute

type ResultCapabilityValidator struct {
	policy    ResultCapabilityPolicy
	verifier  ResultCapabilityVerifier
	authority GuardResultAuthority
	workloads ResultWorkloadAuthenticator
}

func capabilityDependencyPresent(value any) bool {
	if value == nil {
		return false
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return !v.IsNil()
	default:
		return true
	}
}

func validCapabilityField(value string) bool {
	if value == "" || len(value) > 512 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func NewResultCapabilityValidator(policy ResultCapabilityPolicy, verifier ResultCapabilityVerifier, authority GuardResultAuthority, workloads ResultWorkloadAuthenticator) (*ResultCapabilityValidator, error) {
	if !validCapabilityField(policy.Issuer) || !validCapabilityField(policy.Audience) || !validCapabilityField(policy.UserIssuer) || !validCapabilityField(policy.ControlWorkload) || !validCapabilityField(policy.ReceiverWorkload) || !validCapabilityField(policy.GuardWorkload) ||
		policy.ControlWorkload == policy.ReceiverWorkload || policy.ControlWorkload == policy.GuardWorkload || policy.ReceiverWorkload == policy.GuardWorkload ||
		(policy.Scope != "model.result" && policy.Scope != "export.result") || policy.MaxLifetime <= 0 || policy.MaxLifetime > maxResultCapabilityLifetime ||
		!capabilityDependencyPresent(verifier) || !capabilityDependencyPresent(authority) || !capabilityDependencyPresent(workloads) {
		return nil, errors.New("complete trusted result-access configuration required")
	}
	return &ResultCapabilityValidator{policy: policy, verifier: verifier, authority: authority, workloads: workloads}, nil
}

// ReceiptAccess binds an opaque, already-issued service capability to the
// receipt-store callback. Every invocation verifies the signature, workload and
// current authority again; the caller cannot mutate the captured bytes later.
func (v *ResultCapabilityValidator) ReceiptAccess(capability []byte) (ReceiptAccess, error) {
	if v == nil || len(capability) == 0 || len(capability) > 16*1024 {
		return nil, ErrUnknown
	}
	captured := append([]byte(nil), capability...)
	return func(ctx context.Context, operationID, digest string) error {
		return v.Check(ctx, captured, operationID, digest)
	}, nil
}

func validCapabilityTime(claims ResultCapabilityClaims, now time.Time, max time.Duration) bool {
	return !claims.IssuedAt.IsZero() && !claims.NotBefore.IsZero() && !claims.ExpiresAt.IsZero() &&
		!claims.IssuedAt.After(now) && !claims.NotBefore.After(now) && now.Before(claims.ExpiresAt) &&
		claims.IssuedAt.Before(claims.ExpiresAt) && claims.NotBefore.Before(claims.ExpiresAt) && claims.ExpiresAt.Sub(claims.IssuedAt) <= max
}

// Check is non-mutating from this package's perspective. It does not dispatch
// an effect or grant execution. Dependencies must be independently trusted;
// in particular, CheckCurrent must consult current authority and session state.
func (v *ResultCapabilityValidator) Check(ctx context.Context, capability []byte, operationID, digest string) error {
	if v == nil || ctx == nil || ctx.Err() != nil || len(capability) == 0 || len(capability) > 16*1024 || !validID(operationID) || !validReceiptDigest(digest) ||
		!capabilityDependencyPresent(v.verifier) || !capabilityDependencyPresent(v.authority) || !capabilityDependencyPresent(v.workloads) {
		return ErrUnknown
	}
	claims, signer, err := v.verifier.Verify(ctx, append([]byte(nil), capability...))
	if err != nil || claims.Type != "nex.result-access.v1" || claims.Issuer != v.policy.Issuer || claims.Audience != v.policy.Audience || signer != v.policy.ControlWorkload ||
		claims.ControlWorkload != v.policy.ControlWorkload || claims.ReceiverWorkload != v.policy.ReceiverWorkload || claims.GuardWorkload != v.policy.GuardWorkload ||
		claims.Scope != v.policy.Scope || claims.OperationID != operationID || claims.RequestDigest != digest || !validCapabilityTime(claims, time.Now(), v.policy.MaxLifetime) {
		return ErrUnknown
	}
	receiver, guard, err := v.workloads.AuthenticatedWorkloads(ctx)
	if err != nil || receiver != v.policy.ReceiverWorkload || guard != v.policy.GuardWorkload {
		return ErrUnknown
	}
	stored, err := v.authority.Lookup(ctx, operationID, digest)
	if err != nil || stored.OperationID != operationID || stored.RequestDigest != digest ||
		(stored.Kind == "model" && v.policy.Scope != "model.result") || (stored.Kind == "export" && v.policy.Scope != "export.result") || (stored.Kind != "model" && stored.Kind != "export") ||
		!validCapabilityField(stored.UserIssuer) || !validCapabilityField(stored.UserSubject) || !validCapabilityField(stored.SessionID) || !validCapabilityField(stored.ActorID) || !validCapabilityField(stored.TenantID) || !validCapabilityField(stored.DelegationID) ||
		stored.UserIssuer != v.policy.UserIssuer || claims.UserIssuer != stored.UserIssuer || claims.UserSubject != stored.UserSubject || claims.SessionID != stored.SessionID || claims.ActorID != stored.ActorID || claims.TenantID != stored.TenantID || claims.DelegationID != stored.DelegationID {
		return ErrUnknown
	}
	if v.authority.CheckCurrent(ctx, stored) != nil || ctx.Err() != nil || !validCapabilityTime(claims, time.Now(), v.policy.MaxLifetime) {
		return ErrUnknown
	}
	return nil
}
