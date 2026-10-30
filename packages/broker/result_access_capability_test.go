package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// Ed25519 here is only a local test fixture; production key custody and the
// approved cryptographic verifier are deliberately not selected by this test.
type fixtureCapabilityVerifier struct {
	key    ed25519.PublicKey
	signer string
}

func (v *fixtureCapabilityVerifier) Verify(_ context.Context, token []byte) (ResultCapabilityClaims, string, error) {
	var claims ResultCapabilityClaims
	parts := strings.Split(string(token), ".")
	if len(parts) != 2 {
		return claims, "", errors.New("malformed fixture")
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return claims, "", err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !ed25519.Verify(v.key, data, sig) || json.Unmarshal(data, &claims) != nil {
		return claims, "", errors.New("fixture signature denied")
	}
	return claims, v.signer, nil
}

type fixtureResultAuthority struct {
	stored  GuardResultContext
	revoked bool
	lookups int
	checks  int
}

func (a *fixtureResultAuthority) Lookup(_ context.Context, operation, digest string) (GuardResultContext, error) {
	a.lookups++
	if operation != a.stored.OperationID || digest != a.stored.RequestDigest {
		return GuardResultContext{}, errors.New("not found")
	}
	return a.stored, nil
}
func (a *fixtureResultAuthority) CheckCurrent(_ context.Context, stored GuardResultContext) error {
	a.checks++
	if a.revoked || stored != a.stored {
		return errors.New("revoked")
	}
	return nil
}

type fixtureWorkloads struct{ receiver, guard string }

func (w *fixtureWorkloads) AuthenticatedWorkloads(context.Context) (string, string, error) {
	return w.receiver, w.guard, nil
}

func capabilityFixture(t *testing.T) (*ResultCapabilityValidator, ResultCapabilityClaims, ed25519.PrivateKey, *fixtureResultAuthority) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	policy := ResultCapabilityPolicy{Issuer: "nex-control", Audience: "nex-guard-result", UserIssuer: "https://identity.example", ControlWorkload: "spiffe://example/control", ReceiverWorkload: "spiffe://example/model", GuardWorkload: "spiffe://example/guard", Scope: "model.result", MaxLifetime: 2 * time.Minute}
	claims := ResultCapabilityClaims{
		Type: "nex.result-access.v1", Issuer: policy.Issuer, Audience: policy.Audience,
		UserIssuer: "https://identity.example", UserSubject: "alice", SessionID: "session-id",
		ActorID: "actor-alice", TenantID: "tenant-a", DelegationID: "delegation-a",
		OperationID: "operation-123", RequestDigest: Hash([]byte("payload")), Scope: policy.Scope,
		ControlWorkload: policy.ControlWorkload, ReceiverWorkload: policy.ReceiverWorkload, GuardWorkload: policy.GuardWorkload,
		IssuedAt: now.Add(-30 * time.Second), NotBefore: now.Add(-30 * time.Second), ExpiresAt: now.Add(30 * time.Second),
	}
	authority := &fixtureResultAuthority{stored: GuardResultContext{
		UserIssuer: claims.UserIssuer, UserSubject: claims.UserSubject, SessionID: claims.SessionID,
		ActorID: claims.ActorID, TenantID: claims.TenantID, DelegationID: claims.DelegationID,
		OperationID: claims.OperationID, RequestDigest: claims.RequestDigest, Kind: "model",
	}}
	validator, err := NewResultCapabilityValidator(policy, &fixtureCapabilityVerifier{key: pub, signer: policy.ControlWorkload}, authority, &fixtureWorkloads{receiver: policy.ReceiverWorkload, guard: policy.GuardWorkload})
	if err != nil {
		t.Fatal(err)
	}
	return validator, claims, key, authority
}

func signedFixture(t *testing.T, claims ResultCapabilityClaims, key ed25519.PrivateKey) []byte {
	t.Helper()
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(base64.RawURLEncoding.EncodeToString(data) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, data)))
}

func TestResultCapabilityBindsVerifiedIdentityOperationAndCurrentAuthority(t *testing.T) {
	validator, claims, key, authority := capabilityFixture(t)
	token := signedFixture(t, claims, key)
	access, err := validator.ReceiptAccess(token)
	if err != nil {
		t.Fatal(err)
	}
	token[0] ^= 1 // The callback must retain its own immutable capability bytes.
	if err := access(context.Background(), claims.OperationID, claims.RequestDigest); err != nil {
		t.Fatalf("authenticated result capability denied: %v", err)
	}
	authority.revoked = true
	if err := access(context.Background(), claims.OperationID, claims.RequestDigest); !errors.Is(err, ErrUnknown) {
		t.Fatal("same signed capability remained authorized after revocation")
	}
}

func TestResultCapabilityRejectsSignedMismatches(t *testing.T) {
	tests := map[string]func(*ResultCapabilityClaims){
		"type":          func(c *ResultCapabilityClaims) { c.Type = "other" },
		"issuer":        func(c *ResultCapabilityClaims) { c.Issuer = "other" },
		"audience":      func(c *ResultCapabilityClaims) { c.Audience = "other" },
		"user issuer":   func(c *ResultCapabilityClaims) { c.UserIssuer = "https://other.example" },
		"subject":       func(c *ResultCapabilityClaims) { c.UserSubject = "bob" },
		"session":       func(c *ResultCapabilityClaims) { c.SessionID = "other-session" },
		"actor":         func(c *ResultCapabilityClaims) { c.ActorID = "other" },
		"tenant":        func(c *ResultCapabilityClaims) { c.TenantID = "other" },
		"delegation":    func(c *ResultCapabilityClaims) { c.DelegationID = "other" },
		"operation":     func(c *ResultCapabilityClaims) { c.OperationID = "operation-other" },
		"digest":        func(c *ResultCapabilityClaims) { c.RequestDigest = Hash([]byte("other")) },
		"scope":         func(c *ResultCapabilityClaims) { c.Scope = "export.result" },
		"control":       func(c *ResultCapabilityClaims) { c.ControlWorkload = "spiffe://other/control" },
		"receiver":      func(c *ResultCapabilityClaims) { c.ReceiverWorkload = "spiffe://other/model" },
		"guard":         func(c *ResultCapabilityClaims) { c.GuardWorkload = "spiffe://other/guard" },
		"expired":       func(c *ResultCapabilityClaims) { c.ExpiresAt = time.Now().Add(-time.Second) },
		"future":        func(c *ResultCapabilityClaims) { c.NotBefore = time.Now().Add(time.Minute) },
		"long lifetime": func(c *ResultCapabilityClaims) { c.ExpiresAt = time.Now().Add(time.Hour) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			validator, claims, key, _ := capabilityFixture(t)
			operation, digest := claims.OperationID, claims.RequestDigest
			mutate(&claims)
			if err := validator.Check(context.Background(), signedFixture(t, claims, key), operation, digest); !errors.Is(err, ErrUnknown) {
				t.Fatal("mismatched signed capability accepted")
			}
		})
	}
}

func TestResultCapabilityRejectsForgeryAndUntrustedDependencies(t *testing.T) {
	validator, claims, key, authority := capabilityFixture(t)
	token := signedFixture(t, claims, key)
	token[0] ^= 1
	if err := validator.Check(context.Background(), token, claims.OperationID, claims.RequestDigest); !errors.Is(err, ErrUnknown) || authority.lookups != 0 {
		t.Fatal("forged token reached Guard state")
	}
	validator, claims, key, _ = capabilityFixture(t)
	validator.workloads = &fixtureWorkloads{receiver: "spiffe://other/model", guard: validator.policy.GuardWorkload}
	if err := validator.Check(context.Background(), signedFixture(t, claims, key), claims.OperationID, claims.RequestDigest); !errors.Is(err, ErrUnknown) {
		t.Fatal("untrusted receiver workload accepted")
	}
	validator, claims, key, _ = capabilityFixture(t)
	validator.verifier.(*fixtureCapabilityVerifier).signer = "spiffe://other/control"
	if err := validator.Check(context.Background(), signedFixture(t, claims, key), claims.OperationID, claims.RequestDigest); !errors.Is(err, ErrUnknown) {
		t.Fatal("untrusted control signing identity accepted")
	}
	var typedNil *fixtureCapabilityVerifier
	if _, err := NewResultCapabilityValidator(validator.policy, typedNil, validator.authority, validator.workloads); err == nil {
		t.Fatal("nil trusted verifier accepted")
	}
	policy := validator.policy
	policy.ReceiverWorkload = policy.ControlWorkload
	if _, err := NewResultCapabilityValidator(policy, validator.verifier, validator.authority, validator.workloads); err == nil {
		t.Fatal("control and receiver cannot share an assertion identity")
	}
	validator, claims, key, _ = capabilityFixture(t)
	policy = validator.policy
	policy.UserIssuer = "https://other.example"
	if _, err := NewResultCapabilityValidator(policy, validator.verifier, validator.authority, validator.workloads); err != nil {
		t.Fatal(err)
	}
	validator.policy.UserIssuer = policy.UserIssuer
	if err := validator.Check(context.Background(), signedFixture(t, claims, key), claims.OperationID, claims.RequestDigest); !errors.Is(err, ErrUnknown) {
		t.Fatal("unapproved user issuer accepted")
	}
}

func TestResultCapabilityRequiresBoundedConfiguredLifetime(t *testing.T) {
	validator, _, _, _ := capabilityFixture(t)
	for _, lifetime := range []time.Duration{0, -time.Second, 15*time.Minute + time.Nanosecond} {
		policy := validator.policy
		policy.MaxLifetime = lifetime
		if _, err := NewResultCapabilityValidator(policy, validator.verifier, validator.authority, validator.workloads); err == nil {
			t.Fatalf("unsafe lifetime %v accepted", lifetime)
		}
	}
	policy := validator.policy
	policy.MaxLifetime = 15 * time.Minute
	if _, err := NewResultCapabilityValidator(policy, validator.verifier, validator.authority, validator.workloads); err != nil {
		t.Fatalf("documented maximum lifetime denied: %v", err)
	}
}
