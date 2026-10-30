//! Target-independent trusted result-access boundary. Production must supply
//! reviewed cryptographic and live-session implementations and workload trust.

use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tonic::Status;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionPolicy {
    OriginalSessionOnly,
    CurrentSessionSameActor,
}

#[derive(Clone, Debug)]
pub struct ResultAccessPolicy {
    pub issuer: String,
    pub audience: String,
    pub user_issuer: String,
    pub control_workload: String,
    pub model_workload: String,
    pub export_workload: String,
    pub guard_workload: String,
    pub max_lifetime_seconds: i64,
    pub session_policy: SessionPolicy,
}

// Produced only by the injected verifier after authenticating a complete
// service assertion. Signer identity must come from its verified key, not from
// a user-supplied claim. Session reference is non-secret, never a browser cookie.
#[derive(Clone, Debug)]
pub struct VerifiedResultAssertion {
    pub assertion_type: String,
    pub issuer: String,
    pub audience: String,
    pub signer_workload: String,
    pub control_workload: String,
    pub receiver_workload: String,
    pub guard_workload: String,
    pub user_issuer: String,
    pub user_subject: String,
    pub session_reference: String,
    pub actor_id: String,
    pub tenant_id: String,
    pub delegation_id: String,
    pub operation_id: String,
    pub request_digest: String,
    pub scope: String,
    pub issued_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
}

#[tonic::async_trait]
pub trait ResultAssertionVerifier: Send + Sync {
    async fn verify(&self, capability: &[u8]) -> Result<VerifiedResultAssertion, Status>;
}

// Must independently check live session lifecycle against an authoritative
// source. A stored, unexpired assertion or a browser cookie is insufficient.
#[tonic::async_trait]
pub trait ResultSessionAuthority: Send + Sync {
    async fn check_current(&self, assertion: &VerifiedResultAssertion) -> Result<(), Status>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptPhase {
    DispatchPreflight,
    DispatchEffect,
    ReceiverHandoff,
    CompletedRead,
}

// Trusted deployment implementation must verify the proof's signature using
// independently approved signer/key, issuer and audience; check bounded
// issued-at/not-before/expiry and current revocation on every validation using
// trusted time; and bind phase, exact user/tenant/operation/digest, authenticated
// receiver certificate/instance, nonce, receipt state and authoritative fence.
// Prevent replay across sessions, fence epochs and receiver instances.
// The fingerprint is derived from the verified mTLS peer, never request data.
// A successful check cannot itself fence a future provider effect.
// The RPC is bounded by Guard's request deadline; implementations must honor
// cancellation and must not detach work that could outlive that deadline.
#[tonic::async_trait]
pub trait ReceiptPhaseAuthority: Send + Sync {
    async fn check_current(
        &self,
        assertion: &VerifiedResultAssertion,
        receiver_certificate_sha256: &[u8; 32],
        phase: ReceiptPhase,
        guard_status: &str,
        claimant_nonce: &str,
        authority_proof: &[u8],
    ) -> Result<(), Status>;
}

pub(crate) fn phase_status_allowed(phase: ReceiptPhase, status: &str) -> bool {
    match phase {
        ReceiptPhase::DispatchPreflight => status == "pending",
        ReceiptPhase::DispatchEffect | ReceiptPhase::ReceiverHandoff => status == "started",
        ReceiptPhase::CompletedRead => status == "completed",
    }
}

pub struct ResultAccessConfig {
    pub(crate) policy: ResultAccessPolicy,
    pub(crate) verifier: Arc<dyn ResultAssertionVerifier>,
    pub(crate) sessions: Arc<dyn ResultSessionAuthority>,
    pub(crate) receipt_phases: Option<Arc<dyn ReceiptPhaseAuthority>>,
}

fn valid_field(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.chars().any(|c| c.is_control() || c.is_whitespace())
}

impl ResultAccessConfig {
    pub fn new(
        policy: ResultAccessPolicy,
        verifier: Arc<dyn ResultAssertionVerifier>,
        sessions: Arc<dyn ResultSessionAuthority>,
    ) -> Result<Self, &'static str> {
        if ![
            &policy.issuer,
            &policy.audience,
            &policy.user_issuer,
            &policy.control_workload,
            &policy.model_workload,
            &policy.export_workload,
            &policy.guard_workload,
        ]
        .iter()
        .all(|s| valid_field(s))
            || policy.max_lifetime_seconds < 1
            || policy.max_lifetime_seconds > 900
            || policy.control_workload == policy.model_workload
            || policy.control_workload == policy.export_workload
            || policy.control_workload == policy.guard_workload
            || policy.model_workload == policy.export_workload
            || policy.model_workload == policy.guard_workload
            || policy.export_workload == policy.guard_workload
        {
            return Err("complete, distinct result-access trust configuration required");
        }
        Ok(Self {
            policy,
            verifier,
            sessions,
            receipt_phases: None,
        })
    }

    // No main/runtime installs this authority. A caller must independently
    // configure and review its real signing, identity and lifecycle trust.
    pub fn with_receipt_phase_authority(
        mut self,
        authority: Arc<dyn ReceiptPhaseAuthority>,
    ) -> Self {
        self.receipt_phases = Some(authority);
        self
    }

    pub(crate) fn current(&self, claims: &VerifiedResultAssertion) -> bool {
        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(now) => match i64::try_from(now.as_secs()) {
                Ok(value) => value,
                Err(_) => return false,
            },
            Err(_) => return false,
        };
        claims.issued_at > 0
            && claims.not_before > 0
            && claims.expires_at > now
            && claims.issued_at <= now
            && claims.not_before <= now
            && claims.not_before < claims.expires_at
            && claims.issued_at < claims.expires_at
            && claims
                .expires_at
                .checked_sub(claims.issued_at)
                .is_some_and(|age| age <= self.policy.max_lifetime_seconds)
    }

    pub(crate) fn matches(
        &self,
        claims: &VerifiedResultAssertion,
        operation: &str,
        digest: &str,
        kind: &str,
        receiver: &str,
    ) -> bool {
        claims.assertion_type == "nex.result-access.v1"
            && claims.issuer == self.policy.issuer
            && claims.audience == self.policy.audience
            && claims.signer_workload == self.policy.control_workload
            && claims.control_workload == self.policy.control_workload
            && claims.guard_workload == self.policy.guard_workload
            && claims.user_issuer == self.policy.user_issuer
            && claims.receiver_workload == receiver
            && claims.operation_id == operation
            && claims.request_digest == digest
            && ((kind == "model"
                && claims.scope == "model.result"
                && receiver == self.policy.model_workload)
                || (kind == "export"
                    && claims.scope == "export.result"
                    && receiver == self.policy.export_workload))
            && [
                &claims.user_subject,
                &claims.session_reference,
                &claims.actor_id,
                &claims.tenant_id,
                &claims.delegation_id,
            ]
            .iter()
            .all(|s| valid_field(s))
            && self.current(claims)
    }

    // The caller must separately prove the presented current session belongs
    // to the exact bound actor/tenant and is active before invoking this check.
    pub(crate) fn session_allowed(&self, current: &str, original: &str) -> bool {
        valid_field(current)
            && valid_field(original)
            && match self.policy.session_policy {
                SessionPolicy::OriginalSessionOnly => current == original,
                SessionPolicy::CurrentSessionSameActor => true,
            }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_phase_requires_exact_guard_status() {
        let cases = [
            (ReceiptPhase::DispatchPreflight, "pending"),
            (ReceiptPhase::DispatchEffect, "started"),
            (ReceiptPhase::ReceiverHandoff, "started"),
            (ReceiptPhase::CompletedRead, "completed"),
        ];
        for (phase, allowed) in cases {
            for status in [
                "",
                "pending",
                "started",
                "completed",
                "unknown",
                "denied",
                "future",
            ] {
                assert_eq!(phase_status_allowed(phase, status), status == allowed);
            }
        }
    }

    struct DenyVerifier;
    #[tonic::async_trait]
    impl ResultAssertionVerifier for DenyVerifier {
        async fn verify(&self, _: &[u8]) -> Result<VerifiedResultAssertion, Status> {
            Err(Status::permission_denied("fixture"))
        }
    }
    struct DenySession;
    #[tonic::async_trait]
    impl ResultSessionAuthority for DenySession {
        async fn check_current(&self, _: &VerifiedResultAssertion) -> Result<(), Status> {
            Err(Status::permission_denied("fixture"))
        }
    }
    fn fixture(mode: SessionPolicy) -> (ResultAccessConfig, VerifiedResultAssertion) {
        let policy = ResultAccessPolicy {
            issuer: "control-issuer".into(),
            audience: "guard-result".into(),
            user_issuer: "https://identity.example".into(),
            control_workload: "spiffe://nex.local/service/control".into(),
            model_workload: "spiffe://nex.local/service/model".into(),
            export_workload: "spiffe://nex.local/service/export".into(),
            guard_workload: "spiffe://nex.local/service/guard".into(),
            max_lifetime_seconds: 120,
            session_policy: mode,
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let claims = VerifiedResultAssertion {
            assertion_type: "nex.result-access.v1".into(),
            issuer: policy.issuer.clone(),
            audience: policy.audience.clone(),
            signer_workload: policy.control_workload.clone(),
            control_workload: policy.control_workload.clone(),
            receiver_workload: policy.model_workload.clone(),
            guard_workload: policy.guard_workload.clone(),
            user_issuer: policy.user_issuer.clone(),
            user_subject: "alice".into(),
            session_reference: "session-reference".into(),
            actor_id: "alice".into(),
            tenant_id: "tenant-a".into(),
            delegation_id: "delegation-a".into(),
            operation_id: "operation-123".into(),
            request_digest: "a".repeat(64),
            scope: "model.result".into(),
            issued_at: now - 30,
            not_before: now - 30,
            expires_at: now + 30,
        };
        (
            ResultAccessConfig::new(policy, Arc::new(DenyVerifier), Arc::new(DenySession)).unwrap(),
            claims,
        )
    }

    #[test]
    fn exact_scope_workloads_identity_and_bounded_time_required() {
        for mode in [
            SessionPolicy::OriginalSessionOnly,
            SessionPolicy::CurrentSessionSameActor,
        ] {
            let (config, claims) = fixture(mode);
            let receiver = config.policy.model_workload.clone();
            assert!(config.matches(
                &claims,
                &claims.operation_id,
                &claims.request_digest,
                "model",
                &receiver
            ));
            let mut bad = claims.clone();
            bad.user_issuer = "https://other.example".into();
            assert!(!config.matches(
                &bad,
                &claims.operation_id,
                &claims.request_digest,
                "model",
                &receiver
            ));
            let mut bad = claims.clone();
            bad.signer_workload = "spiffe://other/control".into();
            assert!(!config.matches(
                &bad,
                &claims.operation_id,
                &claims.request_digest,
                "model",
                &receiver
            ));
            let mut bad = claims.clone();
            bad.scope = "export.result".into();
            assert!(!config.matches(
                &bad,
                &claims.operation_id,
                &claims.request_digest,
                "model",
                &receiver
            ));
            let mut bad = claims.clone();
            bad.expires_at = bad.issued_at + 901;
            assert!(!config.matches(
                &bad,
                &claims.operation_id,
                &claims.request_digest,
                "model",
                &receiver
            ));
            let mut bad = claims.clone();
            bad.not_before = bad.expires_at + 1;
            assert!(!config.matches(
                &bad,
                &claims.operation_id,
                &claims.request_digest,
                "model",
                &receiver
            ));
            assert!(!config.matches(
                &claims,
                "other-operation",
                &claims.request_digest,
                "model",
                &receiver
            ));
            assert!(!config.matches(
                &claims,
                &claims.operation_id,
                &"b".repeat(64),
                "model",
                &receiver
            ));
        }
    }
    #[test]
    fn missing_conflicting_or_unbounded_trust_configuration_denied() {
        let (config, _) = fixture(SessionPolicy::OriginalSessionOnly);
        for limit in [0, -1, 901] {
            let mut policy = config.policy.clone();
            policy.max_lifetime_seconds = limit;
            assert!(
                ResultAccessConfig::new(policy, Arc::new(DenyVerifier), Arc::new(DenySession))
                    .is_err()
            );
        }
        let mut policy = config.policy.clone();
        policy.model_workload = policy.control_workload.clone();
        assert!(
            ResultAccessConfig::new(policy, Arc::new(DenyVerifier), Arc::new(DenySession)).is_err()
        );
    }
    #[test]
    fn explicit_session_modes_never_default_or_skip_current_session_proof() {
        let (strict, _) = fixture(SessionPolicy::OriginalSessionOnly);
        assert!(strict.session_allowed("original", "original"));
        assert!(!strict.session_allowed("new-session", "original"));
        let (reauthenticated, _) = fixture(SessionPolicy::CurrentSessionSameActor);
        assert!(reauthenticated.session_allowed("new-session", "original"));
        assert!(!reauthenticated.session_allowed("", "original"));
    }
}
