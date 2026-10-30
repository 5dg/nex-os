//! Explicit production-model candidate policy. This module neither activates a
//! runtime profile nor verifies provider credentials, workload identity, session
//! authority, a signature or an effect fence. Its inputs and expected policy
//! digest must come from independently authenticated trusted configuration.
//! Historical v2/v3 payloads and their encodings are not modified.

use sha2::{Digest, Sha256};
use tonic::Status;

// Trusted embedding must independently authenticate current policy identity,
// version, digest, revocation and expiry against an authoritative source.
// This interface supplies no implementation, cloud identity or effect fence.
#[tonic::async_trait]
pub trait CandidatePolicyAuthority: Send + Sync {
    async fn check_current(&self, policy: &CandidateModelPolicy) -> Result<(), Status>;
}

// These facts are obtained from the locked Guard job and manifest, not from a
// user request. They do not authenticate the user/session by themselves.
#[derive(Clone, Debug)]
pub struct CandidateJobBinding {
    pub job_id: String,
    pub tenant_id: String,
    pub actor_id: String,
    pub delegation_id: String,
    pub user_issuer: String,
    pub user_subject: String,
    pub original_session_reference: String,
    pub operation_id: String,
    pub request_digest: String,
    pub document_id: String,
    pub document_version: String,
    pub document_digest: String,
    pub question_digest: String,
    pub policy_digest: String,
}

// Independently authenticates the original user's protected session binding
// for the exact job and checks current user/tenant/delegation/session authority
// and revocation. The job owner alone, raw cookie, or caller-supplied session
// is not proof. This does not implement a cross-system or provider effect fence.
#[tonic::async_trait]
pub trait CandidateJobAuthority: Send + Sync {
    async fn check_current(&self, binding: &CandidateJobBinding) -> Result<(), Status>;
}

const POLICY_DOMAIN: &[u8] = b"nex.production.model.policy.v1\0";
const CONTEXT_DOMAIN: &[u8] = b"nex.production.model.context.v1\0";
const AUTHORIZATION_DOMAIN: &[u8] = b"nex.production.model.authorization.v1\0";

#[derive(Clone, Debug)]
pub struct CandidateModelPolicyInput {
    pub policy_identity: String,
    pub policy_version: String,
    pub tenant_id: String,
    pub route_id: String,
    pub account_id: String,
    pub role_arn: String,
    pub region: String,
    pub model_arn: String,
    pub endpoint: String,
    pub fips: bool,
    pub template_version: String,
    pub question_id: String,
    pub question_version: String,
    pub question_digest: String,
    pub question_classification: String,
    pub allowed_classifications: Vec<String>,
    pub max_tokens: u32,
    pub features: Vec<String>,
}

// This describes independently resolved route and data facts. It is not proof
// that the underlying account, workload, caller, lease or policy is authentic.
#[derive(Clone, Debug)]
pub struct CandidateModelObservation {
    pub policy_identity: String,
    pub policy_version: String,
    pub tenant_id: String,
    pub operation_id: String,
    pub request_digest: String,
    pub route_id: String,
    pub provider: String,
    pub account_id: String,
    pub role_arn: String,
    pub region: String,
    pub model_arn: String,
    pub endpoint: String,
    pub fips: bool,
    pub template_version: String,
    pub question_id: String,
    pub question_version: String,
    pub question_digest: String,
    pub question_classification: String,
    pub document_classification: String,
    pub request_classification: String,
    pub max_tokens: u32,
    pub features: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct CandidateModelPolicy {
    input: CandidateModelPolicyInput,
    digest: String,
}

#[derive(Clone, Debug)]
pub struct CandidateModelContext {
    canonical: Vec<u8>,
    digest: String,
    policy_digest: String,
    prepared: bool,
}

impl CandidateModelContext {
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

fn compact_id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}
fn operation_id(value: &str) -> bool {
    (8..=100).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn rank(value: &str) -> Option<u8> {
    match value {
        "public" => Some(0),
        "internal" => Some(1),
        "confidential" => Some(2),
        _ => None,
    }
}
fn role_matches_account(account: &str, role: &str) -> bool {
    if account.len() != 12 || !account.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let prefix = format!("arn:aws-us-gov:iam::{account}:role/");
    let Some(name) = role.strip_prefix(&prefix) else {
        return false;
    };
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'+' | b'=' | b',' | b'.' | b'@' | b'-')
        })
}
fn valid_model(region: &str, model: &str) -> bool {
    let prefix = format!("arn:aws-us-gov:bedrock:{region}::foundation-model/");
    let Some(id) = model.strip_prefix(&prefix) else {
        return false;
    };
    !id.is_empty()
        && id.len() <= 128
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}
fn policy_fields(input: &CandidateModelPolicyInput) -> Result<Vec<String>, &'static str> {
    let invalid = "invalid candidate model policy";
    if !compact_id(&input.policy_identity, 128)
        || !compact_id(&input.policy_version, 128)
        || !compact_id(&input.tenant_id, 128)
        || !compact_id(&input.route_id, 128)
        || !compact_id(&input.template_version, 128)
        || !compact_id(&input.question_id, 128)
        || !compact_id(&input.question_version, 128)
        || !digest(&input.question_digest)
        || rank(&input.question_classification).is_none()
        || !role_matches_account(&input.account_id, &input.role_arn)
        || !matches!(input.region.as_str(), "us-gov-west-1" | "us-gov-east-1")
        || !valid_model(&input.region, &input.model_arn)
        || input.max_tokens == 0
        || input.max_tokens > 256
        || !input.features.is_empty()
        || input.allowed_classifications.is_empty()
        || input.allowed_classifications.len() > 3
    {
        return Err(invalid);
    }
    let expected = format!(
        "https://bedrock-runtime{}.{}.amazonaws.com",
        if input.fips { "-fips" } else { "" },
        input.region
    );
    if input.endpoint != expected {
        return Err(invalid);
    }
    let mut classifications = input.allowed_classifications.clone();
    classifications.sort();
    if classifications.iter().any(|value| rank(value).is_none())
        || classifications.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(invalid);
    }
    let mut fields = vec![
        input.policy_identity.clone(),
        input.policy_version.clone(),
        input.tenant_id.clone(),
        input.route_id.clone(),
        "bedrock".into(),
        input.account_id.clone(),
        input.role_arn.clone(),
        input.region.clone(),
        input.model_arn.clone(),
        input.endpoint.clone(),
        if input.fips { "1" } else { "0" }.into(),
        input.template_version.clone(),
        input.question_id.clone(),
        input.question_version.clone(),
        input.question_digest.clone(),
        input.question_classification.clone(),
        input.max_tokens.to_string(),
        classifications.len().to_string(),
    ];
    fields.extend(classifications);
    // A count is encoded even while unsupported features are rejected.
    fields.push("0".into());
    Ok(fields)
}
fn encode(domain: &[u8], fields: &[String]) -> Vec<u8> {
    let mut bytes = domain.to_vec();
    for field in fields {
        bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
        bytes.extend_from_slice(field.as_bytes());
    }
    bytes
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Computes a canonical identity for comparison with an independently trusted
/// policy digest. The hash alone authenticates neither the policy nor caller.
pub fn candidate_policy_digest(input: &CandidateModelPolicyInput) -> Result<String, &'static str> {
    Ok(hash(&encode(POLICY_DOMAIN, &policy_fields(input)?)))
}

impl CandidateModelPolicy {
    /// `expected_digest` must come from an independent trusted source. Passing a
    /// digest computed from untrusted request data is not authentication.
    pub fn new(
        input: CandidateModelPolicyInput,
        expected_digest: &str,
    ) -> Result<Self, &'static str> {
        let computed = candidate_policy_digest(&input)?;
        if !digest(expected_digest) || computed != expected_digest {
            return Err("candidate policy digest mismatch");
        }
        Ok(Self {
            input,
            digest: computed,
        })
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Read-only trusted route policy; callers cannot mutate the sealed copy.
    pub fn input(&self) -> &CandidateModelPolicyInput {
        &self.input
    }

    /// Validates exact observed route and classification against the sealed
    /// policy. It is not a signature, credential, session or fence check.
    pub fn matches(&self, o: &CandidateModelObservation) -> bool {
        let p = &self.input;
        let Some(doc) = rank(&o.document_classification) else {
            return false;
        };
        let Some(question) = rank(&o.question_classification) else {
            return false;
        };
        let Some(request) = rank(&o.request_classification) else {
            return false;
        };
        o.policy_identity == p.policy_identity
            && o.policy_version == p.policy_version
            && o.tenant_id == p.tenant_id
            && operation_id(&o.operation_id)
            && digest(&o.request_digest)
            && o.route_id == p.route_id
            && o.provider == "bedrock"
            && o.account_id == p.account_id
            && o.role_arn == p.role_arn
            && o.region == p.region
            && o.model_arn == p.model_arn
            && o.endpoint == p.endpoint
            && o.fips == p.fips
            && o.template_version == p.template_version
            && o.question_id == p.question_id
            && o.question_version == p.question_version
            && o.question_digest == p.question_digest
            && o.question_classification == p.question_classification
            && request == doc.max(question)
            && p.allowed_classifications
                .contains(&o.request_classification)
            && o.max_tokens > 0
            && o.max_tokens <= p.max_tokens
            && o.features.is_empty()
            && p.features.is_empty()
    }

    /// The caller must first authenticate the Guard-owned source and stored v3
    /// context. This separately versioned encoding leaves historical v2/v3
    /// payloads and their context encodings unchanged. No receiver certificate
    /// or credential attestation is presumed to exist at prepare time.
    pub fn prepare_context(
        &self,
        o: &CandidateModelObservation,
        guard_context_digest: &str,
    ) -> Result<CandidateModelContext, &'static str> {
        if !self.matches(o) || !digest(guard_context_digest) {
            return Err("candidate model context denied");
        }
        let fields = vec![
            "1".into(),
            self.digest.clone(),
            o.tenant_id.clone(),
            o.operation_id.clone(),
            o.request_digest.clone(),
            guard_context_digest.into(),
            o.document_classification.clone(),
            o.question_classification.clone(),
            o.request_classification.clone(),
            o.max_tokens.to_string(),
        ];
        let canonical = encode(CONTEXT_DOMAIN, &fields);
        let digest = hash(&canonical);
        Ok(CandidateModelContext {
            canonical,
            digest,
            policy_digest: self.digest.clone(),
            prepared: true,
        })
    }

    /// This binds the already prepared context to credential and receiver
    /// evidence at authorization time. Both digests must come from independently
    /// verified, current authorities; hashing them is not authentication and
    /// does not implement an effect-spanning fence or revocation check.
    pub fn authorization_context(
        &self,
        prepared: &CandidateModelContext,
        credential_attestation_digest: &str,
        receiver_certificate_sha256: &str,
    ) -> Result<CandidateModelContext, &'static str> {
        if !prepared.prepared
            || prepared.policy_digest != self.digest
            || !digest(prepared.digest())
            || !digest(credential_attestation_digest)
            || !digest(receiver_certificate_sha256)
        {
            return Err("candidate authorization context denied");
        }
        let canonical = encode(
            AUTHORIZATION_DOMAIN,
            &[
                "1".into(),
                prepared.digest.clone(),
                credential_attestation_digest.into(),
                receiver_certificate_sha256.into(),
            ],
        );
        let digest = hash(&canonical);
        Ok(CandidateModelContext {
            canonical,
            digest,
            policy_digest: self.digest.clone(),
            prepared: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (CandidateModelPolicyInput, CandidateModelObservation) {
        let policy = CandidateModelPolicyInput {
            policy_identity: "policy-model-a".into(),
            policy_version: "v1".into(),
            tenant_id: "tenant-a".into(),
            route_id: "approved-model".into(),
            account_id: "123456789012".into(),
            role_arn: "arn:aws-us-gov:iam::123456789012:role/model-role".into(),
            region: "us-gov-west-1".into(),
            model_arn: "arn:aws-us-gov:bedrock:us-gov-west-1::foundation-model/fixture-model-v1:0"
                .into(),
            endpoint: "https://bedrock-runtime-fips.us-gov-west-1.amazonaws.com".into(),
            fips: true,
            template_version: "review-template-v3".into(),
            question_id: "question-a".into(),
            question_version: "v1".into(),
            question_digest: "c".repeat(64),
            question_classification: "internal".into(),
            allowed_classifications: vec!["confidential".into(), "internal".into()],
            max_tokens: 128,
            features: vec![],
        };
        let observed = CandidateModelObservation {
            policy_identity: policy.policy_identity.clone(),
            policy_version: policy.policy_version.clone(),
            tenant_id: policy.tenant_id.clone(),
            operation_id: "operation-123".into(),
            request_digest: "a".repeat(64),
            route_id: policy.route_id.clone(),
            provider: "bedrock".into(),
            account_id: policy.account_id.clone(),
            role_arn: policy.role_arn.clone(),
            region: policy.region.clone(),
            model_arn: policy.model_arn.clone(),
            endpoint: policy.endpoint.clone(),
            fips: policy.fips,
            template_version: policy.template_version.clone(),
            question_id: policy.question_id.clone(),
            question_version: policy.question_version.clone(),
            question_digest: policy.question_digest.clone(),
            question_classification: policy.question_classification.clone(),
            document_classification: "public".into(),
            request_classification: "internal".into(),
            max_tokens: 100,
            features: vec![],
        };
        (policy, observed)
    }

    #[test]
    fn policy_requires_independently_trusted_exact_digest_and_safe_route() {
        let (p, _) = fixture();
        let expected = candidate_policy_digest(&p).unwrap();
        assert!(CandidateModelPolicy::new(p.clone(), &expected).is_ok());
        assert!(CandidateModelPolicy::new(p.clone(), &"f".repeat(64)).is_err());
        let mut reordered = p.clone();
        reordered.allowed_classifications.reverse();
        assert_eq!(candidate_policy_digest(&reordered).unwrap(), expected);
        let edits: [fn(&mut CandidateModelPolicyInput); 12] = [
            |x| x.account_id = "123456789013".into(),
            |x| x.role_arn = "arn:aws-us-gov:iam::123456789013:role/model-role".into(),
            |x| x.region = "us-gov-east-1".into(),
            |x| x.endpoint = "https://bedrock-runtime.us-gov-west-1.amazonaws.com".into(),
            |x| x.fips = false,
            |x| x.model_arn = "arn:aws:bedrock:us-gov-west-1::foundation-model/model".into(),
            |x| x.max_tokens = 257,
            |x| x.features.push("tools".into()),
            |x| x.allowed_classifications.push("restricted".into()),
            |x| x.allowed_classifications.push("internal".into()),
            |x| x.policy_identity = "".into(),
            |x| x.question_digest = "bad".into(),
        ];
        for edit in edits {
            let mut bad = p.clone();
            edit(&mut bad);
            assert!(CandidateModelPolicy::new(bad, &expected).is_err());
        }
        let mut changed_question = p.clone();
        changed_question.question_digest = "d".repeat(64);
        assert_ne!(
            candidate_policy_digest(&changed_question).unwrap(),
            expected
        );
        assert!(CandidateModelPolicy::new(changed_question, &expected).is_err());
        let mut stale = p.clone();
        stale.account_id = "123456789013".into();
        stale.role_arn = "arn:aws-us-gov:iam::123456789013:role/model-role".into();
        assert!(candidate_policy_digest(&stale).is_ok());
        assert!(CandidateModelPolicy::new(stale, &expected).is_err());
    }

    #[test]
    fn observation_binds_every_authority_fact_and_classification() {
        let (input, observed) = fixture();
        let expected = candidate_policy_digest(&input).unwrap();
        let policy = CandidateModelPolicy::new(input, &expected).unwrap();
        assert!(policy.matches(&observed));
        let edits: [fn(&mut CandidateModelObservation); 20] = [
            |x| x.policy_identity = "other".into(),
            |x| x.policy_version = "v2".into(),
            |x| x.tenant_id = "tenant-b".into(),
            |x| x.operation_id = "bad/id".into(),
            |x| x.request_digest = "b".repeat(63),
            |x| x.route_id = "other".into(),
            |x| x.provider = "development".into(),
            |x| x.account_id = "123456789013".into(),
            |x| x.role_arn = "arn:aws-us-gov:iam::123456789012:role/other".into(),
            |x| x.region = "us-gov-east-1".into(),
            |x| x.model_arn = "other".into(),
            |x| x.endpoint = "https://other.invalid".into(),
            |x| x.fips = false,
            |x| x.template_version = "other".into(),
            |x| x.question_id = "other".into(),
            |x| x.question_version = "v2".into(),
            |x| x.question_digest = "d".repeat(64),
            |x| x.question_classification = "public".into(),
            |x| x.max_tokens = 129,
            |x| x.features.push("tools".into()),
        ];
        for edit in edits {
            let mut bad = observed.clone();
            edit(&mut bad);
            assert!(!policy.matches(&bad));
        }
        let mut bad = observed.clone();
        bad.document_classification = "restricted".into();
        assert!(!policy.matches(&bad));
        bad = observed.clone();
        bad.document_classification = "confidential".into();
        assert!(!policy.matches(&bad));
        bad = observed.clone();
        bad.request_classification = "public".into();
        assert!(!policy.matches(&bad));
        bad = observed.clone();
        bad.max_tokens = 0;
        assert!(!policy.matches(&bad));
    }

    #[test]
    fn context_domains_bind_preparation_before_later_credentials() {
        let (input, o) = fixture();
        let expected = candidate_policy_digest(&input).unwrap();
        let policy = CandidateModelPolicy::new(input.clone(), &expected).unwrap();
        let prepared = policy.prepare_context(&o, &"b".repeat(64)).unwrap();
        assert!(prepared.canonical_bytes().starts_with(CONTEXT_DOMAIN));
        assert_eq!(prepared.digest().len(), 64);
        let authorized = policy
            .authorization_context(&prepared, &"c".repeat(64), &"d".repeat(64))
            .unwrap();
        assert!(authorized
            .canonical_bytes()
            .starts_with(AUTHORIZATION_DOMAIN));
        assert_ne!(authorized.digest(), prepared.digest());
        assert_ne!(
            policy
                .prepare_context(&o, &"e".repeat(64))
                .unwrap()
                .digest(),
            prepared.digest()
        );
        assert_ne!(
            policy
                .authorization_context(&prepared, &"e".repeat(64), &"d".repeat(64))
                .unwrap()
                .digest(),
            authorized.digest()
        );
        assert!(policy
            .authorization_context(&authorized, &"c".repeat(64), &"d".repeat(64))
            .is_err());
        assert!(policy
            .authorization_context(&prepared, "bad", &"d".repeat(64))
            .is_err());
        let mut other = input;
        other.policy_version = "v2".into();
        let other_digest = candidate_policy_digest(&other).unwrap();
        let other = CandidateModelPolicy::new(other, &other_digest).unwrap();
        assert!(other
            .authorization_context(&prepared, &"c".repeat(64), &"d".repeat(64))
            .is_err());
    }
}
