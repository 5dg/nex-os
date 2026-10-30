//! Synthetic test fixture only: these keys and session checks are not a
//! production issuer, verifier, session authority, or cryptographic policy.
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use nex_guard_kernel::result_access::{
    ReceiptPhase, ReceiptPhaseAuthority, ResultAssertionVerifier, ResultSessionAuthority,
    VerifiedResultAssertion,
};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use tonic::Status;

// Separate, publicly known fixture key. This signed mock attests fabricated
// receipt/fence state solely to exercise the Guard RPC, never production trust.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PhaseProof {
    issuer: String,
    audience: String,
    phase: u8,
    operation: String,
    digest: String,
    tenant: String,
    actor: String,
    delegation: String,
    user_issuer: String,
    user_subject: String,
    session: String,
    receiver_workload: String,
    result_scope: String,
    receiver_certificate: String,
    nonce: String,
    guard_status: String,
    receipt_state: String,
    fence_generation: u64,
    issued_at: i64,
    not_before: i64,
    expires_at: i64,
}

fn phase_number(phase: ReceiptPhase) -> u8 {
    match phase {
        ReceiptPhase::DispatchPreflight => 1,
        ReceiptPhase::DispatchEffect => 2,
        ReceiptPhase::ReceiverHandoff => 3,
        ReceiptPhase::CompletedRead => 4,
    }
}

struct FixturePhaseAuthority {
    key: VerifyingKey,
    active: AtomicBool,
}
#[tonic::async_trait]
impl ReceiptPhaseAuthority for FixturePhaseAuthority {
    async fn check_current(
        &self,
        claims: &VerifiedResultAssertion,
        fingerprint: &[u8; 32],
        phase: ReceiptPhase,
        status: &str,
        nonce: &str,
        proof: &[u8],
    ) -> Result<(), Status> {
        let denied = || Status::permission_denied("synthetic phase proof denied");
        if !self.active.load(Ordering::SeqCst) {
            return Err(denied());
        }
        let (signature, body) = proof.split_at_checked(64).ok_or_else(denied)?;
        self.key
            .verify(
                body,
                &Signature::from_slice(signature).map_err(|_| denied())?,
            )
            .map_err(|_| denied())?;
        let p: PhaseProof = serde_json::from_slice(body).map_err(|_| denied())?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| denied())?
            .as_secs() as i64;
        let expected_state = match phase {
            ReceiptPhase::DispatchPreflight => "absent_or_not_started",
            ReceiptPhase::DispatchEffect => "started",
            ReceiptPhase::ReceiverHandoff | ReceiptPhase::CompletedRead => "completed",
        };
        let peer = fingerprint
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>();
        if p.issuer != "fixture-phase-issuer"
            || p.audience != "fixture-guard-phase"
            || p.phase != phase_number(phase)
            || p.operation != claims.operation_id
            || p.digest != claims.request_digest
            || p.tenant != claims.tenant_id
            || p.actor != claims.actor_id
            || p.delegation != claims.delegation_id
            || p.user_issuer != claims.user_issuer
            || p.user_subject != claims.user_subject
            || p.session != claims.session_reference
            || p.receiver_workload != claims.receiver_workload
            || p.result_scope != claims.scope
            || p.receiver_certificate != peer
            || p.nonce != nonce
            || p.guard_status != status
            || p.receipt_state != expected_state
            || p.fence_generation != 7
            || p.issued_at <= 0
            || p.issued_at > now
            || p.not_before <= 0
            || p.not_before > now
            || p.issued_at >= p.expires_at
            || p.not_before >= p.expires_at
            || p.expires_at
                .checked_sub(p.issued_at)
                .is_none_or(|v| v > 120)
            || p.expires_at <= now
            || !self.active.load(Ordering::SeqCst)
        {
            return Err(denied());
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    assertion_type: String,
    issuer: String,
    audience: String,
    control_workload: String,
    receiver_workload: String,
    guard_workload: String,
    user_issuer: String,
    user_subject: String,
    session_reference: String,
    actor_id: String,
    tenant_id: String,
    delegation_id: String,
    operation_id: String,
    request_digest: String,
    scope: String,
    issued_at: i64,
    not_before: i64,
    expires_at: i64,
}

struct FixtureVerifier(VerifyingKey);
#[tonic::async_trait]
impl ResultAssertionVerifier for FixtureVerifier {
    async fn verify(&self, bytes: &[u8]) -> Result<VerifiedResultAssertion, Status> {
        let denied = || Status::permission_denied("synthetic assertion denied");
        let (signature, body) = bytes.split_at_checked(64).ok_or_else(denied)?;
        let signature = Signature::from_slice(signature).map_err(|_| denied())?;
        self.0.verify(body, &signature).map_err(|_| denied())?;
        let c: Claims = serde_json::from_slice(body).map_err(|_| denied())?;
        Ok(VerifiedResultAssertion {
            assertion_type: c.assertion_type,
            issuer: c.issuer,
            audience: c.audience,
            // The authenticated fixture key fixes the signing identity.
            signer_workload: "spiffe://nex.local/service/control".into(),
            control_workload: c.control_workload,
            receiver_workload: c.receiver_workload,
            guard_workload: c.guard_workload,
            user_issuer: c.user_issuer,
            user_subject: c.user_subject,
            session_reference: c.session_reference,
            actor_id: c.actor_id,
            tenant_id: c.tenant_id,
            delegation_id: c.delegation_id,
            operation_id: c.operation_id,
            request_digest: c.request_digest,
            scope: c.scope,
            issued_at: c.issued_at,
            not_before: c.not_before,
            expires_at: c.expires_at,
        })
    }
}

// The in-process flag models revocation only for this test; it is not an
// authoritative production session source or a cross-system dispatch fence.
struct FixtureSession(AtomicBool);
#[tonic::async_trait]
impl ResultSessionAuthority for FixtureSession {
    async fn check_current(&self, _: &VerifiedResultAssertion) -> Result<(), Status> {
        if self.0.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(Status::permission_denied("synthetic session revoked"))
        }
    }
}

#[tokio::test]
async fn fixture_signature_and_revocation_are_enforced() {
    let key = SigningKey::from_bytes(&[42; 32]);
    let verifier = FixtureVerifier(key.verifying_key());
    let claims = Claims {
        assertion_type: "nex.result-access.v1".into(),
        issuer: "fixture-issuer".into(),
        audience: "fixture-guard".into(),
        control_workload: "spiffe://nex.local/service/control".into(),
        receiver_workload: "spiffe://nex.local/service/model".into(),
        guard_workload: "spiffe://nex.local/service/guard".into(),
        user_issuer: "https://fixture.invalid".into(),
        user_subject: "alice".into(),
        session_reference: "fixture-session".into(),
        actor_id: "alice".into(),
        tenant_id: "tenant-a".into(),
        delegation_id: "delegation-alice".into(),
        operation_id: "fixture-operation".into(),
        request_digest: "a".repeat(64),
        scope: "model.result".into(),
        issued_at: 1,
        not_before: 1,
        expires_at: 2,
    };
    let body = serde_json::to_vec(&claims).unwrap();
    let mut encoded = key.sign(&body).to_bytes().to_vec();
    encoded.extend_from_slice(&body);
    let checked = verifier.verify(&encoded).await.unwrap();
    let session = FixtureSession(AtomicBool::new(true));
    assert!(session.check_current(&checked).await.is_ok());
    session.0.store(false, Ordering::SeqCst);
    assert_eq!(
        session.check_current(&checked).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    *encoded.last_mut().unwrap() ^= 1;
    assert_eq!(
        verifier.verify(&encoded).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
}

// Requires a separately provisioned, freshly created synthetic DB containing
// the exact test job/manifest and a synthetic OPA. The orchestration wrapper
// must create fresh test PKI and supply its Guard, Control and Model identities.
// This test never changes the production binary or installs production trust.
#[tokio::test]
#[ignore = "requires separately provisioned synthetic PostgreSQL, OPA and fresh test PKI"]
async fn synthetic_guard_mtls_result_access_and_revocation() {
    use nex_guard_kernel::{
        Kernel,
        profile::Profile,
        protocol::{
            CompletionRequest, ExecutionRequest, PrepareRequest, ReceiptPhaseRequest,
            ResultAccessRequest, guard_client::GuardClient, guard_server::GuardServer,
        },
        result_access::{ResultAccessConfig, ResultAccessPolicy, SessionPolicy},
        trust::Trust,
    };
    use std::{
        fs,
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity, Server};

    assert_eq!(
        std::env::var("NEX_RESULT_TEST_DISPOSABLE").as_deref(),
        Ok("yes")
    );
    let database = std::env::var("NEX_RESULT_TEST_GUARD_DSN").expect("synthetic Guard DB URL");
    let parsed = reqwest::Url::parse(&database).expect("synthetic DB URL");
    assert_eq!(parsed.host_str(), Some("postgres"));
    assert!(
        parsed
            .path()
            .trim_start_matches('/')
            .starts_with("nex_result_fixture_")
    );
    assert_eq!(
        parsed
            .query_pairs()
            .filter(|(k, _)| k == "sslmode")
            .map(|(_, v)| v.into_owned())
            .collect::<Vec<_>>(),
        ["verify-full"]
    );
    // Guard loads its pinned PostgreSQL CA from NEX_DB_CA_FILE. pgx's
    // sslrootcert URL parameter is not accepted by tokio-postgres.
    let mut kernel_url = parsed.clone();
    let kernel_query = parsed
        .query_pairs()
        .filter(|(key, _)| key != "sslrootcert")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    kernel_url.query_pairs_mut().clear().extend_pairs(
        kernel_query
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    );
    let opa_url = std::env::var("NEX_RESULT_TEST_OPA_URL").expect("synthetic OPA URL");
    let pki = std::path::PathBuf::from(
        std::env::var("NEX_RESULT_TEST_PKI_DIR").expect("fresh synthetic PKI directory"),
    );
    let operation =
        std::env::var("NEX_RESULT_TEST_OPERATION").expect("prepared synthetic operation");
    let digest = std::env::var("NEX_RESULT_TEST_DIGEST").expect("prepared synthetic digest");
    assert_eq!(operation, "operation-v3-123");
    assert_eq!(
        digest,
        "6a6d7815d06aecae50ee34b5be18cc89637209f665a16f72d0e245d44af12109"
    );
    let trust = Arc::new(Trust::load().expect("fresh Guard mTLS identity"));
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let phase_key = SigningKey::from_bytes(&[43; 32]);
    let phase_authority = Arc::new(FixturePhaseAuthority {
        key: phase_key.verifying_key(),
        active: AtomicBool::new(true),
    });
    let sessions = Arc::new(FixtureSession(AtomicBool::new(true)));
    let session_policy = match std::env::var("NEX_RESULT_TEST_SESSION_MODE").as_deref() {
        Ok("original_session_only") => SessionPolicy::OriginalSessionOnly,
        Ok("current_session_same_actor") => SessionPolicy::CurrentSessionSameActor,
        _ => panic!("explicit synthetic session policy required"),
    };
    let policy = ResultAccessPolicy {
        issuer: "fixture-issuer".into(),
        audience: "fixture-guard".into(),
        user_issuer: "https://fixture.invalid".into(),
        control_workload: "spiffe://nex.local/service/control".into(),
        model_workload: "spiffe://nex.local/service/model".into(),
        export_workload: "spiffe://nex.local/service/export".into(),
        guard_workload: "spiffe://nex.local/service/guard".into(),
        max_lifetime_seconds: 120,
        session_policy,
    };
    let config = ResultAccessConfig::new(
        policy,
        Arc::new(FixtureVerifier(signing_key.verifying_key())),
        sessions.clone(),
    )
    .unwrap()
    .with_receipt_phase_authority(phase_authority.clone());
    let kernel =
        Kernel::new_with_profile(opa_url, &[], Profile::Qualification, Some(trust.clone()))
            .unwrap()
            .with_execution(kernel_url.as_str().to_owned(), &[], &[])
            .unwrap()
            .with_evidence(
                std::env::var("NEX_RESULT_TEST_EVIDENCE_URL").expect("synthetic evidence URL"),
                fs::read(pki.join("evidence-kernel.key")).expect("synthetic evidence capability"),
                fs::read(pki.join("evidence-public.key")).expect("synthetic evidence public key"),
            )
            .unwrap()
            .with_result_access(config)
            .unwrap();
    let shutdown = kernel.shutdown_control();
    // incoming binds internally, so reserve a candidate only briefly and retry
    // if another local process takes it before the actual listener starts.
    let mut bound = None;
    for _ in 0..10 {
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reserved.local_addr().unwrap();
        drop(reserved);
        if let Ok(incoming) =
            nex_guard_kernel::trust::incoming(address, trust.clone(), shutdown.clone()).await
        {
            bound = Some((address, incoming));
            break;
        }
    }
    let (address, incoming) = bound.expect("synthetic Guard loopback listener");
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(GuardServer::new(kernel))
            .serve_with_incoming(incoming)
            .await
    });
    async fn client(
        address: std::net::SocketAddr,
        dir: &std::path::Path,
        role: &str,
    ) -> GuardClient<Channel> {
        let ca = fs::read(dir.join("ca.crt")).unwrap();
        let certificate = fs::read(dir.join(role).join("tls.crt")).unwrap();
        let key = fs::read(dir.join(role).join("tls.key")).unwrap();
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca))
            .identity(Identity::from_pem(certificate, key))
            .domain_name("guard");
        let channel = Channel::from_shared(format!("https://{address}"))
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .connect_timeout(Duration::from_secs(3))
            // Guard bounds each RPC at 15 seconds. The competing claimant may
            // wait for the first transaction's policy and evidence calls.
            .timeout(Duration::from_secs(20))
            .connect()
            .await
            .unwrap();
        GuardClient::new(channel)
    }
    fn signed(key: &SigningKey, claims: &Claims) -> Vec<u8> {
        let body = serde_json::to_vec(claims).unwrap();
        let mut capability = key.sign(&body).to_bytes().to_vec();
        capability.extend(body);
        capability
    }
    fn denied<T>(result: Result<tonic::Response<T>, Status>) {
        match result {
            Err(status) => assert_eq!(status.code(), tonic::Code::PermissionDenied),
            Ok(_) => panic!("fixture request unexpectedly authorized"),
        }
    }
    let mut control = client(address, &pki, "control").await;
    let mut model = client(address, &pki, "model").await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = Claims {
        assertion_type: "nex.result-access.v1".into(),
        issuer: "fixture-issuer".into(),
        audience: "fixture-guard".into(),
        control_workload: "spiffe://nex.local/service/control".into(),
        receiver_workload: "spiffe://nex.local/service/model".into(),
        guard_workload: "spiffe://nex.local/service/guard".into(),
        user_issuer: "https://fixture.invalid".into(),
        user_subject: "test-subject".into(),
        session_reference: "test-session".into(),
        actor_id: "test-actor".into(),
        tenant_id: "tenant-a".into(),
        delegation_id: "test-delegation".into(),
        operation_id: operation.clone(),
        request_digest: digest.clone(),
        scope: "model.result".into(),
        issued_at: now - 1,
        not_before: now - 1,
        expires_at: now + 90,
    };
    let request = |claim: &Claims| ResultAccessRequest {
        operation_id: operation.clone(),
        request_digest: digest.clone(),
        service_capability: signed(&signing_key, claim),
    };
    async fn database_connection(
        url: &reqwest::Url,
    ) -> (
        tokio_postgres::Client,
        tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>,
    ) {
        assert_eq!(url.host_str(), Some("postgres"));
        assert!(
            url.path()
                .trim_start_matches('/')
                .starts_with("nex_result_fixture_")
        );
        assert_eq!(
            url.query_pairs()
                .filter(|(key, _)| key == "sslmode")
                .map(|(_, value)| value.into_owned())
                .collect::<Vec<_>>(),
            ["verify-full"]
        );
        let mut postgres_url = url.clone();
        let query = url
            .query_pairs()
            .filter(|(key, _)| key != "sslrootcert")
            .map(|(key, value)| {
                let sslmode = key == "sslmode";
                (
                    key.into_owned(),
                    if sslmode {
                        "require".to_owned()
                    } else {
                        value.into_owned()
                    },
                )
            })
            .collect::<Vec<_>>();
        postgres_url.query_pairs_mut().clear().extend_pairs(
            query
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str())),
        );
        let db_config: tokio_postgres::Config = postgres_url.as_str().parse().unwrap();
        let connector =
            tokio_postgres_rustls::MakeRustlsConnect::new(Trust::database_tls().unwrap());
        let (db, driver) = db_config.connect(connector).await.unwrap();
        (db, tokio::spawn(driver))
    }
    let (db, driver) = database_connection(&parsed).await;
    let admin_url = reqwest::Url::parse(
        &std::env::var("NEX_RESULT_TEST_ADMIN_DSN").expect("synthetic administrator DB URL"),
    )
    .unwrap();
    assert_eq!(admin_url.path(), parsed.path());
    assert_eq!(
        admin_url.port_or_known_default(),
        parsed.port_or_known_default()
    );
    let (admin, admin_driver) = database_connection(&admin_url).await;
    let guard_identity = db
        .query_one("SELECT current_database(),current_user", &[])
        .await
        .unwrap();
    let admin_identity = admin
        .query_one("SELECT current_database(),current_user", &[])
        .await
        .unwrap();
    let guard_database: String = guard_identity.get(0);
    let guard_user: String = guard_identity.get(1);
    let admin_database: String = admin_identity.get(0);
    let admin_user: String = admin_identity.get(1);
    assert_eq!(guard_database, admin_database);
    assert!(guard_database.starts_with("nex_result_fixture_"));
    assert!(guard_user.starts_with("nex_result_fixture_"));
    assert_ne!(guard_user, admin_user);
    let restricted: bool = admin.query_one("SELECT NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=pg_roles.oid) FROM pg_roles WHERE rolname=$1", &[&guard_user]).await.unwrap().get(0);
    assert!(restricted, "synthetic Guard login must be restricted");
    assert!(
        control
            .bind_result_identity(request(&claims))
            .await
            .unwrap()
            .into_inner()
            .allowed
    );
    let before: String = db.query_one("SELECT to_jsonb(b)::text FROM production_result_identity_bindings b WHERE operation_id=$1", &[&operation]).await.unwrap().get(0);
    assert!(
        model
            .check_result_access(request(&claims))
            .await
            .unwrap()
            .into_inner()
            .allowed
    );
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    use sha2::{Digest, Sha256};
    let certificate =
        CertificateDer::from_pem_slice(&fs::read(pki.join("model/tls.crt")).unwrap()).unwrap();
    let fingerprint = format!("{:x}", Sha256::digest(certificate.as_ref()));
    // These state transitions are synthetic administrator setup, not proof
    // that a real claimant, authorization grant, or fence was established.
    // They exercise the actual mTLS Guard RPCs against two distinct leaves
    // carrying the same model role, including legacy unbound operations.
    let mut rotated = client(address, &pki, "model-rotated").await;
    let state_request = || ExecutionRequest {
        operation_id: operation.clone(),
        request_digest: digest.clone(),
    };
    let result = serde_json::json!({"text":"synthetic result", "provider":"development", "model_id":"deterministic-review-v1"});
    let completion = || CompletionRequest {
        operation_id: operation.clone(),
        request_digest: digest.clone(),
        result_json: result.to_string(),
    };
    assert_eq!(
        model
            .execution_state(state_request())
            .await
            .unwrap()
            .into_inner()
            .state,
        "pending"
    );
    assert_eq!(
        rotated
            .execution_state(state_request())
            .await
            .unwrap()
            .into_inner()
            .state,
        "pending"
    );
    admin.execute("UPDATE execution_operations SET status='started', qualification_receiver_cert_sha256=NULL WHERE id=$1", &[&operation]).await.unwrap();
    assert_eq!(
        model
            .execution_state(state_request())
            .await
            .unwrap()
            .into_inner()
            .state,
        "unknown"
    );
    denied(model.complete_execution(completion()).await);
    admin
        .execute(
            "UPDATE execution_operations SET qualification_receiver_cert_sha256=$2 WHERE id=$1",
            &[&operation, &fingerprint],
        )
        .await
        .unwrap();
    assert_eq!(
        model
            .execution_state(state_request())
            .await
            .unwrap()
            .into_inner()
            .state,
        "started"
    );
    assert_eq!(
        rotated
            .execution_state(state_request())
            .await
            .unwrap()
            .into_inner()
            .state,
        "unknown"
    );
    denied(rotated.complete_execution(completion()).await);
    let unchanged = admin
        .query_one(
            "SELECT status,result FROM execution_operations WHERE id=$1",
            &[&operation],
        )
        .await
        .unwrap();
    assert_eq!(unchanged.get::<_, String>("status"), "started");
    assert_eq!(
        unchanged.get::<_, Option<serde_json::Value>>("result"),
        None
    );
    admin.execute("UPDATE execution_operations SET status='completed',result=$2,qualification_receiver_cert_sha256=NULL WHERE id=$1", &[&operation, &result]).await.unwrap();
    assert_eq!(
        model
            .execution_state(state_request())
            .await
            .unwrap()
            .into_inner()
            .state,
        "unknown"
    );
    denied(model.complete_execution(completion()).await);
    admin
        .execute(
            "UPDATE execution_operations SET qualification_receiver_cert_sha256=$2 WHERE id=$1",
            &[&operation, &fingerprint],
        )
        .await
        .unwrap();
    assert_eq!(
        model
            .execution_state(state_request())
            .await
            .unwrap()
            .into_inner()
            .state,
        "completed"
    );
    assert_eq!(
        rotated
            .execution_state(state_request())
            .await
            .unwrap()
            .into_inner()
            .state,
        "unknown"
    );
    denied(rotated.complete_execution(completion()).await);
    assert!(
        model
            .complete_execution(completion())
            .await
            .unwrap()
            .into_inner()
            .allowed
    );
    admin.execute("UPDATE execution_operations SET status='pending',result=NULL,qualification_receiver_cert_sha256=NULL WHERE id=$1", &[&operation]).await.unwrap();

    // Unlike the vector-state matrix above, this separate operation is prepared
    // and authorized by the real Guard RPCs, OPA and independently signed
    // fixture evidence. Both authenticated leaves race for one pending grant.
    let claim_operation = "operation-claim-123";
    let prepared = control
        .prepare_execution(PrepareRequest {
            job_id: "fixture-claim-job".into(),
            operation_id: claim_operation.into(),
        })
        .await
        .expect("real synthetic Guard prepare")
        .into_inner();
    assert!(!prepared.payload_json.is_empty() && prepared.request_digest.len() == 64);
    let claim_request = ExecutionRequest {
        operation_id: claim_operation.into(),
        request_digest: prepared.request_digest.clone(),
    };
    let (first, second) = tokio::join!(
        model.authorize_execution(claim_request.clone()),
        rotated.authorize_execution(claim_request.clone())
    );
    let first_won = match (first, second) {
        (Ok(allowed), Err(failure)) => {
            assert!(allowed.into_inner().allowed);
            assert_eq!(failure.code(), tonic::Code::PermissionDenied);
            true
        }
        (Err(failure), Ok(allowed)) => {
            assert!(allowed.into_inner().allowed);
            assert_eq!(failure.code(), tonic::Code::PermissionDenied);
            false
        }
        _ => panic!("exactly one authenticated model certificate must acquire the grant"),
    };
    let rotated_certificate =
        CertificateDer::from_pem_slice(&fs::read(pki.join("model-rotated/tls.crt")).unwrap())
            .unwrap();
    let rotated_fingerprint = format!("{:x}", Sha256::digest(rotated_certificate.as_ref()));
    assert_ne!(fingerprint, rotated_fingerprint);
    let winner_fingerprint = if first_won {
        &fingerprint
    } else {
        &rotated_fingerprint
    };
    let claimed = admin.query_one("SELECT status,qualification_receiver_cert_sha256,result FROM execution_operations WHERE id=$1", &[&claim_operation]).await.unwrap();
    assert_eq!(claimed.get::<_, String>("status"), "started");
    assert_eq!(
        claimed
            .get::<_, Option<String>>("qualification_receiver_cert_sha256")
            .as_deref(),
        Some(winner_fingerprint.as_str())
    );
    assert_eq!(claimed.get::<_, Option<serde_json::Value>>("result"), None);
    let completion = CompletionRequest {
        operation_id: claim_operation.into(),
        request_digest: prepared.request_digest.clone(),
        result_json: serde_json::json!({"text":"synthetic claim result", "provider":"development", "model_id":"deterministic-review-v1"}).to_string(),
    };
    let (winner, loser) = if first_won {
        (&mut model, &mut rotated)
    } else {
        (&mut rotated, &mut model)
    };
    assert_eq!(
        winner
            .execution_state(claim_request.clone())
            .await
            .unwrap()
            .into_inner()
            .state,
        "started"
    );
    assert_eq!(
        loser
            .execution_state(claim_request.clone())
            .await
            .unwrap()
            .into_inner()
            .state,
        "unknown"
    );
    denied(loser.complete_execution(completion.clone()).await);
    let before_complete = admin
        .query_one(
            "SELECT status,result FROM execution_operations WHERE id=$1",
            &[&claim_operation],
        )
        .await
        .unwrap();
    assert_eq!(before_complete.get::<_, String>("status"), "started");
    assert_eq!(
        before_complete.get::<_, Option<serde_json::Value>>("result"),
        None
    );
    assert!(
        winner
            .complete_execution(completion.clone())
            .await
            .unwrap()
            .into_inner()
            .allowed
    );
    assert!(
        winner
            .complete_execution(completion.clone())
            .await
            .unwrap()
            .into_inner()
            .allowed
    );
    assert_eq!(
        loser
            .execution_state(claim_request.clone())
            .await
            .unwrap()
            .into_inner()
            .state,
        "unknown"
    );
    denied(loser.complete_execution(completion).await);
    let committed = admin
        .query_one(
            "SELECT status,result FROM execution_operations WHERE id=$1",
            &[&claim_operation],
        )
        .await
        .unwrap();
    assert_eq!(committed.get::<_, String>("status"), "completed");
    assert_eq!(
        committed.get::<_, serde_json::Value>("result")["text"],
        "synthetic claim result"
    );
    let signed: i64 = admin.query_one("SELECT count(*) FROM audit_events WHERE job_id='fixture-claim-job' AND action IN ('model.prepared','model.authorized','model.completed') AND integrity_reference IS NOT NULL", &[]).await.unwrap().get(0);
    assert_eq!(signed, 3);
    // A separate reader verifies the retained journal against the public key,
    // then each signed journal proof is matched to the committed Guard row.
    // This does not independently anchor the journal against rollback.
    let evidence_binary = std::env::var("NEX_RESULT_TEST_EVIDENCE_BINARY")
        .expect("independent synthetic journal verifier binary");
    let journal = pki.join("journal");
    let verified = std::process::Command::new(evidence_binary)
        .arg("verify")
        .arg(&journal)
        .arg(pki.join("evidence-public.key"))
        .output()
        .expect("independent journal verification started");
    assert!(
        verified.status.success(),
        "independent journal verification failed"
    );
    let verification: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(verification["events"], 3);
    for (index, action) in ["model.prepared", "model.authorized", "model.completed"]
        .iter()
        .enumerate()
    {
        let entry: serde_json::Value = serde_json::from_slice(
            &fs::read(journal.join(format!("{:012}.json", index + 1))).unwrap(),
        )
        .unwrap();
        assert_eq!(entry["event"]["job_id"], "fixture-claim-job");
        assert_eq!(entry["event"]["action"], *action);
        let event_id = entry["event"]["event_id"].as_str().unwrap();
        let saved: serde_json::Value = admin.query_one(
            "SELECT integrity_reference FROM audit_events WHERE id=$1 AND job_id='fixture-claim-job' AND action=$2",
            &[&event_id, action],
        ).await.unwrap().get(0);
        assert_eq!(saved, entry["proof"]);
        if index == 2 {
            assert_eq!(verification["checkpoint"], saved);
        }
    }
    use std::io::Write;
    let mut receipt = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(pki.join("journal-verification.json"))
        .expect("new synthetic verification receipt");
    receipt.write_all(&verified.stdout).unwrap();
    receipt.sync_all().unwrap();
    let phase_proof = |phase: u8, status: &str, receipt: &str, nonce: &str| PhaseProof {
        issuer: "fixture-phase-issuer".into(),
        audience: "fixture-guard-phase".into(),
        phase,
        operation: operation.clone(),
        digest: digest.clone(),
        tenant: claims.tenant_id.clone(),
        actor: claims.actor_id.clone(),
        delegation: claims.delegation_id.clone(),
        user_issuer: claims.user_issuer.clone(),
        user_subject: claims.user_subject.clone(),
        session: claims.session_reference.clone(),
        receiver_workload: claims.receiver_workload.clone(),
        result_scope: claims.scope.clone(),
        receiver_certificate: fingerprint.clone(),
        nonce: nonce.into(),
        guard_status: status.into(),
        receipt_state: receipt.into(),
        fence_generation: 7,
        issued_at: now - 1,
        not_before: now - 1,
        expires_at: now + 90,
    };
    let phase_request = |phase: i32, nonce: &str, proof: &PhaseProof| {
        let body = serde_json::to_vec(proof).unwrap();
        let mut signed_proof = phase_key.sign(&body).to_bytes().to_vec();
        signed_proof.extend(body);
        ReceiptPhaseRequest {
            operation_id: operation.clone(),
            request_digest: digest.clone(),
            service_capability: signed(&signing_key, &claims),
            phase,
            claimant_nonce: nonce.into(),
            authority_proof: signed_proof,
        }
    };
    let preflight = phase_proof(1, "pending", "absent_or_not_started", "");
    let allowed = model
        .check_receipt_phase(phase_request(1, "", &preflight))
        .await
        .unwrap()
        .into_inner();
    assert!(allowed.allowed && allowed.state == "pending");
    denied(
        control
            .check_receipt_phase(phase_request(1, "", &preflight))
            .await,
    );
    let mut malformed = phase_request(1, "", &preflight);
    malformed.authority_proof.clear();
    denied(model.check_receipt_phase(malformed).await);
    let mut malformed = phase_request(1, "", &preflight);
    malformed.phase = 0;
    denied(model.check_receipt_phase(malformed).await);
    denied(
        model
            .check_receipt_phase(phase_request(1, &"a".repeat(32), &preflight))
            .await,
    );
    let mut mismatch = preflight.clone();
    mismatch.issuer = "untrusted-issuer".into();
    denied(
        model
            .check_receipt_phase(phase_request(1, "", &mismatch))
            .await,
    );
    mismatch = preflight.clone();
    mismatch.audience = "other-audience".into();
    denied(
        model
            .check_receipt_phase(phase_request(1, "", &mismatch))
            .await,
    );
    mismatch = preflight.clone();
    mismatch.not_before = now + 30;
    denied(
        model
            .check_receipt_phase(phase_request(1, "", &mismatch))
            .await,
    );
    mismatch = preflight.clone();
    mismatch.expires_at = now + 121;
    denied(
        model
            .check_receipt_phase(phase_request(1, "", &mismatch))
            .await,
    );
    mismatch = preflight.clone();
    mismatch.receiver_certificate = "0".repeat(64);
    denied(
        model
            .check_receipt_phase(phase_request(1, "", &mismatch))
            .await,
    );
    mismatch = preflight.clone();
    mismatch.tenant = "other-tenant".into();
    denied(
        model
            .check_receipt_phase(phase_request(1, "", &mismatch))
            .await,
    );
    mismatch = preflight.clone();
    mismatch.delegation = "other-delegation".into();
    denied(
        model
            .check_receipt_phase(phase_request(1, "", &mismatch))
            .await,
    );
    mismatch = preflight.clone();
    mismatch.user_subject = "other-subject".into();
    denied(
        model
            .check_receipt_phase(phase_request(1, "", &mismatch))
            .await,
    );
    mismatch = preflight.clone();
    mismatch.phase = 4;
    denied(
        model
            .check_receipt_phase(phase_request(1, "", &mismatch))
            .await,
    );
    mismatch = preflight.clone();
    mismatch.fence_generation = 8;
    denied(
        model
            .check_receipt_phase(phase_request(1, "", &mismatch))
            .await,
    );
    mismatch = preflight.clone();
    mismatch.receipt_state = "started".into();
    denied(
        model
            .check_receipt_phase(phase_request(1, "", &mismatch))
            .await,
    );
    mismatch = preflight.clone();
    mismatch.expires_at = now - 1;
    denied(
        model
            .check_receipt_phase(phase_request(1, "", &mismatch))
            .await,
    );
    let mut tampered_phase = phase_request(1, "", &preflight);
    *tampered_phase.authority_proof.last_mut().unwrap() ^= 1;
    denied(model.check_receipt_phase(tampered_phase).await);
    phase_authority.active.store(false, Ordering::SeqCst);
    denied(
        model
            .check_receipt_phase(phase_request(1, "", &preflight))
            .await,
    );
    phase_authority.active.store(true, Ordering::SeqCst);
    let nonce = "a".repeat(32);
    let effect = phase_proof(2, "started", "started", &nonce);
    denied(
        model
            .check_receipt_phase(phase_request(2, &nonce, &effect))
            .await,
    );
    admin
        .execute(
            "UPDATE execution_operations SET status='started' WHERE id=$1",
            &[&operation],
        )
        .await
        .unwrap();
    let allowed = model
        .check_receipt_phase(phase_request(2, &nonce, &effect))
        .await
        .unwrap()
        .into_inner();
    assert!(allowed.allowed && allowed.state == "started");
    mismatch = effect.clone();
    mismatch.nonce = "b".repeat(32);
    denied(
        model
            .check_receipt_phase(phase_request(2, &nonce, &mismatch))
            .await,
    );
    let handoff = phase_proof(3, "started", "completed", &nonce);
    let allowed = model
        .check_receipt_phase(phase_request(3, &nonce, &handoff))
        .await
        .unwrap()
        .into_inner();
    assert!(allowed.allowed && allowed.state == "started");
    let read = phase_proof(4, "completed", "completed", "");
    denied(model.check_receipt_phase(phase_request(4, "", &read)).await);
    admin
        .execute(
            "UPDATE execution_operations SET status='completed' WHERE id=$1",
            &[&operation],
        )
        .await
        .unwrap();
    let allowed = model
        .check_receipt_phase(phase_request(4, "", &read))
        .await
        .unwrap()
        .into_inner();
    assert!(allowed.allowed && allowed.state == "completed");
    admin
        .execute(
            "UPDATE execution_operations SET status='pending' WHERE id=$1",
            &[&operation],
        )
        .await
        .unwrap();
    denied(control.check_result_access(request(&claims)).await);
    let mut changed = claims.clone();
    changed.actor_id = "different-actor".into();
    denied(model.check_result_access(request(&changed)).await);
    changed = claims.clone();
    changed.tenant_id = "different-tenant".into();
    denied(model.check_result_access(request(&changed)).await);
    changed = claims.clone();
    changed.delegation_id = "different-delegation".into();
    denied(model.check_result_access(request(&changed)).await);
    changed = claims.clone();
    changed.request_digest = "b".repeat(64);
    denied(model.check_result_access(request(&changed)).await);
    changed = claims.clone();
    changed.scope = "export.result".into();
    denied(model.check_result_access(request(&changed)).await);
    changed = claims.clone();
    changed.session_reference = "different-session".into();
    denied(model.check_result_access(request(&changed)).await);
    admin.execute("INSERT INTO production_result_sessions(session_reference,issuer,subject,tenant_id,actor_id,delegation_id,expires_at) VALUES('test-reauth','https://fixture.invalid','test-subject','tenant-a','test-actor','test-delegation',clock_timestamp()+interval '5 minutes')", &[]).await.unwrap();
    changed = claims.clone();
    changed.session_reference = "test-reauth".into();
    let reauth = model.check_result_access(request(&changed)).await;
    if session_policy == SessionPolicy::CurrentSessionSameActor {
        assert!(reauth.unwrap().into_inner().allowed);
    } else {
        denied(reauth);
    }
    admin.execute("UPDATE production_result_sessions SET revoked_at=clock_timestamp() WHERE session_reference='test-session'", &[]).await.unwrap();
    denied(model.check_result_access(request(&claims)).await);
    denied(
        model
            .check_receipt_phase(phase_request(1, "", &preflight))
            .await,
    );
    admin.execute("UPDATE production_result_sessions SET revoked_at=NULL, expires_at=clock_timestamp()-interval '1 second' WHERE session_reference='test-session'", &[]).await.unwrap();
    denied(model.check_result_access(request(&claims)).await);
    admin.execute("UPDATE production_result_sessions SET expires_at=clock_timestamp()+interval '5 minutes' WHERE session_reference='test-session'", &[]).await.unwrap();
    assert!(
        model
            .check_result_access(request(&claims))
            .await
            .unwrap()
            .into_inner()
            .allowed
    );
    changed = claims.clone();
    changed.expires_at = now - 1;
    denied(model.check_result_access(request(&changed)).await);
    let mut tampered = request(&claims);
    *tampered.service_capability.last_mut().unwrap() ^= 1;
    denied(model.check_result_access(tampered).await);
    sessions.0.store(false, Ordering::SeqCst);
    denied(model.check_result_access(request(&claims)).await);
    let after: String = db.query_one("SELECT to_jsonb(b)::text FROM production_result_identity_bindings b WHERE operation_id=$1", &[&operation]).await.unwrap().get(0);
    assert_eq!(before, after, "result checks changed the bound identity");
    shutdown.begin();
    server.abort();
    drop(db);
    driver.abort();
    drop(admin);
    admin_driver.abort();
}
