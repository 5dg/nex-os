//! Unwired candidate outbox bridge. The caller must derive every field from
//! authenticated Guard state, insert the candidate context in the same
//! authoritative transaction, and roll that transaction back on any error.
//! Neither this function nor an outbox row authenticates a user, provides a
//! distributed fence, appends evidence, or permits prompt release.
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio_postgres::Transaction;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Scope {
    pub event_id: String,
    pub tenant_id: String,
    pub actor_id: String,
    pub job_id: String,
    pub resource_id: String,
    pub resource_version: String,
    pub delegation_id: String,
    pub operation_id: String,
    pub payload_digest: String,
    pub context_digest: String,
}

fn id(s: &str, min: usize) -> bool {
    (min..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn version(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_scope(s: &Scope) -> bool {
    id(&s.event_id, 8)
        && id(&s.tenant_id, 1)
        && id(&s.actor_id, 1)
        && id(&s.job_id, 1)
        && id(&s.resource_id, 1)
        && id(&s.delegation_id, 1)
        && id(&s.operation_id, 8)
        && version(&s.resource_version)
        && digest(&s.payload_digest)
        && digest(&s.context_digest)
}
fn text<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key)?.as_str()
}

// This accepts a server-constructed Value, never raw client JSON: serde_json's
// Value parser does not preserve duplicate object keys. Guard must construct
// detail and scope from its authenticated immutable operation records.
pub(crate) fn canonical_event(scope: &Scope, event: &Value) -> Result<Vec<u8>, ()> {
    if !valid_scope(scope)
        || text(event, "event_id") != Some(scope.event_id.as_str())
        || text(event, "tenant_id") != Some(scope.tenant_id.as_str())
        || text(event, "actor_id") != Some(scope.actor_id.as_str())
        || text(event, "job_id") != Some(scope.job_id.as_str())
        || text(event, "resource_id") != Some(scope.resource_id.as_str())
        || text(event, "delegation_id") != Some(scope.delegation_id.as_str())
        || text(event, "producer") != Some("kernel")
        || text(event, "action") != Some("model.prepared")
        || event
            .get("timestamp_us")
            .and_then(Value::as_i64)
            .filter(|n| *n > 0)
            .is_none()
    {
        return Err(());
    }
    let detail = event.get("detail").and_then(Value::as_object).ok_or(())?;
    let get = |name: &str| detail.get(name).and_then(Value::as_str);
    let provenance = detail
        .get("provenance")
        .and_then(Value::as_object)
        .ok_or(())?;
    if get("operation_id") != Some(scope.operation_id.as_str())
        || get("document_id") != Some(scope.resource_id.as_str())
        || get("document_version") != Some(scope.resource_version.as_str())
        || get("candidate_context_digest") != Some(scope.context_digest.as_str())
        || provenance.get("payload_digest").and_then(Value::as_str)
            != Some(scope.payload_digest.as_str())
    {
        return Err(());
    }
    let encoded = serde_json::to_vec(event).map_err(|_| ())?;
    let canonical = crate::evidence_v1::canonical_kernel_event(&encoded)?;
    if canonical.len() < 2 || canonical.len() > 128 * 1024 {
        return Err(());
    }
    Ok(canonical)
}

/// Writes into the caller's existing Guard transaction and does not commit.
/// Errors require rollback of the entire transaction, including context writes.
/// No event may be dispatched until that transaction has committed. The caller
/// must hold an independently established nonrollback admission fence; checks
/// here cannot fence a distributed journal or failover.
#[allow(dead_code)]
pub(crate) async fn enqueue(tx: &Transaction<'_>, scope: &Scope, event: &Value) -> Result<(), ()> {
    let canonical = canonical_event(scope, event)?;
    let hash = format!("{:x}", Sha256::digest(&canonical));
    tx.batch_execute("SET LOCAL synchronous_commit=on")
        .await
        .map_err(|_| ())?;
    let replica: bool = tx
        .query_one("SELECT pg_is_in_recovery()", &[])
        .await
        .map_err(|_| ())?
        .try_get(0)
        .map_err(|_| ())?;
    if replica {
        return Err(());
    }
    tx.execute("INSERT INTO nex_candidate_evidence.outbox(event_id,tenant_id,actor_id,job_id,resource_id,resource_version,delegation_id,operation_id,payload_digest,context_digest,event_bytes,event_sha256,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pending') ON CONFLICT(event_id) DO NOTHING", &[&scope.event_id,&scope.tenant_id,&scope.actor_id,&scope.job_id,&scope.resource_id,&scope.resource_version,&scope.delegation_id,&scope.operation_id,&scope.payload_digest,&scope.context_digest,&canonical,&hash]).await.map_err(|_| ())?;
    let row = tx.query_one("SELECT tenant_id,actor_id,job_id,resource_id,resource_version,delegation_id,operation_id,payload_digest,context_digest,event_bytes,event_sha256,state,proof_bytes FROM nex_candidate_evidence.outbox WHERE event_id=$1 FOR UPDATE", &[&scope.event_id]).await.map_err(|_| ())?;
    let expected = [
        &scope.tenant_id,
        &scope.actor_id,
        &scope.job_id,
        &scope.resource_id,
        &scope.resource_version,
        &scope.delegation_id,
        &scope.operation_id,
        &scope.payload_digest,
        &scope.context_digest,
    ];
    for (index, value) in expected.into_iter().enumerate() {
        let actual: String = row.try_get(index).map_err(|_| ())?;
        if actual.as_str() != value.as_str() {
            return Err(());
        }
    }
    let actual_bytes: Vec<u8> = row.try_get(9).map_err(|_| ())?;
    let actual_hash: String = row.try_get(10).map_err(|_| ())?;
    let state: String = row.try_get(11).map_err(|_| ())?;
    let proof: Option<Vec<u8>> = row.try_get(12).map_err(|_| ())?;
    if actual_bytes != canonical
        || actual_hash != hash
        || !match (state.as_str(), proof) {
            ("pending", None) => true,
            ("emitted", Some(p)) => (2..=16 * 1024).contains(&p.len()),
            _ => false,
        }
    {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Scope, Value, String) {
        let vectors: Vec<Value> = serde_json::from_str(include_str!(
            "../../../packages/evidence/candidate-outbox-vectors.json"
        ))
        .unwrap();
        assert_eq!(vectors.len(), 1);
        let v = &vectors[0];
        let s = &v["scope"];
        let field = |name: &str| s[name].as_str().unwrap().to_owned();
        (
            Scope {
                event_id: field("event_id"),
                tenant_id: field("tenant_id"),
                actor_id: field("actor_id"),
                job_id: field("job_id"),
                resource_id: field("resource_id"),
                resource_version: field("resource_version"),
                delegation_id: field("delegation_id"),
                operation_id: field("operation_id"),
                payload_digest: field("payload_digest"),
                context_digest: field("context_digest"),
            },
            v["event"].clone(),
            v["canonical"].as_str().unwrap().to_owned(),
        )
    }

    #[test]
    fn candidate_event_matches_shared_go_canonical_bytes() {
        let (scope, event, expected) = fixture();
        assert_eq!(
            canonical_event(&scope, &event).unwrap(),
            expected.as_bytes()
        );
    }

    #[test]
    fn substituted_scope_and_event_cannot_be_encoded() {
        let (scope, event, _) = fixture();
        for field in [
            "event_id",
            "tenant_id",
            "actor_id",
            "job_id",
            "resource_id",
            "delegation_id",
            "producer",
            "action",
            "timestamp_us",
        ] {
            let mut changed = event.clone();
            changed[field] = Value::Null;
            assert!(canonical_event(&scope, &changed).is_err(), "{field}");
        }
        for field in [
            "operation_id",
            "document_id",
            "document_version",
            "candidate_context_digest",
        ] {
            let mut changed = event.clone();
            changed["detail"][field] = Value::String("other".to_owned());
            assert!(canonical_event(&scope, &changed).is_err(), "{field}");
        }
        let mut changed = event.clone();
        changed["detail"]["provenance"]["payload_digest"] = Value::String("other".to_owned());
        assert!(canonical_event(&scope, &changed).is_err());
        let mut changed_scope = scope.clone();
        changed_scope.resource_version.clear();
        assert!(canonical_event(&changed_scope, &event).is_err());
        changed_scope = scope;
        changed_scope.delegation_id.clear();
        assert!(canonical_event(&changed_scope, &event).is_err());
    }

    // A runtime coordinator creates a fresh, dedicated TLS database and a
    // separately authenticated restricted role, installs the outbox schema,
    // and runs the Go interoperability test only after this test succeeds.
    #[tokio::test]
    async fn synthetic_postgres_transaction_bridge() {
        let Ok(url) = std::env::var("NEX_EVIDENCE_BRIDGE_DSN") else {
            eprintln!("synthetic bridge database not configured");
            return;
        };
        assert_eq!(
            std::env::var("NEX_EVIDENCE_BRIDGE_FIXTURE").ok().as_deref(),
            Some("disposable-only")
        );
        let state = crate::state::StateStore::new(crate::profile::Profile::Qualification, &url)
            .expect("verified synthetic database configuration required");
        let mut writer = state.connect().await.expect("synthetic writer unavailable");
        let reader = state.connect().await.expect("synthetic reader unavailable");
        let identity = writer
            .query_one("SELECT current_database(),current_user", &[])
            .await
            .expect("fixture identity unavailable");
        let db: String = identity.get(0);
        let role: String = identity.get(1);
        assert!(db.starts_with("nex_evidence_bridge_") && role.starts_with("nex_evidence_bridge_"));
        let restricted: bool = writer.query_one("SELECT NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=pg_roles.oid) AND NOT EXISTS(SELECT FROM pg_database WHERE datname=current_database() AND datdba=pg_roles.oid) FROM pg_roles WHERE rolname=current_user", &[]).await.expect("role inspection failed").get(0);
        assert!(restricted);
        let count: i64 = writer
            .query_one("SELECT count(*) FROM nex_candidate_evidence.outbox", &[])
            .await
            .expect("fixture schema unavailable")
            .get(0);
        assert_eq!(count, 0, "fresh fixture required");
        let (scope, event, _) = fixture();
        let tx = writer
            .transaction()
            .await
            .expect("fixture transaction unavailable");
        assert!(enqueue(&tx, &scope, &event).await.is_ok());
        let visible: i64 = reader
            .query_one(
                "SELECT count(*) FROM nex_candidate_evidence.outbox WHERE event_id=$1",
                &[&scope.event_id],
            )
            .await
            .expect("fixture query failed")
            .get(0);
        assert_eq!(visible, 0, "uncommitted event visible to dispatcher");
        tx.rollback().await.expect("fixture rollback failed");
        let visible: i64 = reader
            .query_one(
                "SELECT count(*) FROM nex_candidate_evidence.outbox WHERE event_id=$1",
                &[&scope.event_id],
            )
            .await
            .expect("fixture query failed")
            .get(0);
        assert_eq!(visible, 0);
        let tx = writer
            .transaction()
            .await
            .expect("fixture transaction unavailable");
        assert!(enqueue(&tx, &scope, &event).await.is_ok());
        assert!(enqueue(&tx, &scope, &event).await.is_ok());
        tx.commit().await.expect("fixture commit failed");
        let mut changed = event.clone();
        changed["detail"]["other"] = Value::Bool(true);
        let tx = writer
            .transaction()
            .await
            .expect("fixture transaction unavailable");
        assert!(
            enqueue(&tx, &scope, &changed).await.is_err(),
            "changed content reused event ID"
        );
        tx.rollback().await.expect("fixture rollback failed");
        let row = reader.query_one("SELECT state,proof_bytes,event_bytes FROM nex_candidate_evidence.outbox WHERE event_id=$1", &[&scope.event_id]).await.expect("fixture query failed");
        let status: String = row.get(0);
        let proof: Option<Vec<u8>> = row.get(1);
        let bytes: Vec<u8> = row.get(2);
        assert_eq!(status, "pending");
        assert!(proof.is_none());
        assert_eq!(bytes, canonical_event(&scope, &event).unwrap());
        println!("synthetic bridge transaction completed");
    }
}
