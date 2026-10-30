//! Synthetic database fixture for the dormant candidate transaction helper.
//! This is not a trusted identity, journal durability, or production test.
use super::*;
use crate::{profile::Profile, state::StateStore};
use tokio_postgres::{Row, Transaction};

async fn synthetic_job(tx: &Transaction<'_>) -> Row {
    tx.query_one("SELECT 'tenant-a'::text AS tenant_id,'alice'::text AS owner_id,'job-0001'::text AS id,'delegation'::text AS delegation_id,'document'::text AS document_id,'v1'::text AS document_version", &[]).await.expect("fixture job unavailable")
}
async fn enqueue_fixture(
    tx: &Transaction<'_>,
    new: bool,
    candidate_digest: &str,
) -> Result<(), tonic::Status> {
    enqueue_fixture_operation(tx, new, candidate_digest, "operation-001").await
}
async fn enqueue_fixture_operation(
    tx: &Transaction<'_>,
    new: bool,
    candidate_digest: &str,
    operation: &str,
) -> Result<(), tonic::Status> {
    let job = synthetic_job(tx).await;
    enqueue_candidate_prepared(
        tx,
        &job,
        operation,
        &"a".repeat(64),
        &"b".repeat(64),
        &serde_json::json!({"version":3}),
        candidate_digest,
        &"d".repeat(64),
        "route-1",
        new,
    )
    .await
}
async fn retry_fixture(client: &mut tokio_postgres::Client) -> Result<(), ()> {
    let tx = client.transaction().await.map_err(|_| ())?;
    enqueue_fixture(&tx, false, &"c".repeat(64))
        .await
        .map_err(|_| ())?;
    tx.commit().await.map_err(|_| ())
}

#[tokio::test]
async fn synthetic_candidate_transaction_and_concurrent_retry() {
    let Ok(url) = std::env::var("NEX_CANDIDATE_TX_DSN") else {
        eprintln!("synthetic candidate transaction database not configured");
        return;
    };
    assert_eq!(
        std::env::var("NEX_CANDIDATE_TX_FIXTURE").ok().as_deref(),
        Some("disposable-only")
    );
    let state = StateStore::new(Profile::Qualification, &url)
        .expect("verified synthetic database configuration required");
    let mut writer = state.connect().await.expect("synthetic writer unavailable");
    let reader = state.connect().await.expect("synthetic reader unavailable");
    let identity = writer
        .query_one("SELECT current_database(),current_user", &[])
        .await
        .expect("fixture identity unavailable");
    let db: String = identity.get(0);
    let role: String = identity.get(1);
    assert!(db.starts_with("nex_candidate_tx_") && role.starts_with("nex_candidate_tx_"));
    let restricted: bool = writer.query_one("SELECT NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=pg_roles.oid) AND NOT EXISTS(SELECT FROM pg_database WHERE datname=current_database() AND datdba=pg_roles.oid) FROM pg_roles WHERE rolname=current_user", &[]).await.expect("role inspection failed").get(0);
    assert!(restricted);
    let locked: bool = writer.query_one("SELECT has_column_privilege(current_user,'audit_events','candidate_lock_version','UPDATE') AND NOT EXISTS (SELECT FROM pg_attribute WHERE attrelid='audit_events'::regclass AND attnum>0 AND NOT attisdropped AND attname<>'candidate_lock_version' AND has_column_privilege(current_user,attrelid,attname,'UPDATE')) AND NOT has_table_privilege(current_user,'audit_events','DELETE') AND NOT has_table_privilege(current_user,'audit_events','TRUNCATE') AND has_table_privilege(current_user,'audit_events','INSERT') AND NOT EXISTS (SELECT FROM pg_attribute WHERE attrelid='nex_candidate_evidence.outbox'::regclass AND attnum>0 AND NOT attisdropped AND attname NOT IN ('state','proof_bytes') AND has_column_privilege(current_user,attrelid,attname,'UPDATE')) AND NOT has_table_privilege(current_user,'nex_candidate_evidence.outbox','DELETE') AND NOT has_table_privilege(current_user,'nex_candidate_evidence.outbox','TRUNCATE')", &[]).await.expect("fixture privilege inspection failed").get(0);
    assert!(
        locked,
        "immutable audit and outbox fields must not be writable"
    );
    let initial: i64 = writer.query_one("SELECT (SELECT count(*) FROM audit_events)+(SELECT count(*) FROM nex_candidate_evidence.outbox)+(SELECT count(*) FROM nex_candidate_test.contexts)", &[]).await.expect("fixture schema unavailable").get(0);
    assert_eq!(initial, 0, "fresh fixture required");
    let candidate_digest = "c".repeat(64);
    // Context, audit and outbox become visible together or not at all.
    let tx = writer
        .transaction()
        .await
        .expect("fixture transaction unavailable");
    tx.execute(
        "INSERT INTO nex_candidate_test.contexts(operation_id,digest) VALUES('operation-001',$1)",
        &[&candidate_digest],
    )
    .await
    .expect("fixture context insert failed");
    assert!(enqueue_fixture(&tx, true, &candidate_digest).await.is_ok());
    let visible: i64 = reader.query_one("SELECT (SELECT count(*) FROM audit_events)+(SELECT count(*) FROM nex_candidate_evidence.outbox)+(SELECT count(*) FROM nex_candidate_test.contexts)", &[]).await.expect("fixture query failed").get(0);
    assert_eq!(visible, 0);
    tx.rollback().await.expect("fixture rollback failed");
    let visible: i64 = reader.query_one("SELECT (SELECT count(*) FROM audit_events)+(SELECT count(*) FROM nex_candidate_evidence.outbox)+(SELECT count(*) FROM nex_candidate_test.contexts)", &[]).await.expect("fixture query failed").get(0);
    assert_eq!(visible, 0);
    let tx = writer
        .transaction()
        .await
        .expect("fixture transaction unavailable");
    tx.execute(
        "INSERT INTO nex_candidate_test.contexts(operation_id,digest) VALUES('operation-001',$1)",
        &[&candidate_digest],
    )
    .await
    .expect("fixture context insert failed");
    assert!(enqueue_fixture(&tx, true, &candidate_digest).await.is_ok());
    tx.commit().await.expect("fixture commit failed");
    let id = candidate_prepared_event_id("tenant-a", "operation-001");
    let before = reader.query_one("SELECT event_bytes,event_sha256,state,proof_bytes FROM nex_candidate_evidence.outbox WHERE event_id=$1", &[&id]).await.expect("fixture outbox unavailable");
    let event: Vec<u8> = before.get(0);
    let hash: String = before.get(1);
    let state_before: String = before.get(2);
    let proof: Option<Vec<u8>> = before.get(3);
    assert_eq!(state_before, "pending");
    assert!(proof.is_none());
    // Distinct restricted connections perform identical retries concurrently.
    let mut first = state
        .connect()
        .await
        .expect("first fixture connection unavailable");
    let mut second = state
        .connect()
        .await
        .expect("second fixture connection unavailable");
    let (a, b) = tokio::join!(retry_fixture(&mut first), retry_fixture(&mut second));
    assert!(
        a.is_ok() && b.is_ok(),
        "concurrent identical retries failed"
    );
    let tx = writer
        .transaction()
        .await
        .expect("fixture transaction unavailable");
    assert!(
        enqueue_fixture(&tx, false, &"e".repeat(64)).await.is_err(),
        "changed evidence scope accepted"
    );
    tx.rollback().await.expect("fixture rollback failed");
    let after = reader.query_one("SELECT event_bytes,event_sha256,state,proof_bytes FROM nex_candidate_evidence.outbox WHERE event_id=$1", &[&id]).await.expect("fixture outbox unavailable");
    assert_eq!(after.get::<_, Vec<u8>>(0), event);
    assert_eq!(after.get::<_, String>(1), hash);
    assert_eq!(after.get::<_, String>(2), "pending");
    assert!(after.get::<_, Option<Vec<u8>>>(3).is_none());
    // An existing context/audit without its original outbox is not repaired
    // during retry, even when the immutable audit fields otherwise match.
    let missing_op = "operation-missing";
    let missing_id = candidate_prepared_event_id("tenant-a", missing_op);
    let tx = writer
        .transaction()
        .await
        .expect("fixture transaction unavailable");
    tx.execute(
        "INSERT INTO nex_candidate_test.contexts(operation_id,digest) VALUES($1,$2)",
        &[&missing_op, &candidate_digest],
    )
    .await
    .expect("fixture context insert failed");
    let inserted = tx.execute("INSERT INTO audit_events(id,tenant_id,actor_id,delegation_id,resource_id,action,decision,job_id,created_at) SELECT $1,tenant_id,actor_id,delegation_id,resource_id,action,jsonb_set(decision,'{operation_id}',to_jsonb($2::text)),job_id,created_at FROM audit_events WHERE id=$3", &[&missing_id,&missing_op,&id]).await.expect("fixture audit insert failed");
    assert_eq!(inserted, 1);
    tx.commit().await.expect("fixture commit failed");
    let tx = writer
        .transaction()
        .await
        .expect("fixture transaction unavailable");
    assert!(
        enqueue_fixture_operation(&tx, false, &candidate_digest, missing_op)
            .await
            .is_err(),
        "missing outbox was silently recreated"
    );
    tx.rollback().await.expect("fixture rollback failed");
    let missing: i64 = reader
        .query_one(
            "SELECT count(*) FROM nex_candidate_evidence.outbox WHERE event_id=$1",
            &[&missing_id],
        )
        .await
        .expect("fixture query failed")
        .get(0);
    assert_eq!(missing, 0);
    println!("synthetic candidate transaction completed");
}
