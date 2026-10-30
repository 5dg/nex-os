-- A committed reconciliation transition and this immutable event are inserted
-- in the same transaction. This table does not assert delivery or independent
-- custody, and no dispatcher or production grant is installed by migration.
CREATE TABLE committed_reconciliation_outbox (
 event_id text PRIMARY KEY CHECK (length(event_id) BETWEEN 8 AND 128),
 tenant_id text NOT NULL,
 job_id text NOT NULL,
 operation_id text NOT NULL,
 event_bytes bytea NOT NULL CHECK (octet_length(event_bytes) BETWEEN 2 AND 131072),
 event_sha256 text NOT NULL CHECK (event_sha256 ~ '^[0-9a-f]{64}$' AND event_sha256=encode(sha256(event_bytes),'hex')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE (job_id,operation_id),
 FOREIGN KEY (tenant_id,job_id) REFERENCES jobs(tenant_id,id)
);
REVOKE ALL ON committed_reconciliation_outbox FROM PUBLIC;
