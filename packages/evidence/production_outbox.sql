-- Additive candidate evidence outbox. No existing journal, event encoding or
-- historical migration is changed. Runtime roles receive no grants here.
CREATE SCHEMA nex_candidate_evidence;
CREATE TABLE nex_candidate_evidence.outbox (
 event_id text PRIMARY KEY CHECK (event_id ~ '^[A-Za-z0-9_-]{8,128}$'),
 tenant_id text NOT NULL, actor_id text NOT NULL, job_id text NOT NULL,
 resource_id text NOT NULL, resource_version text NOT NULL, delegation_id text NOT NULL,
 operation_id text NOT NULL, payload_digest text NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
 context_digest text NOT NULL CHECK (context_digest ~ '^[0-9a-f]{64}$'),
 event_bytes bytea NOT NULL CHECK (octet_length(event_bytes) BETWEEN 2 AND 131072),
 event_sha256 text NOT NULL CHECK (event_sha256 ~ '^[0-9a-f]{64}$'),
 state text NOT NULL CHECK (state IN ('pending','emitted')),
 proof_bytes bytea,
 CHECK ((state='pending' AND proof_bytes IS NULL) OR
        (state='emitted' AND proof_bytes IS NOT NULL AND octet_length(proof_bytes) BETWEEN 2 AND 16384))
);
REVOKE ALL ON SCHEMA nex_candidate_evidence FROM PUBLIC;
REVOKE ALL ON nex_candidate_evidence.outbox FROM PUBLIC;
