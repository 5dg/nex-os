-- Apply once as the database migration owner, never as a receiver. Runtime
-- roles receive USAGE and SELECT/INSERT/UPDATE only on their own schema/table.
-- No role, grant, existing receipt, or production profile is created here.
CREATE SCHEMA nex_model_receipts;
REVOKE ALL ON SCHEMA nex_model_receipts FROM PUBLIC;
CREATE TABLE nex_model_receipts.operations (
    operation_id text PRIMARY KEY CHECK (operation_id ~ '^[A-Za-z0-9_-]{8,100}$'),
    request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    owner_nonce text NOT NULL CHECK (owner_nonce ~ '^[0-9a-f]{32}$'),
    state text NOT NULL CHECK (state IN ('prepared', 'started', 'not_started', 'completed')),
    result_bytes bytea,
    CHECK ((state = 'completed' AND result_bytes IS NOT NULL AND octet_length(result_bytes) BETWEEN 1 AND 131072)
        OR (state <> 'completed' AND result_bytes IS NULL))
);
REVOKE ALL ON nex_model_receipts.operations FROM PUBLIC;

CREATE SCHEMA nex_export_receipts;
REVOKE ALL ON SCHEMA nex_export_receipts FROM PUBLIC;
CREATE TABLE nex_export_receipts.operations (
    operation_id text PRIMARY KEY CHECK (operation_id ~ '^[A-Za-z0-9_-]{8,100}$'),
    request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    owner_nonce text NOT NULL CHECK (owner_nonce ~ '^[0-9a-f]{32}$'),
    state text NOT NULL CHECK (state IN ('prepared', 'started', 'not_started', 'completed')),
    result_bytes bytea,
    CHECK ((state = 'completed' AND result_bytes IS NOT NULL AND octet_length(result_bytes) BETWEEN 1 AND 131072)
        OR (state <> 'completed' AND result_bytes IS NULL))
);
REVOKE ALL ON nex_export_receipts.operations FROM PUBLIC;
