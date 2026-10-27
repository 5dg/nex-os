-- Preserve v1 operations. Only operations with a v2 kernel-owned manifest execute.
CREATE TABLE execution_manifests (
 operation_id text PRIMARY KEY REFERENCES execution_operations(id),
 version integer NOT NULL CHECK(version=2),
 payload jsonb NOT NULL,
 payload_digest text NOT NULL,
 context_digest text NOT NULL,
 expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE execution_operations ADD COLUMN result jsonb;
ALTER TABLE execution_operations ADD COLUMN completed_at timestamptz;
-- Existing history is never rewritten to claim v2 verification.
ALTER TABLE jobs ADD COLUMN review_operation_id text REFERENCES execution_operations(id);
