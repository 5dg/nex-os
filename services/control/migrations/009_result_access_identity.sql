-- Additive production result-access state. No historical v2/v3 manifest or
-- prior receipt is changed. Empty tables deny access until authenticated
-- identity/session provisioning and scoped database grants are implemented.
-- PostgreSQL row locks require UPDATE privilege on at least one column. These
-- inert columns allow a result-access role to lock rows without permission to
-- update job, operation, or manifest authority fields. No grant is made here.
ALTER TABLE jobs ADD COLUMN result_access_lock_version bigint NOT NULL DEFAULT 0;
ALTER TABLE execution_operations ADD COLUMN result_access_lock_version bigint NOT NULL DEFAULT 0;
ALTER TABLE execution_manifests ADD COLUMN result_access_lock_version bigint NOT NULL DEFAULT 0;
CREATE TABLE production_result_tenant_status (
 tenant_id text PRIMARY KEY REFERENCES tenants(id),
 enabled boolean NOT NULL DEFAULT false,
 lock_version bigint NOT NULL DEFAULT 0
);
CREATE TABLE production_result_actor_status (
 tenant_id text NOT NULL, actor_id text NOT NULL,
 enabled boolean NOT NULL DEFAULT false,
 lock_version bigint NOT NULL DEFAULT 0,
 PRIMARY KEY (tenant_id, actor_id),
 FOREIGN KEY (tenant_id, actor_id) REFERENCES users(tenant_id,id)
);
CREATE TABLE production_result_sessions (
 session_reference text PRIMARY KEY CHECK(length(session_reference) BETWEEN 1 AND 512),
 issuer text NOT NULL, subject text NOT NULL,
 tenant_id text NOT NULL, actor_id text NOT NULL, delegation_id text NOT NULL,
 expires_at timestamptz NOT NULL, revoked_at timestamptz,
 lock_version bigint NOT NULL DEFAULT 0,
 FOREIGN KEY (tenant_id, actor_id) REFERENCES users(tenant_id,id),
 FOREIGN KEY (tenant_id, delegation_id) REFERENCES delegations(tenant_id,id)
);
CREATE TABLE production_result_identity_bindings (
 operation_id text PRIMARY KEY REFERENCES execution_operations(id),
 request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
 kind text NOT NULL CHECK(kind IN ('model','export')),
 tenant_id text NOT NULL, actor_id text NOT NULL, delegation_id text NOT NULL,
 issuer text NOT NULL, subject text NOT NULL,
 original_session_reference text NOT NULL CHECK(length(original_session_reference) BETWEEN 1 AND 512),
 lock_version bigint NOT NULL DEFAULT 0,
 FOREIGN KEY (tenant_id, actor_id) REFERENCES users(tenant_id,id),
 FOREIGN KEY (tenant_id, delegation_id) REFERENCES delegations(tenant_id,id),
 FOREIGN KEY (original_session_reference) REFERENCES production_result_sessions(session_reference)
);
REVOKE ALL ON production_result_tenant_status,production_result_actor_status,
 production_result_sessions,production_result_identity_bindings FROM PUBLIC;
