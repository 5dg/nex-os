-- Additive preparation-only candidate context. Existing v2/v3 manifests and
-- their encodings are untouched; no historical row is promoted or rewritten.
-- Runtime profile parsing remains closed and no production grants are made.
ALTER TABLE jobs DROP CONSTRAINT jobs_execution_profile_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_execution_profile_check
 CHECK (execution_profile IN ('development','synthetic-qualification','production-model-candidate'));
ALTER TABLE jobs ADD COLUMN model_route_id text;
ALTER TABLE jobs ADD CONSTRAINT candidate_model_route_required
 CHECK ((execution_profile = 'production-model-candidate' AND model_route_id IS NOT NULL)
     OR (execution_profile <> 'production-model-candidate' AND model_route_id IS NULL));
ALTER TABLE jobs ADD CONSTRAINT candidate_model_route_tenant_fk
 FOREIGN KEY (tenant_id,model_route_id) REFERENCES model_routes(tenant_id,id);
ALTER TABLE execution_operations ADD CONSTRAINT candidate_operation_identity_unique
 UNIQUE (id,tenant_id,request_digest);

CREATE TABLE production_model_contexts (
 operation_id text PRIMARY KEY,
 tenant_id text NOT NULL,
 request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
 version integer NOT NULL CHECK(version=1),
 canonical_context bytea NOT NULL CHECK(octet_length(canonical_context) BETWEEN 1 AND 16384),
 context_digest text NOT NULL CHECK(context_digest ~ '^[0-9a-f]{64}$'),
 policy_id text NOT NULL CHECK(length(policy_id) BETWEEN 1 AND 128),
 policy_version text NOT NULL CHECK(length(policy_version) BETWEEN 1 AND 128),
 policy_digest text NOT NULL CHECK(policy_digest ~ '^[0-9a-f]{64}$'),
 lock_version bigint NOT NULL DEFAULT 0,
 FOREIGN KEY (operation_id,tenant_id,request_digest)
   REFERENCES execution_operations(id,tenant_id,request_digest)
);

-- Empty/default-disabled until an independently authorized admission process
-- installs the exact immutable document version for a trusted policy.
CREATE TABLE production_model_document_admissions (
 tenant_id text NOT NULL,
 resource_id text NOT NULL,
 document_version text NOT NULL,
 content_digest text NOT NULL CHECK(content_digest ~ '^[0-9a-f]{64}$'),
 policy_digest text NOT NULL CHECK(policy_digest ~ '^[0-9a-f]{64}$'),
 enabled boolean NOT NULL DEFAULT false,
 lock_version bigint NOT NULL DEFAULT 0,
 PRIMARY KEY (tenant_id,resource_id,document_version,policy_digest),
 FOREIGN KEY (tenant_id,resource_id) REFERENCES resources(tenant_id,id)
);

-- Installed only by a separately authenticated session-binding authority.
-- No candidate can derive a session identity merely from a job owner.
CREATE TABLE production_model_job_identity_bindings (
 job_id text PRIMARY KEY,
 tenant_id text NOT NULL,
 actor_id text NOT NULL,
 delegation_id text NOT NULL,
 issuer text NOT NULL,
 subject text NOT NULL,
 original_session_reference text NOT NULL,
 lock_version bigint NOT NULL DEFAULT 0,
 FOREIGN KEY (tenant_id,job_id) REFERENCES jobs(tenant_id,id),
 FOREIGN KEY (tenant_id,actor_id) REFERENCES users(tenant_id,id),
 FOREIGN KEY (tenant_id,delegation_id) REFERENCES delegations(tenant_id,id),
 FOREIGN KEY (original_session_reference) REFERENCES production_result_sessions(session_reference)
);
REVOKE ALL ON production_model_contexts,production_model_document_admissions,
 production_model_job_identity_bindings FROM PUBLIC;
