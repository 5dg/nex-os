ALTER TABLE delegations ADD CONSTRAINT delegation_tenant_id_unique UNIQUE(tenant_id,id);
ALTER TABLE audit_events ADD COLUMN job_id text;
CREATE INDEX audit_job_tenant ON audit_events(tenant_id,job_id,created_at);
ALTER TABLE jobs ADD COLUMN owner_id text;
ALTER TABLE jobs ADD COLUMN document_id text;
ALTER TABLE jobs ADD COLUMN document_version text;
ALTER TABLE jobs ADD COLUMN question text;
ALTER TABLE jobs ADD COLUMN phase text NOT NULL DEFAULT 'review';
ALTER TABLE jobs ADD COLUMN answer text NOT NULL DEFAULT '';
ALTER TABLE jobs ADD COLUMN provider text NOT NULL DEFAULT '';
ALTER TABLE jobs ADD COLUMN error_code text NOT NULL DEFAULT '';
ALTER TABLE jobs ADD COLUMN lease_token text;
ALTER TABLE jobs ADD COLUMN lease_until timestamptz;
ALTER TABLE jobs ADD COLUMN idempotency_key text;
ALTER TABLE jobs ADD COLUMN request_digest text;
ALTER TABLE jobs ADD COLUMN operation_id text;
ALTER TABLE jobs ADD COLUMN approval_id text;
ALTER TABLE jobs ADD COLUMN export_id text NOT NULL DEFAULT '';
ALTER TABLE jobs ADD CONSTRAINT job_tenant_id_unique UNIQUE(tenant_id,id);
ALTER TABLE jobs ADD CONSTRAINT job_delegation_tenant_fk FOREIGN KEY(tenant_id,delegation_id) REFERENCES delegations(tenant_id,id);
ALTER TABLE jobs ADD CONSTRAINT job_owner_tenant_fk FOREIGN KEY(tenant_id,owner_id) REFERENCES users(tenant_id,id);
CREATE UNIQUE INDEX job_idempotency ON jobs(tenant_id,owner_id,idempotency_key);
CREATE INDEX job_claim ON jobs(state,lease_until,created_at);
CREATE TABLE document_bodies (
 tenant_id text NOT NULL, resource_id text NOT NULL, content text NOT NULL,
 content_digest text NOT NULL, PRIMARY KEY(tenant_id,resource_id),
 FOREIGN KEY(tenant_id,resource_id) REFERENCES resources(tenant_id,id)
);
CREATE TABLE model_routes (
 tenant_id text NOT NULL, id text NOT NULL, approved_classifications text[] NOT NULL,
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,id) REFERENCES resources(tenant_id,id)
);
CREATE TABLE export_destinations (
 tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL,
 enabled boolean NOT NULL DEFAULT true, PRIMARY KEY(tenant_id,id)
);
ALTER TABLE approvals ADD COLUMN job_id text;
ALTER TABLE approvals ADD COLUMN destination_id text;
ALTER TABLE approvals ADD COLUMN approved_at timestamptz;
ALTER TABLE approvals ADD COLUMN approver_id text;
ALTER TABLE approvals ADD COLUMN rejected_at timestamptz;
ALTER TABLE approvals ADD COLUMN policy_digest text;
ALTER TABLE approvals ADD CONSTRAINT approval_job_tenant_fk FOREIGN KEY(tenant_id,job_id) REFERENCES jobs(tenant_id,id);
ALTER TABLE approvals ADD CONSTRAINT approval_approver_tenant_fk FOREIGN KEY(tenant_id,approver_id) REFERENCES users(tenant_id,id);
CREATE UNIQUE INDEX one_export_per_job ON approvals(tenant_id,job_id);
CREATE TABLE execution_operations (
 id text PRIMARY KEY, tenant_id text NOT NULL, job_id text NOT NULL,
 kind text NOT NULL CHECK(kind IN ('model','export')), request_digest text NOT NULL,
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','started','completed','unknown','denied')),
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(tenant_id,job_id) REFERENCES jobs(tenant_id,id)
);
