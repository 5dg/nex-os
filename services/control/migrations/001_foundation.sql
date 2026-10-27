CREATE TABLE tenants (id text PRIMARY KEY, name text NOT NULL);
CREATE TABLE users (
  id text PRIMARY KEY, tenant_id text NOT NULL REFERENCES tenants(id),
  issuer text NOT NULL, subject text NOT NULL, permissions text[] NOT NULL DEFAULT '{}',
  UNIQUE (issuer, subject), UNIQUE (tenant_id, id)
);
CREATE TABLE delegations (
  id text PRIMARY KEY, tenant_id text NOT NULL, user_id text NOT NULL,
  permissions text[] NOT NULL DEFAULT '{}', expires_at timestamptz NOT NULL,
  revoked_at timestamptz, FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id)
);
CREATE TABLE resources (
  id text NOT NULL, tenant_id text NOT NULL REFERENCES tenants(id),
  kind text NOT NULL CHECK (kind IN ('document','model')),
  classification text NOT NULL CHECK (classification IN ('public','internal','confidential','restricted')),
  version text NOT NULL, reader_ids text[] NOT NULL DEFAULT '{}',
  PRIMARY KEY (tenant_id, id)
);
CREATE TABLE jobs (
  id text PRIMARY KEY, tenant_id text NOT NULL REFERENCES tenants(id),
  delegation_id text NOT NULL REFERENCES delegations(id),
  state text NOT NULL CHECK (state IN ('created','queued','running','approval_required','completed','failed','cancelled','expired')),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE approvals (
  id text PRIMARY KEY, tenant_id text NOT NULL REFERENCES tenants(id),
  request_digest text NOT NULL, expires_at timestamptz NOT NULL, consumed_at timestamptz
);
CREATE TABLE audit_events (
  id text PRIMARY KEY, tenant_id text NOT NULL REFERENCES tenants(id),
  actor_id text NOT NULL, delegation_id text NOT NULL, resource_id text NOT NULL,
  action text NOT NULL, decision jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_tenant_created ON audit_events(tenant_id, created_at);
