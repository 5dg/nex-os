-- PostgreSQL row locks require UPDATE on at least one column. Deployments may
-- grant a Guard role UPDATE on this inert column only; this migration grants
-- nothing and does not permit changing audit content.
ALTER TABLE audit_events ADD COLUMN candidate_lock_version bigint NOT NULL DEFAULT 0;
