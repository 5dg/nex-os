ALTER TABLE users ADD COLUMN lock_version bigint NOT NULL DEFAULT 0;
ALTER TABLE delegations ADD COLUMN lock_version bigint NOT NULL DEFAULT 0;
ALTER TABLE resources ADD COLUMN lock_version bigint NOT NULL DEFAULT 0;
ALTER TABLE document_bodies ADD COLUMN lock_version bigint NOT NULL DEFAULT 0;
ALTER TABLE model_routes ADD COLUMN lock_version bigint NOT NULL DEFAULT 0;
ALTER TABLE export_destinations ADD COLUMN lock_version bigint NOT NULL DEFAULT 0;
ALTER TABLE approvals ADD COLUMN lock_version bigint NOT NULL DEFAULT 0;
