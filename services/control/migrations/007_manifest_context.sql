-- Retain earlier manifest history without retrospectively claiming its context
-- was sealed. Kernels reject empty legacy context rather than auto-upgrading it.
ALTER TABLE execution_manifests ADD COLUMN manifest_context jsonb NOT NULL DEFAULT '{}';
