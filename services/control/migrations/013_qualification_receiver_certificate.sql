-- Qualification-only binding to the leaf certificate that received the
-- pending-to-started grant. Historical rows remain NULL and are never backfilled.
-- This is not a unique instance identity or a fence across recovery/failover.
ALTER TABLE execution_operations ADD COLUMN qualification_receiver_cert_sha256 text
    CHECK (qualification_receiver_cert_sha256 IS NULL OR qualification_receiver_cert_sha256 ~ '^[0-9a-f]{64}$');
