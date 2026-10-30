-- Encrypted workspace authentication state. Existing control/guard roles receive
-- no grants; deployment must explicitly provision a separate workspace role.
CREATE SCHEMA nex_workspace_auth;
REVOKE ALL ON SCHEMA nex_workspace_auth FROM PUBLIC;
CREATE TABLE nex_workspace_auth.workspace_session_state (
 kind text NOT NULL CHECK (kind IN ('login', 'session')),
 handle_hash text NOT NULL CHECK (handle_hash ~ '^[a-f0-9]{64}$'),
 hard_expires_ms bigint NOT NULL CHECK (hard_expires_ms > 0),
 idle_expires_ms bigint NOT NULL CHECK (idle_expires_ms > 0 AND idle_expires_ms <= hard_expires_ms),
 sealed bytea NOT NULL CHECK (octet_length(sealed) BETWEEN 28 AND 65536),
 PRIMARY KEY (kind, handle_hash)
);
CREATE INDEX workspace_session_expiry_idx ON nex_workspace_auth.workspace_session_state (kind, idle_expires_ms, hard_expires_ms);
REVOKE ALL ON nex_workspace_auth.workspace_session_state FROM PUBLIC;
