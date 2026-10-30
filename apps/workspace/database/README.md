# Workspace session database

The optional PostgreSQL session store is an experimental synthetic-profile
exercise. The production workspace profile remains closed. It stores encrypted
login transactions and sessions shared across replicas; it does not provide a
production identity integration or deploy infrastructure.

An administrator applies `001_sessions.sql` in an isolated database. The
migration creates the dedicated `nex_workspace_auth` schema and table, with no
PUBLIC access. Provision a separate login role outside this migration and grant
only USAGE on that schema and SELECT, INSERT, UPDATE and DELETE on that table,
without grant options. The role must not own the schema or table, be a member of
other roles, have elevated PostgreSQL attributes, create objects in application
schemas or access other application tables/functions. Revoke inherited PUBLIC
CREATE on the database's public schema in the approved deployment boundary.
The store checks these requirements on startup. Coordinate database-wide ACL
changes with the owner; they can affect other applications.

For the optional synthetic profile, configure:

- `NEX_SESSION_BACKEND=postgres`.
- `NEX_SESSION_DB_URL_FILE`: private owner-readable 0400/0600 regular file
  containing a PostgreSQL URI with credentials and exactly `sslmode=verify-full`.
- `NEX_SESSION_DB_HOST`: exact expected database DNS hostname in that URI.
- `NEX_SESSION_DB_CA_FILE`: the public CA bundle used to validate that host.
- `NEX_SESSION_ENCRYPTION_KEY_FILE`: separate private owner-readable 0400/0600
  regular file containing 32 independently generated random bytes. All replicas
  must receive the same key. Do not derive it from public inputs or reuse service,
  evidence or cursor keys.

Files containing credentials or encryption keys must be owned by the workspace
service UID, with no symlinks, group/other access, executable or special bits.
Connections use certificate verification, a pinned server hostname, a restricted
`pg_catalog` search path, and bounded pool/query timeouts. Missing or invalid
configuration and insufficient database privileges fail closed.

Each browser handle is random and only its SHA-256 hash is stored. Login state,
PKCE verifier, actor, access token and CSRF token are authenticated and encrypted
with AES-256-GCM. Associated data binds the record type, hashed handle and both
expiry limits. The database clock controls expiry. Login transactions are deleted
atomically before state validation and token exchange; touching and logging out
serialize through database row locks.

Changing the encryption key makes existing records unreadable and returns an
unavailable error while they remain live. Coordinate a key change across every
replica with an explicitly approved session invalidation procedure. Never delete
existing session records or rotate a live key without the deployment owner's
approval. Credential rotation also requires coordinated restart because pool
configuration is loaded at startup. Production rotation and recovery remain to be
qualified against the approved deployment.
