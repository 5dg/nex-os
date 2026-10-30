# Workspace session encryption key rotation

The PostgreSQL session backend supports rotation during synthetic qualification.
This does not enable the production profile or establish production key custody.
Each replica reads its keys on startup; a change requires restarting the replica.
Keep both secrets out of logs and version control. Supply independent randomly
generated nonzero 32-byte raw keys in regular files owned by the process user,
with mode 0400 or 0600 and no symlinks. `NEX_SESSION_ENCRYPTION_KEY_FILE` is
required and encrypts new or touched records. The optional
`NEX_SESSION_PREVIOUS_ENCRYPTION_KEY_FILE` permits reading records encrypted
with a distinct second key. Invalid, identical, or unavailable keys fail
startup. Existing single-key records keep their original format and AAD.

For a planned rotation, coordinate the whole fleet:

1. Generate and securely distribute the new key. Roll every replica with the
   old key as current and the new key as previous; verify every replica has
   completed this phase before continuing.
2. Roll every replica with the new key as current and the old key as previous.
   Both phases can read records from either signer, and touched records are
   re-encrypted under the current key.
3. After the last old-key writer has stopped, wait at least the maximum session
   hard lifetime of 15 minutes before removing the old key from all replicas.
   Database records can have shorter limits; idle activity cannot extend the
   hard deadline. Existing login transactions expire within five minutes.

If a key is compromised, remove it immediately on every replica and invalidate
affected sessions and login transactions; do not wait for overlap. Records
encrypted with a removed key cannot be read and may produce authentication
failures until invalidated or expired. Validate rotation with the actual fleet,
secret distribution, identity provider and deployment before production use.
