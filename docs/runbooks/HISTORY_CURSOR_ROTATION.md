# History cursor keys

The optional control-plane history cursor key permits replicas with the same
private key to validate each other's 15-minute continuations. Every continuation
still checks the current tenant, actor, job and authority. The production profile
remains closed; this is a separately testable precursor.

Provision `NEX_HISTORY_CURSOR_KEY_FILE` as a non-symlink regular file containing
exactly 32 independently generated random bytes, owned by the control service UID
with mode 0400 or 0600 and no special bits. Keep it separate from evidence,
session-encryption and service capability keys. No key bytes belong in Git,
logs or public evidence. If unset, the existing process-local random key is used:
cursors then fail across replicas and after restart.

For an overlap, configure `NEX_HISTORY_CURSOR_PREVIOUS_KEY_FILE` with a second,
distinct, independently generated key subject to the same private-file checks.
A previous file without a current file, an empty/malformed/unreadable file, an
all-zero key or duplicate current/previous keys causes startup failure. Keys are
loaded once; change them through a reviewed deployment, not in-place mutation.
New cursors are signed with the current key. Both current and previous keys
validate only correctly scoped, unexpired and authenticated cursors.

For a planned rotation:

1. Provision the new key securely. Roll every replica to current=old and
   previous=new; verify every replica has the prepared two-key configuration.
2. Roll every replica to current=new and previous=old. Verify the last old-key
   signer has stopped before starting the retention interval.
3. Wait at least 15 minutes after that last old-key signer stops, then remove
   the previous key from every replica. Test old/new continuations and authority
   checks during rollout and confirm old signatures are rejected after retirement.

If a key is compromised, remove it from all trusted key configurations
immediately and invalidate affected continuations. Do not retain it for the
normal overlap. Incomplete rollouts or differing key pairs can reject valid
continuations; clients must start a fresh history snapshot. This runbook does not
claim a deployed production rotation or verified customer key-custody solution.
