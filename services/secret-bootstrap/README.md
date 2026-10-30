# Task-private secret-file bootstrap

This short-lived Linux process converts already-injected secret environment
values into files on a fresh task-private volume. It performs no AWS API calls,
does not start the application, and does not authorize a production deployment.
The ECS execution identity must be scoped to the exact approved secret ARNs and
keys; the application must depend on successful bootstrap completion and mount
the same volume read-only. The root image contains only the static executable.

Set `NEX_SECRET_LAYOUT` to a JSON object with a non-root numeric `uid` and `gid`
and a nonempty `files` array. Each entry has a single-component `name`, an
`env` named `NEX_SECRET_VALUE_...`, and an optional Boolean `base64` flag.
The optional Boolean `tmp` requests ownership of a separate fresh
`/run/nex-tmp` task volume before secret delivery; the application can mount
that volume at `/tmp` while retaining a read-only root filesystem.
Supply the corresponding values using the approved ECS secret mechanism; the
layout contains names and ownership only, never secret values. Base64 mode is
for binary data stored as a base64-encoded Secrets Manager string. Errors do
not include values, names or the supplied layout.

The process requires root with exactly `CAP_CHOWN` in its effective and
permitted capability sets, no inheritable capabilities, a fresh root-owned
`/run/nex-secrets` mount and no additional capabilities. It creates exclusive
0600 files using a no-follow directory handle, syncs them, then hands a 0700
directory to the specified UID/GID. It rejects duplicate JSON keys, mismatched
field casing, duplicate names/environment mappings, missing/oversized values and
nonempty/symlinked volumes. The no-follow check protects the mount's final path
component; `/run` and its ancestors must come from the trusted scratch image.
Use distinct fresh task-private volumes, give the bootstrap the only writable
secret mount, and make the application mount read-only. Rollback on a failed
write is best effort; a failed init must prevent application startup and both
volumes must be discarded with the task, including after a handoff/sync failure.

The process sets no-new-privileges on its calling thread and disables dumps;
neither measure substitutes for task isolation or control-plane access policy.
Injected environment values may be visible to authorized task/container
inspection mechanisms. Restrict ECS Exec and task inspection, scope execution
role permissions to exact secret and KMS resources, and review Fargate volume
ownership, capability-drop behavior and logging in the target platform before
use. Rotation requires tested task replacement and trust/credential overlap.

The Dockerfile pins the Go builder and frontend. Supply the required trusted CA
bundle as the `proxy_ca` build secret; retain TLS verification. A reviewed
canonical build, image digest and isolated capability/ownership probe are still
required before this helper can be selected in a production task definition.
