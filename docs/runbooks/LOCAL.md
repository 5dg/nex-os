# Local operation and recovery

Use the existing checkout. Cloud tasks are already isolated; do not create a worktree unless explicitly requested.

1. Activate the pinned Go/Rust tools and homes as shown in README.md. Run `make start` for unchanged prepared images or `make dev` after code changes. Docker must already be healthy; preserve its registry/proxy/trust configuration.
2. Startup reapplies checksum-tracked migrations and inserts missing synthetic fixtures without replacing existing records. Local identities are generated once and retained in ignored `.local` files; never print them or commit them.
3. The development administrator provisions restricted runtime database roles. Go cannot approve/consume approvals. `python3 scripts/check-local-roles.py` verifies this with an actual denied write, without reading credentials.
4. Run `make verify-local` for functional/negative checks and `python3 scripts/verify-restore.py` for the disposable restore check. A process or open port alone is insufficient.
5. `make logs` shows this Compose project's logs. Internal service names, including Guard and evidence, must be in the appropriate `NO_PROXY` values. Never bypass the platform proxy for external destinations or disable TLS verification.
6. `make down` preserves the database volume. Never remove unknown Docker caches, images, volumes, or local identities. VFS uses substantial space: inspect usage before repeated builds and remove only artifacts confirmed to belong to the task when necessary.
7. Worker leases expire after 90 seconds; stale lease tokens cannot update a reclaimed job. Completed executor receipts are reusable only for the identical logical request. Pending receipts mean outcome unknown; reconcile them before any manual retry. Do not delete a receipt to force a passing run.
8. Approval expiry, changed versions/answers/destinations/policy, or revoked requester/approver authority prevent execution. Rejected/expired requests require a new deliberate workflow; do not edit approval records to bypass them.
9. `bin/evidence verify .local/evidence .local/evidence-public` validates the journal. An optional fourth argument after the public-key path supplies a saved checkpoint JSON file. Store trusted public-key/checkpoint anchors outside the host for rollback detection.
10. `scripts/verify-restore.py` pauses only this project's control/worker, restores into a newly created disposable database, verifies row fingerprints and a copied journal, drops only that database and resumes services. It is a synthetic development recovery test, not production backup assurance.

Snapshots may retain files/tools/images/volumes, but processes and connections must restart. Environment settings contain reusable install/start instructions; saving them does not execute, deploy or publish anything.
