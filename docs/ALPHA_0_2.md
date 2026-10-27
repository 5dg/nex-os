# Alpha 0.2: execution integrity and safe recovery

## Result

Rust now prepares the operation, independently validates the exact receiver payload, and owns the protected result. Go schedules the operation and forwards sealed content. It fences completion by lease, operation and phase, compares the HTTP acknowledgement with Rust-protected results using SELECT-only operation access, and uses protected current metadata for outcome evidence. The existing document-review, independent-approval and controlled-export workflow remains the development path.

The missing invariant was reproduced before the fix: a producer-selected digest, registered by Go, could authorize bytes unrelated to the approved export. The regression now fails closed even if the stored Go-side digest is changed to match substituted content. Separate model/export cases cover tenant, route, prompt, destination, classification and limits.

## Reviewable implementation

| Responsibility | Implementation |
|---|---|
| Rust-owned preparation and immutable context | `services/guard-kernel/src/execution.rs`; additive migrations `006_execution_manifests.sql` and `007_manifest_context.sql` |
| Semantic cross-language payload binding | `packages/contracts/execution.go`, `execution-vectors.json`, Rust vector test and `scripts/check-contracts.sh` |
| Versioned service contract | `packages/contracts/proto/nex/guard/v1/guard.proto`: preparation, execution, authenticated state observation and protected completion |
| Restricted orchestration role | `services/control/devseed/roles.go`; installed-role negative SQL checks in `scripts/check-local-roles.py` |
| Receiver integrity and durable outcomes | `services/model/server.go`, `services/tool-executor/server.go`, `packages/broker/broker.go` |
| Fenced preparation failures and recovery | `services/control/api/workflow_execution.go`, `workflow_recovery.go`, owner-scoped HTTP tests and `scripts/recovery-smoke.py` |
| Workspace recovery actions | `apps/workspace/app/workflow/page.tsx` and its development BFF |
| Configuration and signing prerequisites | Rust explicit execution/evaluation profiles; independent startup-negative baseline tests |
| Restore and release evidence | `scripts/verify-restore.py`, `scripts/receipt-restore-check`, release inventory/audit scripts and hosted CI configuration |

A failed authorization RPC is not enough to prove execution never started. The receiver's authenticated state query waits for the operation row lock; only a still-pending exact operation can become known not started. Unknown state, missing storage, corrupt receipts and effect callback failures remain unknown. Recovery never provides a 'mark complete' override or an unconditional retry.

Signed authorization candidates can survive a later database rollback and are labeled as pending commit. Completed results have separate receiver receipts and producer-bound outcome evidence. A late result uses its original immutable operation/approval context. No exactly-once external delivery claim is made.

## Compatibility and operating limits

Existing rows, migrations, receipts and journal history are preserved. Legacy/unsealed operations are not silently promoted into v2 authority. A legacy answer without verified source context requires a new governed review. A pending receipt is never deleted to manufacture a retry.

This is a synthetic-data local milestone. The identity adapter, kernel, controlled receivers, database, signer and administrator are trusted components. No real CUI, production sign-in, approved production transport/crypto or live GovCloud/Bedrock operation is introduced.

The final local checks cover 139 integration leaf scenarios, crash/restart and wire-bound regressions, seven policy tests, actual runtime role/network denials, real UI/service/recovery flows and a controlled DB/journal/receipt restore. Fresh-source scoped reproduction also passed. The release gate remains blocked by native Go feed access, unfixed runtime-image OS findings and unrun hosted/production gates; runtime package-manager findings and available pinned Debian fixes were remediated.

See [validation evidence](VALIDATION.md) for actual checks and remaining release blockers, [the boundary specification](architecture/GO_RUST_BOUNDARY.md) for the contracts and [the original goal](NEXT_GOAL.md) for the accepted development sequence. Vulnerability findings and unrun hosted/cloud/assessment checks remain explicit gates rather than implied passes.
