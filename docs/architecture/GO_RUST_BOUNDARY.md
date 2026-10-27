# Go control plane and Rust enforcement kernel

Go owns orchestration/integrations, Rust owns Nex.Guard, and gRPC connects them. TypeScript remains the workspace language; Rego defines policy and Terraform defines infrastructure.

## Authority and immutable operations

Runtime control requires Rust and has no direct-OPA fallback. The direct Go adapter remains only for isolated contract tests. `Evaluate` accepts resolved facts from the trusted identity/control adapter and returns a decision, never a reusable execution grant.

`PrepareExecution` resolves the current job, source, delegation, route and approval in Rust. It constructs the exact model/export payload and inserts a v2 manifest with a semantic payload digest, immutable source/action context and expiry. Go forwards this prepared content. It cannot insert execution operations, change their digests/results, mutate a manifest, rewrite protected job input, or supply model/export results directly through SQL. Rust runtime cannot update an existing manifest either.

`AuthorizeExecution` authenticates the corresponding receiver and compares its actual semantic payload digest against the kernel-owned manifest and freshly reconstructed payload/context. Rust checks current requester/delegation permissions, tenant and resource ownership, ACLs, document version/content digest, classification, model route, destination, policy, expiry and lease. Row locks protect these reads. Wall-clock freshness is checked again after policy/signing calls and before commit. Only a pending operation can start; a started operation cannot authorize another effect.

Export requires a completed model result reported through the authenticated model boundary. Its review manifest must bind the same source digest/version, question and template context. Human approval is separately recomputed and permanently consumed for one logical export operation. Changing Go's scheduler operation ID cannot reuse it.

`CompleteExecution` accepts the receiver's durable result, validates the applicable bounds/artifact binding, and owns protected model answer/provider/export provenance. Repeated identical completion is idempotent; altered results or the wrong service identity are rejected. A late completion records its original operation and sealed context even if scheduling has advanced. It does not resurrect a cancelled job or grant new execution authority.

Go remains trusted for authenticated human identity and initial job proposals. Runtime roles cannot modify identity permissions, classifications or source bodies. A separate development administrator performs migrations/fixtures. The alpha does not claim resistance to a compromised identity provider, host administrator or all trusted components together.

## Versioned payload and approval binding

The v2 execution digest is SHA-256 over `nex.execution.payload.v2\0` and unsigned big-endian uint64 byte-length-prefixed UTF-8 fields. Export fields are kind, operation ID, tenant, destination, exact content and approval request digest. Model fields are kind, operation ID, tenant, route, classification, exact prompt and decimal token limit. Go and Rust share independent expected vectors covering Unicode, NUL and ambiguous delimiter cases. Raw JSON or Protobuf serialization is not the signing format.

Human approval retains its distinct `nex.export.v1` domain and fields: approval ID, job ID, tenant, requester, delegation, action, document ID/version/content digest, answer digest, destination, policy digest and expiry seconds. Rust links this binding to the prepared export. The human preview renders the same protected answer/source content as the export.

Legacy operation/answer history is retained. Unsealed operations and results without the required source context are not silently upgraded into verified v2 operations. Start a new governed review for a legacy answer.

## Receipts and safe recovery

Broker capabilities bind audience, exact body and short expiry. A receiver reserves a logical operation durably before authorization/effects. A process lock distinguishes a concurrent in-progress request from a receipt left by a crashed process. New receipt states distinguish prepared, known not started, started and completed; interrupted or corrupt state remains unknown. Atomic file replacement and directory synchronization publish completion. Legacy completed receipts remain readable; pending reservations are never deleted to make a retry pass.

An authorization transport error may hide a committed Rust grant. Receivers therefore query authenticated `ExecutionState`; its row lock waits for an in-flight authorization to resolve. Only a confirmed pending state permits a known-not-started classification. A failed/ambiguous state query, a started operation, missing receipt storage, or an effect callback error remains unknown. Missing storage is not evidence that nothing happened.

A completed receipt can report its original result again without repeating the provider/export effect. Export receivers also verify actual stored artifact content against the sealed request before reporting completion. `/status` only inspects a durable receipt and reports it to Rust; it never executes an effect.

Owner/current-authority-checked recovery APIs accept no supplied result or state override. Reconciliation uses receiver `/status`; retry requeues the same still-pending operation only for a positively known pre-execution failure. A preparation failure before any receiver call may retry with the same ID when no operation was created. Started/unknown outcomes cannot use this path. Leases fence stale scheduling updates. The workspace explains blocked, retryable and uncertain outcomes.

## Signing and failure behavior

The explicit execution profile requires state, distinct service identities, policy configuration, evidence endpoint/key and pinned verification key. Evaluation-only mode cannot execute. Execution readiness checks the state schema and signer availability; actual append signatures and identities are verified before an execution grant commits. Missing configuration cannot select unsigned execution.

Protected authorization requires database intent and signed producer-bound evidence. The writer has separate control/kernel producer identities and exclusive signing-seed access. Signed authorization candidates describe attempts pending database commit; an orphan candidate can remain if the transaction later fails. Receiver receipts and signed outcome records establish completed results. An external API and a database transaction do not provide exactly-once effects.

A fenced operational failure status may be recorded when signing is unavailable so a rejected preparation does not loop forever as running. Its optional failure event is committed only if signing succeeds; this deny-only status is not unsigned evidence of authorization or execution.

Local signing is development Ed25519. Approved cryptographic modules, independent key/checkpoint custody, retention and external anchoring remain deployment gates. Both Go and Rust reject production plaintext gRPC; local authenticated HTTP/gRPC uses isolated development networks. Worker network probes and database role tests establish local boundaries, not live AWS IAM/VPC enforcement or compliance authorization.
