# Next goal: Nex.os Alpha 0.2 execution integrity

Historical Alpha 0.2 milestone proposal. The current goal is [Alpha 0.5 synthetic release qualification](NEXT_GOAL_ALPHA_0_5.md), which first finishes the remaining Alpha 0.4 work. See [BUILD_PLAN.md](BUILD_PLAN.md) for navigation and [ALPHA_0_3.md](ALPHA_0_3.md) for earlier executed evidence.

## Goal

Make the Rust governance kernel the authoritative owner of exactly what may execute, and make interrupted operations recoverable without weakening approvals or repeating uncertain effects. Preserve the working Go/Rust/gRPC review–approval–export workflow and its signed evidence.

Completion means that changing Go's proposed operation, registered digest, executor payload, or scheduler state cannot substitute different content, tenant, destination, model route, or limits for what Rust authorized. Required signer configuration must fail closed. Known pre-execution failures must remain distinguishable from genuinely unknown outcomes.

This is a local, synthetic-data hardening milestone. GovCloud, real Bedrock inference, customer identity, production cryptography and compliance assessment remain deferred. Do not restart the application or change languages/frameworks.

## What the code review established

The current application already provides a useful end-to-end demonstration, separate service/database roles, live Rust authorization, operation-bound approvals, signed producer-specific evidence, lease fencing and local restore checks. The recorded full baseline has 71 integration scenarios, seven Rego tests and four Terraform mock tests. Those results validate the tested paths, not every possible boundary.

The next work should address these concrete gaps:

1. **Execution payload agreement is not independent approval binding.** `services/control/api/workflow_execution.go:92` constructs and registers an execution digest in Go. `services/control/devseed/roles.go:40` permits Go to insert that digest. `services/guard-kernel/src/execution.rs:295` compares the receiver's digest with the registered digest and separately validates approval against job data. It does not reconstruct or verify that the actual receiver payload is the approved job content. The existing positive Rust fixture even uses a random digest (`services/control/guard/execution_integration_test.go:116`). The focused positive test passes with it. This confirms a missing invariant, not an anonymous public-API exploit: the current Go producer normally constructs the expected payload and is a trusted component.
2. **Mandatory signing can be omitted in configuration.** Rust startup conditionally configures evidence in `services/guard-kernel/src/main.rs:22`; the audit path conditionally signs at `services/guard-kernel/src/execution.rs:180`. A configured writer outage is tested, but execution-enabled startup without a writer is not rejected. Required configuration must have the same fail-closed semantics as a failed dependency.
3. **Receipt state is too coarse for recovery.** `packages/broker/broker.go:156` creates a pending receipt before the callback performs authorization. A definitive denial can leave the same pending state as a possible external effect. The completion file is written directly, so interrupted completion writes also need explicit recovery semantics. `services/control/api/workflow_execution.go:140` collapses executor errors into unavailable-or-unknown.
4. **Protected context remains broader than scheduler ownership.** Go has general job UPDATE privileges. The next design should distinguish orchestration fields from immutable action context and kernel-owned operation/result provenance.
5. **Release evidence still depends on this prepared instance.** Hosted CI has not run. A fresh checkout with no retained binaries, identities, images or volumes must reproduce the checks before declaring this milestone complete.

These findings support tightening authority and recovery before adding more connectors or interface features.

## Stable decisions and scope

- Go owns user-facing APIs, the trusted identity adapter, scheduling and integrations.
- Rust owns protected operation preparation/authorization, approval binding and consumption, and authoritative operation provenance.
- TypeScript/Next.js remains the workspace; Rego/OPA remains the policy language; PostgreSQL remains the state/queue engine.
- Keep the existing services and gRPC boundary. Add no message bus, workflow framework, Kubernetes deployment, new language, marketplace or arbitrary executable tools.
- Keep one document-review template and one controlled export destination until the invariants below pass.
- Preserve existing data and applied migrations. Introduce new migrations and versioned contracts; never edit history or delete pending receipts to manufacture success.
- The Go identity adapter remains trusted for authenticated human identity. This milestone does not claim resistance to a compromised IdP, host administrator or all trusted components together.

## Implementation sequence

### 1. Turn the missing invariants into failing regression tests

Capture a baseline first. Add tests that prepare a valid approved job but propose a different export body/tenant/destination or model prompt/route/limits while registering a matching Go-side digest. Assert denial before any provider/export callback or approval consumption. Test omitted signer configuration separately from signer outage. Add fault injection before authorization, after authorization, before the effect, after possible effect, and during result persistence.

Use disposable schemas and the actual runtime permission model. Preserve the existing valid workflow and test source/producer proof verification.

**Exit gate:** The new tests expose the gaps, identify which boundary must reject each request, and contain no production fixes hidden in fixtures. Successful operation tests use digests derived from actual payloads rather than unrelated random values.

### 2. Introduce an immutable kernel-owned operation manifest

Define a versioned `OperationManifest` contract and preparation RPC. Rust resolves trusted records and validates a proposed action, then creates an immutable manifest containing the applicable tenant/requester/delegation, job/action, document/version/content references, rendered payload digest, destination or model route, classification, limits, policy digest and expiry. Include model template/version and user-question handling in the model contract; do not authorize an arbitrary opaque prompt digest.

Use a specified cross-language canonical encoding with Go/Rust conformance vectors. Keep approval and execution digests distinct and explicitly linked. The human preview must be generated from the same sealed content/version used by the manifest.

Store manifests and protected result provenance in kernel-owned records. Go can submit proposals and update allowed scheduling fields; it cannot replace authoritative manifests, approvals, actor context or result provenance through direct SQL. An executor reports outcomes through its authenticated boundary.

**Exit gate:** Actual Go-role SQL attempts to insert/alter authoritative manifests or rewrite protected context fail. Rust reconstructs the expected binding independently. Existing v1 operations are not silently upgraded or retrospectively declared verified; preserve their history and require a fresh applicable approval for changed semantics.

### 3. Bind executor requests to the sealed manifest

Executors submit the operation identity and actual payload binding to Rust. Rust checks them against its immutable manifest and current authority. Where practical, executors fetch canonical content/references from the kernel-owned record instead of accepting free-form replacements from Go.

Recheck delegation, source ACLs/versions, classification, route, destination, policy and expiry at the execution boundary. Keep exact approval consumption bound to one logical operation. A changed manifest requires a new authorized operation and approval when applicable.

Do not use raw Protobuf bytes as an unspecified signing format. Retain explicit deadlines and scoped service identities. Do not enable automatic retries for potentially side-effectful execution.

**Exit gate:** Every payload-substitution regression fails before effects, including a matching attacker-selected Go digest. Valid exports deliver precisely the previewed content. Forged, expired, cross-service, cross-tenant and replayed requests remain rejected.

### 4. Make executable profiles fail closed at startup

Define explicit evaluation-only and full-execution modes. Evaluation-only mode must never authorize an effect. Full execution requires state-store configuration, all relevant service identities, the expected policy source, signer endpoint and pinned public verification key.

Missing, malformed or incompatible configuration must reject startup or keep execution unavailable; it must not select an unsigned mode. Preserve the existing production plaintext rejection. Keep local development crypto visibly separate from future approved cryptographic deployments.

**Exit gate:** Table-driven startup tests cover omitted/invalid dependencies and keys. Full execution without a signer is impossible. Readiness and authorization failures agree about required dependencies without exposing secret values.

### 5. Implement typed outcomes and safe reconciliation

Replace generic unavailable-or-unknown handling with a documented state machine. At minimum distinguish prepared, definitively denied/not started, started/in flight, completed, known failure and unknown outcome. Classify a failure as known only when the implementation has evidence that no effect occurred.

Publish durable completion atomically. Bind receipts to manifest identity and digest. Distinguish a concurrent in-progress attempt from a crashed or corrupt record. Add a narrowly authorized reconciliation/status path that checks executor evidence; it must not be an arbitrary 'mark complete' or 'retry anyway' endpoint.

Safe retries reuse the same logical operation and follow explicit semantics. Unknown external outcomes require evidence or operator review before any new effect. Never promise exactly-once delivery from a database transaction plus an external API.

**Exit gate:** Restart/fault tests show one effect or an explicit unresolved outcome, never a hidden duplicate. A pre-execution denial does not poison the operation as if an effect might have happened. The workspace explains blocked/unknown states and available safe next actions.

### 6. Produce reproducible release evidence

Run the full suite from a fresh checkout with fresh local state and the configured tool root, not only the retained machine. Exercise minimal runtime DB roles in integration tests. Add contract regeneration/conformance checks so Go/Rust payload semantics cannot drift silently.

Keep the existing workflow, isolation, signing, role and restore checks. Add a release evidence index linking each invariant to its test and result. Run dependency/image vulnerability checks and produce a software inventory/SBOM, documenting failures instead of masking them. Hosted execution remains unverified until the workflow actually runs; prepare all local checks without requiring an AWS account.

**Exit gate:** One documented verification command passes locally and in a fresh CI run, with zero unintentional integration skips. A reviewer can trace an approved manifest through Rust authorization, executor receipt, result and producer-bound evidence.

## Definition of done

- Rust independently binds the exact bytes/parameters that may execute to an immutable manifest and applicable approval.
- Go scheduling cannot overwrite protected action context or operation provenance.
- Required state/policy/signing configuration is enforced before effects.
- Known rejection, safe retry, in-flight work and unknown outcome have distinct behavior and operator-visible status.
- Fault, concurrency, revocation, payload-substitution, role, proof and restore tests pass without weakening assertions or resetting data.
- The synthetic review–approval–export demonstration still works through the workspace.
- Local/fresh-CI results, unrun cloud checks and remaining assessment gates are reported separately.

## First implementation task

Implement step 1 and agree the v2 manifest/receipt contract before changing the execution path. Then complete the export path through Rust-owned preparation, receiver validation and signed outcome evidence. Extend the same invariant to model requests next. Finish each vertical slice before expanding the service catalog.

The following goal can address real browser identity, authenticated transport and cloud storage/deployment once this integrity milestone is stable and the user supplies the deferred environment requirements.
