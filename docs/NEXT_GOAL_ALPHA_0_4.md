# Next goal: Alpha 0.4 verified governance evidence and reproducible synthetic release candidate

Current execution ordering and ownership: [28 October completion goal](FINISH_GOAL_2026_10_28.md).
This earlier plan is retained as history; several implementation tickets below are now complete.

Code review: 2026-10-27, starting from published `main` commit `5b7b34e5a540d21b47b5578123ca7d65953123de`. This is the next development plan; its proposed checks have not been executed by this review. Preserve [Alpha 0.3 evidence](ALPHA_0_3.md) and earlier history.

## Copyable goal

> Turn the working synthetic review → independent approval → exact export workflow into a reproducibly built, operationally tested release candidate. Close the identified Rust evidence-content verification gap without changing historical proof formats; prove bounded shutdown and current-authority behavior under faults; and bind one captured source revision to the exact images, test results, inventories and release decision. Keep one agent publishing reviewed checkpoints to `main` and another removing confirmed dead code behind completed work. Preserve Go, Rust, gRPC, v2/v3 interpretation, protected results and conservative unknown outcomes.
>
> Keep live GovCloud/Bedrock, customer identity, approved production cryptography and CUI use deferred. Report implementation, qualification and release eligibility separately. Findings, unavailable feeds and unverified CI remain explicit blockers; passing functional tests does not confer FedRAMP/NIST/CMMC authorization.

## Why this is the next step

The authenticated slice already works. Alpha 0.3 records real service authorization, token-purpose and tenant denials, thirteen authority mutations, receiver proofs, PKI rotation and isolated restore. GitHub publication now succeeds. Retain historical publication failures with a dated resolution; successful push alone does not establish a hosted CI result.

| Current code/evidence | Concrete next work |
|---|---|
| `services/guard-kernel/src/evidence.rs:172` checks signature, event ID and producer; Go `packages/evidence/journal.go:69` also checks exact event content | Reproduce and close the verification asymmetry. No live authority bypass has been demonstrated. |
| `services/guard-kernel/src/main.rs:7` waits for Ctrl-C; lifecycle scripts use short container-stop bounds | Define and test real SIGTERM admission/drain behavior, with consistent process and orchestration deadlines. |
| `services/control/api/profile.go` authenticates inbound callers at entry; handlers await dependencies | Test original caller expiry and committed permission/delegation revocation before the next grant. Fix demonstrated failures, preserving accepted-job semantics. |
| `scripts/qualification-build.sh` has a pinned container mode, but `scripts/qualification.sh` unconditionally uses host `bin/evidence` | Make a fresh source build self-contained; reject stale host artifacts. The pinned Rust builder and combined verifier remain unproven. |
| Published source differs from the precisely disclosed tested application snapshot | Build and test one captured revision. Connect source, builder, images and retained evidence automatically. |
| Read polling creates signed `document.read` events; journal append/readiness verifies history | Measure bounded polling, journal growth, concurrency and slow-dependency behavior before optimizing. Preserve meaningful read auditing. |
| Six-image scans retain unresolved findings; Go advisory access failed | Continue evidence-backed remediation and obtain complete scans. No severity reductions, automatic exclusions or invented waivers. |

## Scope and stable contracts

Keep the existing workflow, one question catalogue, fixed synthetic route and one export destination. Qualification must remain unable to construct a live provider. Keep database roles minimal, exact input/provider/result binding intact, and missing trust/signing dependencies closed.

For evidence parity, preserve the existing v1 event/head encoding and signature domain: Go field order, normalized detail/numbers, omitted empty fields and JSON escaping matter. Add shared vectors before implementing Rust parity; do not silently replace serialization or rewrite old proofs. A matching proof does not establish independently durable custody against a compromised signer; external anchoring remains a future requirement.

Define shutdown and revocation linearization first. Stop new admission on SIGTERM; previously admitted work may finish within the agreed drain or become conservatively unknown. Align Rust/Go deadlines with Compose stop grace periods. A revocation committed before a new authoritative grant must deny that grant. Logout does not cancel already accepted delegated jobs, and rollback does not undo an external effect.

Exclude new connectors, arbitrary shell execution, workflow frameworks, distributed sessions/custody, Kubernetes, vector search, a UI redesign and live infrastructure deployment. Terraform is still foundation scaffolding. Customer MFA, cryptographic-module approval, KMS/storage/custody, live IAM/model/network tests and organizational assessments require a later approved boundary.

## Development path

### Wave 0 — establish contracts and the first failing case

Record the published baseline and actual hosted CI status; if API access is unavailable, record **unknown/access blocked**, not “unrun.” Freeze proof-canonicalization, shutdown/grant ordering and candidate-evidence contracts. Declare measurable shutdown/admission/load budgets and the reproducibility target before tests: compare binary, rootfs and OCI-byte identity separately, allowing only explicitly documented metadata nondeterminism. Budget storage, build parallelism and short-lived fixture credentials before expensive builds.

D reproduces a correctly signed proof with the same event ID/producer but different content. B implements exact-content verification; D proves rejection, transaction rollback and no authorization grant. Add Unicode, HTML escaping, numeric and empty-job vectors and valid/historical positive controls. Preserve existing proof bytes and signatures.

### Wave 1 — fix correctness and packaging in parallel

A/B implement only fixes supported by the evidence and shutdown tests. D adds held-dependency caller-expiry and revocation cases with unexpired sessions/tokens, plus bounded concurrency/cancellation and actual SIGTERM/restart coverage. Require zero new provider/artifact effects after a denied new grant; preserve started/unknown receipts.

C makes the pinned source-build path include every required binary, proves the Rust builder/ABI, and prevents live-tree or stale-host-input substitution. Source identity must work in clean archives/CI without assuming `.git` or old `bin/evidence` exists. C/D triage supported image/dependency fixes against actual inventories and behavior. A/B/D measure polling/journal limits; optimize only a reproduced capacity problem without weakening verification or audit semantics. A/D add one real DOM-browser workflow smoke test to complement the existing HTTP protocol harness, retaining trusted test CA validation.

E publishes coherent reviewed batches throughout. F follows those batches with narrowly justified cleanup; neither waits until the end.

### Wave 2 — qualify the exact candidate

Finish F’s applicable cleanup, capture the final coherent revision, release source editors, and build from that snapshot. A later code change requires a new candidate and rerunning affected gates; never relabel later cleanup as already tested. Run the entire ordered verifier from fresh isolated state: browser/API, PostgreSQL trust/roles, kernel mutations, receiver proofs, rotation and quiescent restore. Keep shared mutations and lifecycle transitions serial. Preserve previous volumes, signing identities, receipts and backups; the current one-shot restore refusal must not be bypassed by deleting retained state.

Produce a release manifest connecting source/input hashes, pinned builders/compiler/target/ABI, binary and immutable image identities, test commands/results, source and OS SBOMs, scanner/database versions and raw findings. Run a second clean build and measure reproducibility; unexplained payload/artifact differences remain a failed gate and cannot be normalized away. Local image tags and unsigned host records are not provenance attestations.

### Wave 3 — establish the release decision

Run actual hosted CI when access permits. Retain the candidate, build records and complete verification evidence durably with the same source/image identities; temporary logs alone are insufficient. Keep incomplete, failed and blocked checks distinct. Publish an explicit qualified-or-blocked decision with each remaining finding, owner and required external action. Do not manufacture a green release while vendor findings or required advisory checks remain unresolved.

## Six subagents and the lead auditor

| Agent | Exclusive normal ownership | Responsibility |
|---|---|---|
| A — application and shared contracts | `services/control/**` including `migrations/migrate.go`, excluding migration SQL and integration tests; `packages/contracts/**`, `packages/trust/**`, `packages/broker/**`, `apps/workspace/**`, Go module locks | Caller/current-authority behavior, bounded polling/operator fixes and shared interfaces. Sole generated-contract writer; coordinates proof vectors with B. |
| B — governance and effects | `services/guard-kernel/**`, `policies/**`, model/export/evidence/worker services, `packages/evidence/**`, new SQL migrations | Exact proof verification, kernel/service shutdown and effect/custody invariants. Existing migrations stay immutable; source owners keep component tests. |
| C — builds and supply chain | `deploy/**` except SQL; scripts/tooling, Makefile, `.github/**`, operational/compliance/evidence documentation | Self-contained pinned builds, ABI/image fixes, resource budgets, full inventories/scans and accurate release records. Requests shared runtime execution through E. |
| D — independent qualification | `tests/**`, service `*_integration_test.go`, independent fixtures/results | Red/green proof, authority, fault/load/DOM and release-manifest verification. Never substitutes fabricated completion SQL for real Rust provenance. |
| E — dedicated publisher/integration scheduler | Git index/commits/pushes and generated publication/artifact reports | Sole `main` publisher and shared Docker/Compose/DB/PKI/restore/build coordinator. Stages approved paths, checks secrets/artifacts, obtains lead audit, pushes normally and verifies remote `main` equals the intended SHA. Never force-pushes; no competing feature ownership. |
| F — trailing dead-code cleanup | Cleanup ledger; temporary exclusive file handoffs for deletions | Reviews completed batches, proves reachability/consumer status, removes confirmed obsolete code and supplies regression evidence. Does not own Git publication or shared runtime mutations. |
| Lead — auditor | Decisions and review, not feature implementation | Audits contracts, evidence and staged changes; resolves ownership; accepts or rejects each gate. |

F works one published implementation batch behind: record the producing revision and candidate → check code/generated/API/CLI/configuration/saved-startup consumers → obtain file-owner handoff → make a small deletion batch → run relevant checks → obtain D/lead review → hand files back → E publishes the audited cleanup commit. Preserve active development paths, deferred provider seams, v2/v3 codecs, migrations, proof history and uncertain receipts. Reference count alone is insufficient: generated trait methods, route exports, interface implementations and SQL lock sentinels can look unused. No deletion quota; this review confirmed no additional executable deletion safe enough to authorize without further consumer checks.

Freeze editors only long enough to capture source. E runs builds/tests against the immutable snapshot while unrelated editing and cleanup continue. E never stages another agent’s unfinished work or validates an unapproved live tree as the candidate. No two agents edit the same file concurrently. Every handoff includes paths, contract version, checks, limitations and readiness. E publishes each coherent milestone and cleanup batch without waiting for a final giant commit.

## Completion

Implementation is complete when proof parity and bounded fault behavior pass, the fresh self-contained pinned build and full verifier execute, and candidate evidence is traceable and retained. Release eligibility additionally requires complete scans, required vulnerability disposition, reproducibility and a verified CI/provenance result. Regulated deployment remains a separate gate. The first executable ticket is the signed wrong-content proof regression, paired with C's fresh-build dependency-closure investigation.
