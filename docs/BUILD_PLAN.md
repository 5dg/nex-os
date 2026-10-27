# Nex.os development goal and implementation path

## Current goal: Alpha 0.4 governance evidence and reproducible release candidate

Turn the working synthetic document-review → independent approval → exact export slice into an exact-source, operationally tested release candidate. Close the identified Rust proof-content verification asymmetry, establish bounded shutdown/current-authority behavior, and connect a captured revision to pinned builds, immutable images and retained qualification/security evidence.

The executable plan, dependency waves, acceptance gates and cleanup/publication protocol are in [NEXT_GOAL_ALPHA_0_4.md](NEXT_GOAL_ALPHA_0_4.md). This update plans the next work; it does not claim those changes or tests have been implemented.

## Grounded starting point

[Alpha 0.3](ALPHA_0_3.md) records actual synthetic OIDC/BFF sessions, workload TLS, strict API tokens, v3 route/input/result binding, minimal database roles, independent approvals, receiver proofs, PKI rotation and isolated restore. [VALIDATION.md](VALIDATION.md) preserves earlier Alpha 0.2 results. Published `main` now contains `5b7b34e`; historical push failures no longer block publication. Hosted CI status is currently unverified because its API lookup was Forbidden.

The earlier application candidate was accurately recorded as a host-built Go/Rust and container-built workspace snapshot. The pinned Rust builder and combined one-shot verifier have not been established by that evidence. A fresh container build also needs to close the existing host `bin/evidence` dependency. Freeze measurable shutdown/load budgets and binary/rootfs/OCI reproducibility targets before testing; only declared metadata nondeterminism is allowed, with no normalization of unexplained payload/artifact differences. The next candidate must include cleanup before final source capture, avoiding another distinction between finished source and tested images.

This remains synthetic data and a deterministic model. Ordinary TLS/test PKI does not establish FIPS qualification, CUI authorization or FedRAMP/NIST/CMMC compliance. Live account/model/customer-identity setup remains deferred.

## Development path and acceptance gates

| Order | Deliverable | Acceptance evidence |
|---|---|---|
| 1 | Exact signed-content verification | A correctly signed wrong-content proof with the same ID/producer is rejected; canonical cross-language v1 vectors and historical valid proofs pass without format changes. |
| 2 | Bounded operational/current-authority behavior | Actual SIGTERM stops new admission and drains/cancels under defined bounds; original caller expiry, committed revocation, cancellation and saturation tests preserve denied/started/unknown semantics. |
| 3 | Self-contained pinned build | Fresh exact-source builds need no stale host artifacts; all binaries, builder/ABI/image identities are recorded; clean-build reproducibility is measured. |
| 4 | Complete qualification of the same artifacts | Actual DOM smoke plus existing protocol, database, mutation, readiness, rotation and restore tests run in order against the selected images; previous state remains intact. |
| 5 | Supply-chain evidence and release decision | Complete source/image inventories, raw findings, advisory results, durable verification artifacts and actual CI/provenance status share the same candidate identity. Any unmet required gate remains blocked. |

Do not start broad model routing, terminal execution, connectors, distributed sessions/custody or deployment frameworks. Add production integrations only after the separate boundary and account prerequisites below are ready.

## Parallel ownership and continuous publication

| Agent | Responsibility |
|---|---|
| A — application/contracts | Control/auth/workspace, migration runner (not SQL), shared trust/broker/contracts, caller validity and bounded operator behavior. |
| B — governance/effects | Rust kernel, policies, new SQL migrations, receivers/worker/evidence, exact signed content and effect/shutdown invariants. |
| C — builds/supply chain | Deployment/tooling/CI source, pinned builds, image remediation, inventories and operator documentation. |
| D — independent verification | Proof/identity/revocation/load/browser/lifecycle fixtures, integration checks and evidence verification. |
| E — dedicated publisher | Sole staging/commit/push owner and shared runtime scheduler; publish audited coherent checkpoints to `main`, never force, and verify the remote SHA. |
| F — trailing dead-code cleanup | Follow completed batches, prove obsolete consumers, obtain exclusive file handoff, remove safely, obtain independent review and submit a separate cleanup checkpoint through E. |
| Lead — auditor | Audit contracts, changes, test evidence and release decisions; resolve ownership without doing feature implementation. |

Precise paths and handoff rules are in the Alpha 0.4 plan. Keep three implementation lanes, an independent verifier, the publisher and the cleanup agent active. Source freezes cover only coherent capture. E runs shared builds/database/PKI/restore operations serially; unrelated file owners can continue once the snapshot is fixed. Final candidate cleanup must precede capture and affected validation.

Preserve active development paths, v2/v3 codecs, migrations, proof history and uncertain receipts. The cleanup agent is not paid by deletion count: interface/route dispatch, SQL lock sentinels, saved startup hooks and intentional deferred-provider seams require consumer checks.

## GovCloud production path after synthetic release qualification

Cloud identifiers and access are deferred at the user's request. Once available, confirm the target account, exact region and approved Bedrock model/features, then implement the application deployment rather than treating the current Terraform scaffold as a deployed service.

1. Establish the customer boundary and applicable contract clauses, NIST revision, CMMC level/assessment path, and FedRAMP authorization or equivalency requirements. Map each control to AWS, Nex.os, the customer or shared responsibility with dated scope evidence.
2. Replace synthetic identity and PKI with approved customer identity, workload certificates, rotation and revocation operations. Select and verify the required cryptographic modules and deployment configuration; ordinary TLS libraries do not establish FIPS qualification.
3. Implement approved storage, secret delivery, evidence/key custody and the fixed live Bedrock route. Validate service/model/region/API authorization scope and entitlement. Never silently fall back to another provider, model or region.
4. Deploy distinct task identities and private backend boundaries in GovCloud. Execute real worker-denial, provider, network, outage and recovery tests using synthetic payloads before any CUI.
5. Close software supply-chain and operating controls: reproducible provenance, vulnerability disposition, access review, monitoring, retention, backups, incident handling and assessor-reviewable evidence. Obtain the required operational and assessment approvals before real CUI use.

Keep on-premises packaging, Kubernetes, arbitrary terminal execution, broad connectors, vector search and multiregion deployment deferred until an actual requirement justifies them. A dedicated Ubuntu server is not required for managed AWS compute; Ubuntu remains a practical development host or a separately scoped future on-premises target.

## Report readiness accurately

Report local functionality, synthetic qualification, release readiness, actual cloud enforcement and formal assessment/authorization as separate results. GitHub publication is now verified at `5b7b34e`; the earlier HTTP 403 failures are historical. Current blockers include the denied native Go advisory feed, unresolved image findings and unverified hosted CI/provenance/reproducibility. After publication, the CI-status API lookup was Forbidden, so current hosted status is unknown/access blocked rather than assumed unrun. Preserve raw findings and incomplete evidence; do not weaken severity gates or invent waivers. See [ALPHA03_WIP.md](checkpoints/ALPHA03_WIP.md) for local checkpoint status.
