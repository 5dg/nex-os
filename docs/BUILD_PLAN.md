# Nex.os development goal and implementation path

## Current goal: Alpha 0.3 synthetic qualification

Deliver a reproducible, identity-bound document-review → approval → export workflow using the existing Go control plane, Rust Nex.Guard and versioned gRPC contracts. A browser authenticates through an explicit synthetic OIDC provider; every protected service call uses an authenticated workload identity. Guard validates the exact model route, fixed question, admitted document version, delegated authority and approval before a receiver produces an effect. Evidence binds those decisions and outcomes to the same operation.

This milestone uses synthetic data and a deterministic model. It establishes a testable application boundary before adding a real cloud model and customer identity. It does not process CUI, establish FIPS qualification, authorize Nex.os under FedRAMP or satisfy an organization's CMMC assessment.

## Grounded starting point

The repository already contains a working Alpha 0.2 development workflow, a durable PostgreSQL queue, scoped model/export receivers, signed evidence, crash/retry handling and role-separated deployment. Historical executed results are in [VALIDATION.md](VALIDATION.md).

Alpha 0.3 adds strict TLS workload identities, browser OIDC sessions and CSRF protection, access-token validation, a v3 execution manifest, trusted question/document admission records and authenticated receiver-readiness proofs. The frozen contract is [ALPHA03_TRUST_CONTRACT.md](architecture/ALPHA03_TRUST_CONTRACT.md). The isolated `deploy/qualification` project preserves the old development state. Its first core stack completed TLS PostgreSQL bootstrap, migration and seeding, and returned HTTP200 to a workspace-authenticated readiness request. Whole-Go race checks and the component Rust/workspace checks passed. The current-source browser/API workflow, PostgreSQL trust/role checks, thirteen kernel authority mutations, receiver-readiness negatives, coordinated certificate rotation and an isolated quiescent restore have now passed actual integration checks. Release qualification remains blocked by vulnerability/advisory, reproducibility and external CI/publication gates; see [ALPHA_0_3.md](ALPHA_0_3.md) for the exact candidate and executed evidence.

## Development path and acceptance gates

| Order | Deliverable | Acceptance evidence |
|---|---|---|
| 1 | Freeze one identity and execution contract | Exact service principals, TLS endpoints, v3 fields, SQL grants, production rejection and error behavior agree across Go, Rust and TypeScript. |
| 2 | Start the isolated current-source stack | Fresh and interrupted initialization preserve state; verified TLS PostgreSQL and distinct minimal database roles work; OPA engine has no exposed administrative listener; readiness verifies live dependencies with bounded requests. |
| 3 | Complete the real browser workflow | Login, tenant-scoped review, delegation, approval for the exact export, execution and independent receipt/signature verification pass using the actual Go/Rust services. No browser persona or ID token grants API authority. |
| 4 | Exercise denied and changed authority | Wrong identity, CA, DNS, expired chain, wrong body key, replay, changed catalogue/admission/body/route and expired or revoked authority fail before protected effects. Run shared-metadata mutations serially after the ordinary workflow. |
| 5 | Verify lifecycle custody | Coordinated certificate rotation invalidates old sessions and permits fresh login while preserving signing identity, old receipts and journal prefixes. A quiescent isolated restore preserves application/evidence consistency without concurrent writer sets. |
| 6 | Qualify the release artifacts | Reproduce the pinned-builder path, record source/image/binary/SBOM identity, retain all vulnerability findings and unresolved advisories, run hosted CI and capture dated evidence. A host-compiled functional candidate is explicitly not a release attestation. |

Start with `scripts/qualification.sh build-host` for a clearly labeled local diagnostic candidate, or `build` for the pinned-container-builder path. Then run `init`, `up` and `ready`. The build mode and executed checks must accompany any result. Do not delete retained volumes, signing keys, receipts or past migrations to make a check pass.

## Parallel ownership and integration discipline

| Agent | Exclusive implementation responsibility | Hand-off |
|---|---|---|
| A — contracts/control | Trust contract and shared Go trust library; wire contracts; control API, database role grants and exact fixture admission | Freezes interfaces first; resolves cross-language or authority mismatches. |
| B — governance | Rust kernel, canonical manifest enforcement, migration schema and kernel adversarial tests | Implements the frozen contract; never substitutes caller assertions for trusted records. |
| C — identity/workspace | Strict access-token validation, browser OIDC/session/CSRF/BFF and workspace UI | Supplies component tests and exact endpoint/session behavior. |
| D — effects/evidence | Model, export, evidence and worker services; capability and readiness proofs | Supplies scoped receiver tests and a read-only live readiness probe. |
| E — release coordinator | Deployment, Docker, scripts/tooling, CI, shared stack operations, source checkpoints and final evidence/runbooks | Sole owner of builds, stack changes, migrations, rotation, restore and Git publication. |
| F — independent acceptance | Synthetic PKI/OIDC fixtures, browser/lifecycle integration tests and dead-code audit | Reviews implementation independently; coordinates deletions with each source owner. |
| Root — audit | Contract decisions, staged-change review, acceptance and final readiness assessment | Audits agent work and requires actual evidence before claiming a gate passed. |

Keep production edits within ownership. Route shared runtime requests through E. Use short source freezes only to capture a coherent immutable compiler input; release editors before Docker builds or stack testing. Run browser baseline first, then metadata mutations and custody transitions serially. Remove only code shown to be unused; retain active development behavior, historical v2 interpretation, migrations and receipts.

## GovCloud production path after Alpha 0.3

Cloud identifiers and access are deferred at the user's request. Once available, confirm the target account, exact region and approved Bedrock model/features, then implement the application deployment rather than treating the current Terraform scaffold as a deployed service.

1. Establish the customer boundary and applicable contract clauses, NIST revision, CMMC level/assessment path, and FedRAMP authorization or equivalency requirements. Map each control to AWS, Nex.os, the customer or shared responsibility with dated scope evidence.
2. Replace synthetic identity and PKI with approved customer identity, workload certificates, rotation and revocation operations. Select and verify the required cryptographic modules and deployment configuration; ordinary TLS libraries do not establish FIPS qualification.
3. Implement approved storage, secret delivery, evidence/key custody and the fixed live Bedrock route. Validate service/model/region/API authorization scope and entitlement. Never silently fall back to another provider, model or region.
4. Deploy distinct task identities and private backend boundaries in GovCloud. Execute real worker-denial, provider, network, outage and recovery tests using synthetic payloads before any CUI.
5. Close software supply-chain and operating controls: reproducible provenance, vulnerability disposition, access review, monitoring, retention, backups, incident handling and assessor-reviewable evidence. Obtain the required operational and assessment approvals before real CUI use.

Keep on-premises packaging, Kubernetes, arbitrary terminal execution, broad connectors, vector search and multiregion deployment deferred until an actual requirement justifies them. A dedicated Ubuntu server is not required for managed AWS compute; Ubuntu remains a practical development host or a separately scoped future on-premises target.

## Report readiness accurately

Report local functionality, synthetic qualification, release readiness, actual cloud enforcement and formal assessment/authorization as separate results. Current external blockers include GitHub write access (normal main pushes returned HTTP403), the denied native Go advisory feed, unresolved OS-image advisories and an unexecuted hosted CI run. Preserve raw findings and incomplete evidence; do not weaken severity gates or invent waivers. See [ALPHA03_WIP.md](checkpoints/ALPHA03_WIP.md) for local checkpoint status.
