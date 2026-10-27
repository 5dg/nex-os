# Next goal: Alpha 0.3 authenticated boundaries and release qualification

Historical milestone proposal. For executed Alpha 0.3 results see [ALPHA_0_3.md](ALPHA_0_3.md); the current development path and remaining release/cloud gates are in [BUILD_PLAN.md](BUILD_PLAN.md).

Planning review: 2026-10-27. This is a proposed development goal, not an instruction to deploy or publish configuration. Preserve [Alpha 0.2](ALPHA_0_2.md) and its [validation evidence](VALIDATION.md).

## Copyable goal

> Build a synthetic qualification profile in which an authenticated browser session and verified service identities carry one document review through independent approval and controlled export. Rust must preserve exact payload/limit authorization and protected results, and extend sealed binding to the actual provider identity. Missing identity, trust, signing or admission configuration must prevent the affected action. Preserve Go, Rust, gRPC and all Alpha 0.2 execution/recovery invariants. Produce repeatable evidence tied to tested source and images, reporting external release blockers explicitly.
>
> Use a controlled OIDC fixture, test PKI, synthetic records and provider stubs. Keep live GovCloud/Bedrock, customer identity configuration, approved production cryptography and CUI deployment deferred until their prerequisites are supplied and assessed.

## Why this is next

The recorded baseline has 139 integration leaf scenarios, seven policy tests, four Terraform mock tests, actual database-role denials, workflow/recovery checks and controlled database/journal/receipt restoration. These were not rerun for this planning review. Review of authored services, contracts, workspace, tests, infrastructure, scripts and documentation points to identity and deployment boundaries as the next useful advance.

| Current code | Finding and next work |
|---|---|
| `apps/workspace/app/api/workflow/route.ts` and `api/demo/route.ts` | The BFF accepts selected development personas and mints their tokens. Add server-owned login/session/callback/logout; keep persona minting confined to development. |
| `services/control/auth/auth.go` | Bearer authentication uses `oidc.IDTokenVerifier`. Freeze a distinct API token-use/audience contract while retaining issuer/subject membership resolution. |
| Rust `main.rs`, `execution.rs`; Go `guard/grpc.go`; broker/worker/policy/evidence clients | Transport is deliberately development-only; Rust PostgreSQL uses `NoTls`. Cover every credential-bearing edge, not just gRPC. |
| `services/control/cmd/control/main.go`, `api/evidence.go` | Required clients/signing depend on optional URL presence; missing writers succeed in legacy fixtures. A qualification profile must reject omitted dependencies and unsigned control-event fallback. Rust execution already requires signing. |
| `services/model/bedrock.go` and kernel route construction | SDK invocation uses separately configured `b.ModelARN`; sealed requests name symbolic `dev-model`. Bind the effective provider/region/model/endpoint/features at invocation and protected completion before any live adapter. |
| Kernel model input construction | Questions are sealed text, but classification comes from the document. Define admission for every input; unknown questions cannot silently acquire a public label. |
| `api/workflow_approval.go` and `workflow_store.go` | `requestExport` persists new approval/operation IDs but records the previous job value. First fix `approval.requested` attribution. Rust execution protection remains intact. |
| Kernel database access and deployment tooling | Per-RPC connections lack established admission/DB time bounds. Release checks remain blocked; Terraform is foundation scaffolding, not a running application deployment. |

These are concrete next boundaries, not a demonstrated bypass of the synthetic Alpha 0.2 execution path.

## Scope and completion levels

Keep one template, one fixed route contract and one export destination. Preserve immutable manifests, current authority, independent approvals, minimal database roles, protected results and conservative receipts. Changed route/admission semantics require a versioned canonical payload/manifest and additive migration; never add unhashed authority fields or silently upgrade v2 history. Changed context requires a fresh applicable approval.

Use an explicit **synthetic qualification** profile. It must forbid real provider calls even if AWS credentials/provider environment variables appear. Preserve the development demonstration separately. Production remains closed; loosening existing `APP_ENV` checks is not a production implementation.

Report three outcomes separately:

- **Local implementation:** authenticated synthetic workflow and negative/fault tests pass.
- **Release qualification:** an authorized fresh CI run, immutable source/image identities, complete scans and required vulnerability dispositions exist.
- **Regulated deployment:** approved environment, identity, crypto/custody, operating controls, boundary/SSP and applicable assessment/authorization exist. TLS or these tests alone confer no FedRAMP/NIST/CMMC status.

Exclude S3/KMS implementation, full Terraform deployment, connectors, arbitrary model routing, multi-writer custody, Kubernetes, workflow frameworks and product redesign. Browser work supplies identity and accurate workflow/status navigation.

## Freeze these contracts first

A short ADR must define:

1. Profile/configuration behavior, complete trust matrix, service identities, role permissions, CA/SAN checks, rotation/revocation windows, deadlines and downgrade rejection. Freeze compatible test backends/versions before coding. Missing approved production modules are an external gate, not a blocker for offline fixtures; test PKI confers no production crypto approval.
2. Browser authorization-code flow with PKCE/state/nonce; server session ownership; supported API access-token format, issuer/audience/use and membership mapping. Select one explicit fixture profile. Do not assume every access token is a JWT or accept a browser ID token as the API credential. Unsupported opaque-token/provider profiles remain deferred.
3. Fixed provider/region/exact model/effective endpoint/features, template/version, limits and all-input admission. Check returned provider/model identity too. A server-owned synthetic question catalogue is a suitable first slice; otherwise require explicit trusted classification/provenance. Unclassified input must not reach an external provider. No automatic CUI-classifier claim.
4. Event-context ownership, authenticated readiness and bounded server/DB behavior. Separate liveness from verified dependency readiness; a public signer `healthz` response cannot prove the configured signing identity/key match. Preserve unknown outcomes during cancellation, rotation and dependency failure.

| Edge | Qualification requirement |
|---|---|
| Browser → workspace | HTTPS and secure server session; CSRF/origin/redirect controls; no client-selected identity |
| Workspace → control | mTLS BFF service identity plus the separate API access-token/delegation contract; tokens stay server-side |
| Control/model/export → Guard | mTLS peer roles: control evaluates/prepares/decides; receivers authorize/inspect/complete only their execution kind |
| Control → receivers; worker → control | mTLS service peers plus existing operation scope; worker remains limited to claim/step |
| Guard → OPA | mTLS policy peer, pinned source and restricted management/write authority |
| Control/Guard → evidence | mTLS producer identities and pinned signing verification; mismatched trust/keys cannot appear execution-ready |
| Control/Guard → PostgreSQL | Verified server CA/name plus distinct minimal role credentials; no plaintext/admin fallback |
| Workspace/control → OIDC | Verified issuer/discovery/JWKS/token endpoints under the declared issuer policy |

Specify TLS termination/trusted-hop behavior; spoofable forwarding headers are not peer identity. Browser server TLS differs from service mTLS. A service certificate never confers human/tenant permissions. Unsupported authentication remains a gap. OPA transport/management changes must preserve explicit expected-bundle/source checks: adding an authorization module cannot justify dropping mismatch detection or granting policy writes to every trusted certificate.

## Development sequence

### 0. Correct attribution and establish the baseline

F reproduces the stale `approval.requested` IDs; A fixes the event context without altering history or policy. Catalogue development routes and required dependencies while A drafts the contracts. An immutable source revision is a release prerequisite; repository publication/run needs its applicable authorization.

**Gate:** new event matches persisted approval/operation/job/tenant; existing workflow, proof and role checks pass.

### 1. Complete one authenticated export slice

After contract freeze, implement control→Guard mTLS, control→export mTLS and their policy/signer/database dependencies according to the matrix. Establish review provenance through genuine Rust preparation/authorization/protected completion against a controlled model fixture, or a fully verified restored fixture. Never inject answers/provenance by SQL. Then prove approval, exact export and receipt-status recovery. Add bounded server admission and database acquisition/statement/lock limits, preserving unknown-state semantics.

**Gate:** exact export succeeds; wrong CA/SAN/role, expired identity, plaintext, omitted configuration, wrong database CA and signer mismatch fail before effects. Use actual minimal runtime roles, including SELECT-only protected-result access.

### 2. Extend to model admission and browser sessions in parallel

B/D bind the one model route and all inputs, check the effective adapter before the callback, and check completion identity. Offline stubs must reject changed provider/region/ARN/endpoint with zero provider calls. Qualification must remain incapable of a real Bedrock call.

C implements fixture-backed login/callback/session/logout with HttpOnly/Secure/SameSite cookies, bounded parsing, CSRF/state/nonce and strict redirects. Identity comes from the session; current membership/permissions remain server-resolved. Make the working document workflow primary and clearly separate the development laboratory.

**Gate:** one authenticated requester reviews, a distinct authorized approver approves, and exported bytes match the preview. Forged identity/tenant/roles, wrong token use/audience/issuer, callback replay, expired session and revoked membership are denied. Input-classification downgrades and altered provider completions are denied.

### 3. Exercise lifecycle faults and reproduce the release

Test certificate/token rotation and expiry, including already-established connections, plus slow dependencies, concurrency, cancellation and restart. Unknown receipts must not repeat effects; old proofs/receipts still verify; source/delegation/approval authority is rechecked.

E runs release closure in parallel: preserve raw findings, verify vendor applicability and evaluate supported minimal images/fixes. Correct known drift: `Dockerfile.control` omits the evidence binary present in `.control.local`; `build-local.sh` hard-codes the workspace tool root; host-linked Rust/debug packaging lacks a pinned builder/ABI provenance story. Source SBOMs do not replace image OS inventories or signed provenance.

**Gate:** one documented qualification verification entry point covers the trust matrix, workflow, roles, faults, contracts and restore. Source/locks/images/results/SBOM/scans are traceable. A genuinely fresh CI run is claimed only after execution. Scanner filters are not weakened and risk acceptance is not invented.

## Subagent ownership and execution waves

Use six active children at most, plus the lead auditor. The lead reviews contracts/diffs/evidence and resolves findings; implementation remains delegated. Small component unit tests stay with their owner; shared integration tests stay with F.

| Agent | Exclusive files | Responsibility |
|---|---|---|
| A: contracts and Go runtime | `packages/contracts/**`, new Go service-auth/transport package, Go module locks, architecture ADR; `services/control/guard/**` except integration tests; `services/control/cmd/control/**`; control API production files and `services/control/devseed/**` | First attribution and ADR/protocol freeze; then shared transport and strict Go runtime wiring. Sole generated-binding and control `server.go`/`main.go` owner. Does not edit broker or C's auth/workspace files. |
| B: Rust authority | `services/guard-kernel/**`, `policies/**`, new SQL migrations | Peer roles, OPA source policy, database TLS/bounds and route/result binding. Reserve migration numbers with A; preserve old checksums. |
| C: human identity | `services/control/auth/**`, `apps/workspace/**` | Access-token verifier, server sessions and workflow navigation. Uses F's OIDC fixture; supplies constructor/config requirements to A rather than editing control startup. |
| D: receivers/custody | `services/model/**`, `services/tool-executor/**`, `services/evidence/**`, `services/worker/**`, `packages/broker/**`, `packages/evidence/**` | Consume A's transport API; exact adapter binding, producer readiness, safe receipts. Sole broker writer. Keep one local writer/custody domain. |
| E: release/stack coordinator | `deploy/**` except SQL, `.github/**`, `scripts/**`, Makefile/tool/bootstrap files and final evidence/runbooks | Sole Docker/build/Compose/ports/shared-state/migration-invocation owner. CI, build drift, scan triage and final orchestration. Others submit build requests. |
| F: independent verification | `tests/**`, control API/Guard `*_integration_test.go`, new `tests/qualification/**` fixtures | OIDC/PKI/fault fixtures and cross-boundary tests; production code read-only. Verify fixes independently and supply E the consolidated command manifest. |

- **Wave 0:** A attribution/contracts; F failing regression/fixtures; E release inventory. B/C/D investigate read-only until interfaces freeze.
- **Wave 1:** A/B/D complete export first; C builds sessions concurrently; F develops negative/fault tests; E triages release issues without disturbing the stack.
- **Wave 2:** E integrates export, model, then browser in separate batches. Contract changes reopen the relevant gate and regenerate through A only.
- **Wave 3:** freeze implementation, run consolidated verification, then only justified targeted reruns. E retains non-secret logs/hashes; F and the lead audit outcomes.

Each handoff includes owned files, contract/schema versions, positive/negative results, limitations and build readiness. Current scripts hard-code `nex-local`, ports and shared `.local` state: never run competing stacks. Never reset volumes/delete receipts/edit past migrations to manufacture success.

## Completion and external blockers

Local completion requires the session-to-export trust matrix, exact route/input/result binding and lifecycle/resource tests, retaining the Alpha 0.2 invariants. Qualification must contain no persona-vending path, plaintext/unsigned fallback or live-provider escape.

Release closure remains explicit: the inactive `vuln.go.dev` draft needs operator review/save/publication; hosted CI needs an authorized source publication/run; residual Guard/workspace OS advisories need evidence-backed remediation/applicability or authorized disposition. Missing feeds and unrun checks remain blocked. Do not ask again for deferred account/model/customer-issuer details while implementing the offline scope.

Production storage/custody, approved crypto, customer MFA/lifecycle, live IAM/network/model behavior, budgets, operational recovery objectives and assessment follow later. Update stale `BUILD_PLAN.md`, supply-chain control status and six-writer restore instructions in `runbooks/LOCAL.md`; retain `NEXT_GOAL.md` as the historical Alpha 0.2 plan.

## First executable ticket

**Correct `approval.requested` attribution.** F proves the event currently names stale IDs. A records the newly persisted approval/operation/job/tenant context. Verify valid signatures and unchanged approval/execution behavior, preserve historical events, and retain the focused result. Draft the identity/crypto/trust ADR in parallel. The next ticket is the authenticated export slice above, before expanding model and browser integration.
