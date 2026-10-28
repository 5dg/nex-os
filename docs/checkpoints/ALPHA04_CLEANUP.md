# Alpha 0.4 trailing cleanup ledger

The cleanup agent follows completed implementation batches. The publisher owns
Git staging, commits and pushes; this ledger does not establish publication or
release approval.

## Required handoff for each deletion batch

1. Record the producing revision, file owner, changed symbols and supported
   compatibility promises after the implementation batch is reviewed and pushed.
2. Check consumers across source, tests, generated interfaces, framework routing,
   configuration, Docker/CI/Make entry points, documentation and saved environment
   installation/startup instructions. A text-reference count is only a lead.
3. Obtain an exclusive file handoff before editing. No cleanup changes may race
   with the implementation owner or an immutable candidate capture.
4. Remove only proven obsolete items, run relevant compiler/contract/behavior
   checks and provide the deletion diff to independent verification and the lead.
5. Return the files with the reason, consumer evidence, checks and limitations.
   The publisher then creates and verifies a separate cleanup checkpoint.

There is no deletion quota. Keep active development paths, intentionally tested
provider seams, v2/v3 codecs, migrations, proof history and uncertain receipts.
SQL `lock_version` columns can support minimum row-lock grants without being
updated by a runtime query. Generated RPC trait methods, gRPC interface methods
and framework route exports can have no ordinary direct call sites.

The final candidate must be captured after its applicable cleanup. Later source
changes require a new candidate or an explicit record that the changes were not
included in the tested artifacts.

## Wave 0 audit — 2026-10-27

Starting revision: `3650f10`, the published Alpha 0.4 plan. The initial audit
deleted no production files. The separately handed-off cleanup below follows
that audit.

| Candidate or pattern | Consumer evidence | Decision |
|---|---|---|
| `scripts/install-aws-cli.sh` has no tracked caller | The saved cloud environment installation script at draft revision 4 explicitly invokes it. The saved startup instructions also retain the GovCloud preflight workflow. Only script references were inspected; no credential values were read. | Keep. It is an active setup hook, not dead code. |
| `perRPC.RequireTransportSecurity` in `packages/trust/grpc.go` | Required by `credentials.PerRPCCredentials`; the implementation is returned to gRPC by `Config.PerRPCCredentials`. | Keep. Interface dispatch is a consumer. |
| Rust `check_readiness`, preparation, authorization, completion and state RPC methods | Implement the generated Tonic `Guard` trait in `services/guard-kernel/src/lib.rs`. | Keep. Generated server dispatch is a consumer. |
| Direct OPA client and development adapter paths | Existing integration tests and development routes still exercise them. | Keep while those supported paths remain. |
| Bedrock constructor and provider seam | Offline tests retain routing validation and provider behavior; live runtime construction remains prohibited in the supported synthetic profiles. | Keep the deliberate tested seam. |
| `QualificationManifestVersion` in `packages/contracts/qualification.go` | The published baseline had no supported consumer beyond its declaration. A initially reserved the file, then finished validation work without consuming the constant and explicitly released the reservation. | Initially held; resolved by the approved F-003 batch below. |

The entry-point and publication-status documentation findings from the preceding
review were corrected in `3650f10`: the README and current build/risk records now
distinguish qualification from the development lab, and historical evidence has
dated successful-publication addenda. These are completed documentation updates,
not pending cleanup work or evidence that an implementation can be deleted.

## Deletion batches

### F-001 — unused cached workspace configuration fields

- Producing revision: `3650f10`; the underlying implementation had prior
  qualification evidence for the exact snapshots disclosed in
  `docs/ALPHA_0_3.md`. This cleanup does not relabel those images as builds of a
  later source revision.
- Exclusive files: A granted `apps/workspace/lib/trust.ts` for removal of only
  the stored `WorkspaceConfig.audience` and `.scope` properties and their object
  shorthand values. No other A-owned source file was edited by F.
- Consumer evidence: workspace source, existing security tests and qualification
  fixtures have no property, destructuring or indexed consumer of those cached
  fields. The workspace package is private and the fields are not a public
  browser/API contract. The local variables and exact `OIDC_AUDIENCE` and
  `OIDC_REQUIRED_SCOPE` validation remain unchanged.
- Changes: removed the two cached type properties and two stored object values;
  retained client ID, all trust snapshots, native TLS validation, deadlines,
  canonical-host checks and credential/profile rejection behavior.
- Validation: `npm run typecheck` passed; the existing `npm test` security suite
  passed all five tests with zero failures or skips. No new field-mirroring test
  was added, and no package dependencies or generated contracts changed.
- Review/publication: D independently accepted the deletion and the existing
  checks after reviewing the diff and consumer searches. The lead also accepted
  the diff and verification. E published the two approved files in
  `25c7d680d23a6f467cd268725ac5963b05f8ce25` and verified remote `main` matches that
  revision. The exclusive source-file window was returned to A afterward.
  No final-candidate claim is made here.

### F-002 — unused foundation DTOs and unreachable OpenAPI definitions

- Producing revision: `ada368e20b57a38f2b19e2683a897a0337a6d9cc`; the five
  definitions predate that batch and were already published in the Alpha 0.3
  source.
- Scope: remove only exported Go DTOs `Delegation`, `Job`, `Approval`,
  `DocumentReference` and `AuditEvent` from `packages/contracts/types.go`, and the
  same five schema definitions from `packages/contracts/openapi.json`.
- Consumer evidence: no supported Go consumers were found. Both F and D
  independently followed nested OpenAPI schema references from the API roots;
  exactly these five definitions were unreachable. The similarly named UI
  types, active `ReviewJob`, `ApprovalView`, document/event list schemas, Protobuf
  messages and v2/v3 payloads remain intact. No version tags or stable Go SDK
  promise are known; this is not a claim about every possible external consumer.
- Authorization: the lead approved this narrow removal conditional on D's
  independent closure audit and A's exclusive two-file handoff. Both conditions
  were met before editing; no other A-owned production file was changed by F.
- Verification: the resulting OpenAPI object equals the saved baseline after
  removing exactly the approved five definitions. All paths, security settings,
  remaining schema values and reachable references are identical; no dangling
  references remain. `go test -mod=readonly -race ./packages/contracts` passed
  using Go's valid test cache. All Go packages and integration-tagged tests
  compiled with `go test -mod=readonly -tags=integration -run '^$' ./...`; that
  command was compilation only, not an integration-test execution. Formatting
  and diff-whitespace checks passed. No deletion-mirroring tests were added.
- Review/publication: D accepted the post-deletion diff after independently
  repeating the whole-document semantic comparison and confirming the exact
  approved DTO removals. The lead accepted the exact diff, closure and compile
  evidence. E published the three approved files in
  `958e775daf14b7f77da836c5edbae9303795aedb` and verified remote `main` matches that
  revision. The two source files were then returned to A. No final-candidate
  claim is made here.

### F-003 — unused qualification version declaration

- Producing scope: the already published `958e775` baseline. A completed its
  validation work without consuming the reserved declaration and explicitly
  granted the one-line file handoff once the lead approved removal.
- Scope: remove only the unused exported `QualificationManifestVersion`
  constant from `packages/contracts/qualification.go`. The validator's literal
  version 3, all other tuple constants, v2/v3 payload code and conformance vectors
  remain unchanged.
- Consumer evidence: F and D independently found no supported code consumer.
  The cleanup ledger was the only other name reference. As with F-002, no stable
  SDK promise or release tag is known; this is not a universal external-consumer
  compatibility assertion.
- Verification: the existing contracts race suite passed with Go's valid test
  cache. The actual source diff is exactly the approved declaration deletion;
  Go formatting and diff-whitespace checks passed. No new tests were introduced.
- Review/publication: D independently accepted the exact one-line source diff
  and proportionate checks. The lead accepted the exact diff and verification.
  E published the two approved files in
  `56adf29d6e9f4590974c316b136b13dbc391e118` and verified remote `main` matches that
  revision. The source file was then returned to A.

## Reviewed implementation batches

| Published batch | Consumer audit | Cleanup decision |
|---|---|---|
| `ada368e20b57a38f2b19e2683a897a0337a6d9cc` — exact Rust evidence content | The new `evidence_v1` head/canonical/normalization helpers, event/envelope fields and `serde_json` raw-value feature all have active writer or conformance-test consumers. The fixed v1 vectors and real signed-wrong-content regression remain active verification. | No deletion justified. B's overlapping lifecycle files remain reserved for active implementation; no cleanup edits there. |
| `1819277d4859ea601c298d4f759edadadae12208` — original caller rechecks | The request snapshot, current-caller checks, pre/post-dispatch checks, fenced operational accounting and transaction wrapper are consumed by the control paths or meaningful boundary tests. `requestTx.Begin` deliberately overrides the embedded `pgx.Tx` method to preserve the original authority and nested cancellation; an absent direct application call is not evidence of obsolescence. | No deletion justified. Keep the wrapper/interface guard and the caller expiry, disconnect, cancellation and accounting tests. |
| `139a242559a6cded70794afdbb92194f944ce73d` — bounded workload shutdown | The new shutdown control, watch subscriptions, request/database permit accounting, capacity constants and listener cancellation branches are consumed by the process, transport, state store or meaningful shutdown tests. `StateStore::admission` is also used as a method pointer. The Go 70-second drain and Compose 75-second grace remain an active coordinated contract. | No deletion justified. Preserve platform signal branches and the signal/admission/database/post-dispatch tests. C's newer Compose and script work remains reserved; this audit reviewed the published cohort, not unpublished replacements. |
| `4c1f4163f5e7f979879caf3e4180ef77687d3227` — source and image integrity helpers | Source companion/input validation, capture and artifact checks, IPAM/environment binding and merged image metadata are consumed by the CLI, integrity tests or active build integration. The published hardlink rejection is an intentional fail-closed branch while C develops its replacement semantics; helpers reserved for that ongoing integration are not obsolete. | No deletion justified. Preserve the metadata/tamper checks and independent integrity tests. This is a consumer review, not proof that a complete canonical build or reproducibility run has passed. |
| `a1d825503072035efb03af11cee94e89c7b714e7` — runtime hardlink identity | C replaced the prior blanket hardlink rejection with supported inode/alias semantics. The new path and ancestor checks, inode alias tracking, structural metadata handling and invalid-link rejections are consumed by the payload algorithm and semantic regression cases. | No additional deletion justified. Preserve the unsupported-input failures and hardlink/content/whiteout tests; C's replacement already removed the obsolete blanket rejection within its reviewed implementation. |

For each future batch record: producing revision, exclusive files, obsolete
items, consumer checks, validation commands/results, independent and lead review,
publisher commit/verified remote revision, and candidate-capture status.

## Current-baseline consumer audit — 2026-10-28

Reviewed baseline: `640ce8f` (immutable candidate builds and qualification delivery
tooling). The lead granted the cleanup owner exclusive access to this ledger;
this audit changes no executable source and does not establish remote publication.

| Reviewed paths | Observed consumers | Decision |
|---|---|---|
| `scripts/candidate-pipeline.sh`, `canonical-build.py`, `canonical-compiler.sh` and `candidate-evidence.py` | The canonical CI job invokes the pipeline; the pipeline invokes two builds, comparison and evidence retention; the builder invokes the compiler script. The candidate runbook exposes the supported local entry point. | Keep. These are connected delivery paths, not obsolete replacements. |
| `scripts/ipam-preflight.py`, `qualification-native-fixtures.sh`, `candidate-native-suite.sh` and `qualification-native-check.sh` | The pipeline invokes IPAM admission and native fixtures; the fixture child runs the native suite, which dispatches the proof-parity and shutdown checks. | Keep. Their execution remains a qualification gate; lack of a completed candidate run does not make them dead code. |
| `scripts/qualification-browser.sh`, browser tooling and qualification drivers | The ordered verifier invokes the browser harness when a candidate manifest is present; the harness mounts the workflow and revocation drivers into the browser fixture. | Keep. Preserve the real-browser qualification path and its isolated fixture. |
| `scripts/verify-retained-candidate.py`, `verify-provenance.py` and `install-gh-attestation.sh` | The candidate runbook invokes retained verification and the pinned verifier installer; retained verification imports the provenance verifier. Existing release tests exercise these interfaces. | Keep. Deferred hosted execution is not proof of obsolescence. |
| Development smoke, workflow, recovery and restore scripts | `scripts/verify-local.sh` still invokes these checks for the supported development profile. | Keep. Qualification delivery does not retire the development workflow. |

No additional executable deletion is justified by this bounded consumer audit.
The existing cleanup exclusions remain in force, including provider seams,
framework/generated dispatch, historical migrations and proofs, v2/v3 contracts
and uncertain receipts. This records static call-path inspection only: no new
behavioral tests, canonical builds, hosted CI, reproducibility checks or release
qualification were executed by the cleanup owner. Later implementation batches
still need their own consumer audit before final candidate capture.

## Packaging and operator completion audit — 2026-10-28

Producing delivery revision: `b65cf7bb02eb21c0067c6cdf084062c1c5c9e94a`.
The lead released the diagnostic snapshot window before granting this ledger
update. The application/history/browser review below covers the then-uncommitted
completion batch based on that revision; it is not a publication or candidate
qualification claim for that batch.

| Reviewed scope | Consumer evidence | Cleanup decision |
|---|---|---|
| Pinned workspace runtime preparation | `canonical-compiler.sh` invokes `prepare-workspace-runtime.mjs`; its CLI invokes `prepareWorkspaceRuntime`. The source/layout, manifest, key-occurrence and symlink checks guard admitted packaging; counters and source hashes populate its emitted report. `test_workspace_packaging.py` exercises this path. | Keep the preparation and rejection paths. No orphan helper or field was established by this review. |
| Packaged lifecycle wrapper and required evidence | `candidate-pipeline.sh` invokes `qualification-packaged-lifecycle.sh`; the wrapper dispatches `TestQualificationPackagedLifecycle`. Candidate sealing and retained verification both require `packaged-shutdown`. Canonical and explicitly selected diagnostic modes have distinct supported callers. | Keep both modes and the state-preserving lifecycle fixtures. Diagnostic mode is not obsolete merely because the candidate pipeline uses canonical mode. |
| Browser dependency inventory and scanning | `release-audit.py` invokes the source inventory and the workspace/browser lock-only audits. Inventory components merge shared dependency properties and hashes; source inventory regressions exercise both locks. | Keep the browser tooling inventory and merge logic. No dependency deletion is justified. |
| Workflow polling, history selection and refresh adapter | `Workflow.tsx` consumes `pollJob`, `historyPage` and `appendHistory`; their existing unit tests exercise scheduling, cancellation and history continuation. `refresh(id)` still serves the load, reconcile, retry and export handlers and returns the promise expected by the `run` action contract. | Keep these reachable helpers. The old interval polling body was replaced within the implementation; the remaining async adapter is active code, not a dead function. |
| History cursor, ordering and compatibility fields | The routed `jobEvents` handler consumes option parsing, event verification and cursor encode/decode. Cursor snapshot/XID, sequence/time/ID boundaries and scope/expiry fields participate in SQL selection, continuation or authenticated validation. `historySecretOnce` and `historySecret` feed the MAC. The row-lock scan supports serialized same-job signing. Both BFF profiles retain the legacy `events` operation alongside `event_page`. | Keep cursor fields, lock acquisition and bounded legacy handling. The implementation already removed the superseded handler body/imports from `workflow_http.go`; no further deletion is established. |
| Operator browser helpers and drivers | The browser harness mounts `acceptance.mjs` and `workflow-fixture.mjs` and invokes `operator-browser.mjs`. Workflow/operator drivers and acceptance tests consume the limits, history verification, request helpers and polling assertions. | Keep the shared helpers and genuine signed-history fixtures. They are active acceptance paths, not production dead code. |

Decision: no additional executable deletion justified. This is a bounded static
consumer audit, with no deletion quota and no source-file handoff requested.
Only this ledger changed; the cleanup owner did not run behavioral tests, mutate
shared runtime state, stage files or publish commits. Independent review and
publication remain with the lead and publisher. Any later edits to the reviewed
application batch require a follow-up audit before final candidate capture.
