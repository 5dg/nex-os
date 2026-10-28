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
  Publication is pending. The one-file handoff remains held until E's approved
  separate publication.

## Reviewed implementation batches

| Published batch | Consumer audit | Cleanup decision |
|---|---|---|
| `ada368e20b57a38f2b19e2683a897a0337a6d9cc` — exact Rust evidence content | The new `evidence_v1` head/canonical/normalization helpers, event/envelope fields and `serde_json` raw-value feature all have active writer or conformance-test consumers. The fixed v1 vectors and real signed-wrong-content regression remain active verification. | No deletion justified. B's overlapping lifecycle files remain reserved for active implementation; no cleanup edits there. |

For each future batch record: producing revision, exclusive files, obsolete
items, consumer checks, validation commands/results, independent and lead review,
publisher commit/verified remote revision, and candidate-capture status.
