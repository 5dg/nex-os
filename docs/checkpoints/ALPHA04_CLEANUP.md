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
| `QualificationManifestVersion` in `packages/contracts/qualification.go` | The published baseline has no tracked consumer beyond its declaration, but A has reserved the file and may consume the constant during the current validation work. No exclusive edit handoff exists. | Hold. Recheck after A's completed batch; do not race or remove planned contract work. |

The entry-point and publication-status documentation findings from the preceding
review were corrected in `3650f10`: the README and current build/risk records now
distinguish qualification from the development lab, and historical evidence has
dated successful-publication addenda. These are completed documentation updates,
not pending cleanup work or evidence that an implementation can be deleted.

## Deletion batches

### F-001 — unused cached workspace configuration fields

- Producing revision: `3650f10`; the underlying implementation was already
  published and qualified before this cleanup.
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
  the diff and verification. Publication is not yet recorded; E alone may stage
  and publish these approved files. Record the verified publisher revision in
  the next ledger update rather than introducing a self-referential commit hash.
  No final-candidate claim is made here.

For each future batch record: producing revision, exclusive files, obsolete
items, consumer checks, validation commands/results, independent and lead review,
publisher commit/verified remote revision, and candidate-capture status.
