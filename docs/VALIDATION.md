# Validation evidence: Alpha 0.2 local execution integrity

Observed on 2026-10-27 with synthetic data. Local verification, source reproduction, hosted CI, live cloud enforcement and formal assessment are separate outcomes. No CUI production-readiness or compliance authorization is asserted.

## Functional evidence

`make verify-local` passed end to end in the prepared instance. After independent audit fixes, the affected Rust/Go/API suites and real workspace/service/recovery flows were rerun against the final code/images. Combined evidence covers 139 integration leaf scenarios: 35 tenant/API, ten Go preparation/recovery/acknowledgement/fencing, and 94 Rust boundary/configuration/execution cases. These passed across the full run and focused final reruns; this is not a claim that every command ran once in a single final invocation. Dependencies are required and integration tests do not silently skip.

| Invariant/check | Outcome | Evidence |
|---|---|---|
| Reproducible contracts | Passed | Pinned Go gRPC output reproduces exactly; six shared semantic digest vectors pass in Go and Rust; Rust formatting is checked |
| Unit/static checks | Passed | Race-enabled Go suite and `go vet`; broker child-process crash/restart, concurrent calls, corrupt/missing receipts and strict bounded responses; evidence/proof and Bedrock stub checks |
| Independent payload binding | Passed | Go-selected matching digests cannot authorize substituted export content/tenant/destination/approval or model prompt/route/limits/classification; receiver denies before provider/artifact effects |
| Protected provenance | Passed | Rust prepares immutable manifests and records authenticated outcomes; wrong producer/altered result/replayed start rejected; stale source, cross-job/tenant aliases and late completion contexts covered; Go compares HTTP acknowledgement with the protected result and signs protected current metadata |
| Configuration/signing | Passed | Positive execution-profile baseline; omitted/malformed/same-key/profile configurations rejected independently; evaluation cannot execute; signer failure rolls back authorization |
| Freshness | Passed | Current ACL/delegation/permissions/version/classification/destination/policy checked; lease/approval freshness rechecked after slow signing; expired grant rolls back consumption |
| Preparation/recovery API | Passed | Fenced failure releases lease even when signing is unavailable; stale worker cannot overwrite new lease; HTTP owner/current-authority checks, forged outcome rejection, pending-only same-operation retry and status-only reconciliation; SELECT-only protected-result reads; matching acknowledgement positive control, substituted acknowledgement rejection, operation/phase advance with unchanged lease cannot overwrite progress |
| Receipt recovery | Passed | Known-not-started versus in-progress/unknown; completed result recovered after signing/report outage without repeating provider; pending/corrupt/missing storage cannot justify repetition |
| Wire bounds | Passed | Escaped 12 KiB model result signs, approves and exports exact bytes within bounded HTTP/gRPC messages; semantic text/token limits remain enforced |
| Rego policy | Passed | Seven policy tests |
| TypeScript and workspace | Passed | Type generation/typecheck and local Next.js build; rendered decision UI, exact export preview, independent approval, verified evidence and cross-origin denial |
| Real service workflow | Passed | Review/citation, idempotent create, cross-tenant denial, modified/replayed approval denial, exact controlled export and signed outcome |
| Real recovery workflow | Passed | Simulated lost acknowledgement for a newly created synthetic job; owner reconciliation restores completion while manifest/receipt bytes and completion count remain unchanged |
| Installed database roles | Passed | Actual Go-role SQL cannot insert/mutate manifests, digests, outcomes, protected job context or approval decisions; Rust cannot update an existing manifest; legitimate runtime workflow succeeds |
| Worker boundary | Passed | Worker namespace can reach broker but not PostgreSQL/model/executor/Guard/evidence/OPA; only worker identity mounted |
| Controlled restore | Passed | Stop ingress then state writers; disposable PostgreSQL restore matches security/manifest/result/audit fingerprints, copied journal matches pinned checkpoint, both copied receipt stores preserve bytes and completed/not-started/unknown lookups; original data retained and services resumed |
| Terraform | Passed | Format/init/validate and four provider-mocked tests; no live AWS enforcement claim |
| Final audit-context regressions | Passed | Final kernel suite: 94 Rust scenarios, including manifest aliases and validated current approval context; final API suite: ten leaf scenarios including acknowledgement substitution and operation/phase fencing |
| Fresh source reproduction | Passed within stated scope | Separate source copy, fresh disposable schemas, newly compiled isolated offline/locked Rust target, Go race units and integrations; final Go-only changes rechecked from another empty source copy, with unchanged Rust proof retained; installed pinned toolchains/cached dependency sources and existing PostgreSQL/OPA services used |

The initial complete run restored 21 receiver records. Record counts grow as additional synthetic workflows run; they are observations, not a fixed acceptance threshold.

The final scoped runtime/contracts/policy/tests fingerprint is `cb4138d97cb1eb0a268b63d741e96ce1df44a994a07d33e15b7cbe359cf69b11`. The fresh-source report records the exact path/hash algorithm and staged commands, including the final Go-only rerun; it explicitly excludes a fresh host, Docker/UI/release/CI verification. Those components have separate local evidence.

## Release and deployment gates

| Gate | Outcome | Meaning |
|---|---|---|
| Source software inventory | Generated | Lockfile-derived CycloneDX SBOM, frozen-input hashes and local image identifiers in `.local/release-evidence`; this is not signed build provenance |
| npm application audit | Passed | No findings in the frozen application dependency tree; runtime-image findings are assessed separately |
| Vulnerability release gate | Blocked | Final control image, Rust dependency audit and npm application audit pass. Native Go feed access is blocked; final guard/workspace images retain unfixed OS findings. Reports fail the release gate rather than suppressing findings |
| Reusable environment configuration | Saved draft, inactive | Draft includes pinned contract-tool installation and proposed `vuln.go.dev` access; it still requires review/save/publication and does not change the active policy |
| Hosted CI | Unrun | Fresh-run workflow and artifact collection prepared; no push/hosted run performed here |
| Live GovCloud/Bedrock and customer identity | Deferred | User requested returning to these when the account/configuration is available |
| Production cryptography, retention and assessment | Unrun | Approved TLS/workload identity/cryptographic modules, independent key/checkpoint custody, storage controls, SSP and applicable assessment/authorization remain required |

Final image scans recorded **43 HIGH** OS findings in Guard and **one CRITICAL / 56 HIGH** OS findings in the workspace, with no published fix listed for the remaining HIGH/CRITICAL instances. The workspace critical is `zlib1g` / `CVE-2023-45853`, reported `will_not_fix`; no risk acceptance or production authorization is implied. Exact pinned Debian security patches and removal of unused runtime npm/corepack/yarn removed four CRITICAL and 20 HIGH instances from the initial workspace scan, leaving zero Node-package findings. The control image has zero reported findings. Native Go scanning could not reach `vuln.go.dev` under the active environment policy. Remaining vendor dispositions, image/runtime choices and successful feed checks are release work.

Final local images:

- Control: `sha256:188b579a0eafd46ac23d80c30319d32994ff1faffa0340cc22631e9331b8e15a`.
- Guard: `sha256:8c64a97d5316ef7c4d257bb444e312d98485a18220918a11ab6cba756fde4d84`.
- Workspace: `sha256:d9c525a99a2dbf420de27b5d7ee166843201970e7115df8affae78f1d7956265`.

Reproduce with `make dev` and `make verify-local` after installing the pinned tools/plugins described in the README. Run infrastructure checks with `make terraform-check` and `terraform -chdir=deploy/terraform test`. Release inventory/scans use `scripts/release-inventory.py` and `scripts/release-audit.py`; any nonzero/incomplete scan remains a release blocker.

Execution readiness checks state-schema and signer availability, with key format checks at startup. A valid-looking but incorrect remote service key/pinned public key is detected by authenticated append/signature verification before an execution grant commits; the health probe alone does not prove that remote key match.

The managed daemon uses VFS; builds compile Go/Rust on the host and package thin images. Preserve source, identities, receipts, data and referenced images when managing storage. A copied source/disposable-schema check establishes local reproducibility, not a fresh hosted runner or a production backup exercise.

## Retained local evidence index

Non-secret synthetic verification artifacts are retained in `.local/release-evidence/verification/` (ignored by Git), alongside the SBOM and scan reports:

- `nex-alpha02-verification.log`: initial complete local command, including policy/UI/role/network/recovery/restore results.
- `nex-alpha02-final-guard.log`: final 94-scenario Rust boundary/configuration/receiver run.
- `nex-alpha02-final-api.log` and `nex-alpha02-final-go-units.log`: final Go race tests, SELECT-only role, acknowledgement and completion-fencing checks.
- `nex-alpha02-terraform.log`: validation and four mocked infrastructure tests.
- `fresh-source-report.json`, `nex-fresh-source-final.log`, `nex-fresh-rust-build.log`, `nex-late-go-proof.log`, `nex-late-go-sql-proof.log`: staged fresh-source scopes, commands, fingerprints and local proof limitations.
- `final-runtime.log` and `final-runtime-report.json`: final real workflow/owner recovery/role checks, readiness and all six shared Go-image consumers matching the final image.
- Final control/workspace build logs and `evidence-index.json`: build observations and artifact hashes.

These local artifacts are not independently signed release provenance. No keys, private configuration or DSNs are included. Source and receipt data are retained; test-generated Python bytecode and only confirmed unreferenced prior images from this Compose project were removed to manage local storage.
