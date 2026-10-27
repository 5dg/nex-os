# Alpha 0.3 executed evidence and remaining gates

Status dated 2026-10-27 UTC. The synthetic workflow and lifecycle checks below passed against actual local Go/Rust/TypeScript services. This is not release approval, cloud enforcement evidence, FIPS qualification or FedRAMP/NIST/CMMC authorization.

## Candidate identity

The tested application images were built from captured local main commit `cecec1a87fe967e6c1e5bc5a9243b0d70a7c2c83`. Every compiler input was checked against the immutable source archive; the sorted path/hash map digest was `8302c5235f5fff6979b8c07feb71f45374161dd49ccc6678c7cc688ef3093a79`. Go/Rust application binaries were built on the pinned host toolchains; the workspace was built inside its pinned Node container. This functional candidate has recorded host ABI/compiler/binary identity, not a reproducible release attestation. The pinned Rust container-builder path remains unexecuted.

| Image | Tested image ID |
|---|---|
| `nex-control:qualification` | `sha256:1fcf70560e330305417667106bb0b7980af8fd3c6182f7454044747e6a874a81` |
| `nex-guard:qualification` | `sha256:91d817d5c5699351175b4516ff2e75ded1f194eebab9cbc1a3bdce187dbd59fa` |
| `nex-workspace:qualification` | `sha256:a3cea7cb5eb3ce2ad820c3ab4cc153a1bfc82b472fe326aa397eaff5c058db33` |
| `nex-qualification-fixtures:local` | `sha256:346a575b62bf3ecffdb168a0d7ad06242c96539942510c000af214008a743a23` |

Later changes removed one unused stored TypeScript configuration property and corrected/strengthened test harnesses, deployment lifecycle coordination and evidence tooling. The application images above were not silently relabeled as builds of those later sources. The subsequent PostgreSQL security image `nex-postgres:qualification` is `sha256:e5853251529f836255ff6c567028a875d32a0b6ab59c1f771f71da7ebd55b597`, built from Dockerfile SHA256 `8e0542b8f3f7472107fff7790285ee4842a86cf6e5035eb4774c114587e15d80`. It preserves the pinned PostgreSQL 17 base/entrypoint and records exact gosu 1.19 source revision/archive/checksum verification, rebuilt using pinned Go 1.27.3. Debian OpenSSL/libssl3 were updated to exactly 3.0.22-1~deb12u2 through signed HTTPS repositories.

## Actual executed checks

Durations below are Go `-race` harness timings. Rust and TypeScript services exercised by those harnesses are not race-instrumented. PostgreSQL certificate validation is scoped to connection establishment; these checks do not establish continuous certificate revalidation of an already pooled database connection.

| Check | Result |
|---|---|
| Whole-repository Go race tests; component Rust checks/tests; workspace type/security/build checks | Passed. Component compilation alone was not treated as full-stack evidence. |
| Verified PostgreSQL TLS 1.3, minimal runtime roles, wrong CA/DNS and plaintext refusal | Passed, Go `-race` harness: 1.181s. |
| Disposable-schema seeding with changed body/hash/class/version/kind | Passed, Go `-race` harness: 1.913s; mismatches denied with rollback, existing content retained. |
| Browser/API review → approval → export | Passed, Go `-race` harness: 6.682s. Actual Rust authorization, Carol approval, exact returned artifact bytes/hash and independent event signatures; access-token versus ID-token, CSRF/origin/session and workload-role negatives. |
| Kernel current-authority mutations | Passed, Go `-race` harness: 8.077s. One real Model-role authorization control and thirteen denied changes to route/catalogue/admission/source authority, restoring each case without invoking a receiver. |
| Established/awaited transport expiry | Passed: reused Go HTTP/1.1 caller/server leaf expiry; held model response-body leaf expiry; warm Go→Rust gRPC calls held across caller-leaf or OPA-server-leaf expiry; Node responses held across peer-intermediate or own-intermediate expiry. Positive controls and denial after actual awaited bodies were verified. No Rust intermediate-expiry or PostgreSQL per-query-expiry case is claimed. |
| Actual receiver readiness | Passed. Six POST readiness calls each to model/export: healthy before/after, exact HTTP 401 for wrong key/execute audience/status audience, exact HTTP 400 for malformed nonce. No operation endpoints; independent execution-row and receipt/journal hashes unchanged. |
| Coordinated PKI rotation | Passed, Go `-race` harness: 68.296s. Typed old-CA rejection, old unexpired session HTTP 401, fresh login, same completed protected job/result, signed historical timeline prefix and receipt/journal bytes/signatures preserved. |
| Post-PostgreSQL remediation regression | Passed, Go `-race` harness: 7.556s. Browser/API completed a new real review, independent approval and exact export; native PostgreSQL TLS/role positives and wrong-CA/name/plaintext negatives passed on the retained restored volume. |
| Quiescent isolated restore | Passed, Go `-race` harness: 82.329s. New restore project and PostgreSQL volume; source writers stopped and source state retained. Fresh authenticated application returned the prior completed export result and independently verified historical timeline/custody. |

The first rotation assertion incorrectly required equal timeline lengths despite legitimate signed `document.read` events emitted by authenticated job/timeline reads. Its failed log was retained. The corrected check requires an exact historical prefix, verifies every appended signature and restricts additions to the expected Alice/control/document-read context; the fresh-session rerun passed. No production behavior was changed to satisfy that assertion.

The combined `scripts/verify-qualification.sh` wrapper was syntax-reviewed and wired into CI; its constituent steps above were executed individually. The combined wrapper itself was not run during this local validation; current hosted CI status is unverified because its API lookup is forbidden in this environment. It is deliberately one-shot and refuses an existing restore state.

## Operational observations

PostgreSQL initially required copying HBA into its private runtime directory with correct ownership. Interrupted initialization was recovered by creating only the missing expected database; no cluster or volume was reset. On this Docker daemon, internal-only networks suppressed actual published listeners. Fixed loopback raw TCP relays preserve private networks and end-to-end verified TLS. Rotation force-recreates all peers and PostgreSQL so new PKI files are remounted. Source and restored writer sets are never run concurrently.

Docker VFS exhausted the filesystem during workspace image construction. Removing only unused reproducible build cache recovered headroom; application data, keys, receipts, images in use and both PostgreSQL volumes were preserved. The workspace image build completed successfully. The PostgreSQL security-image first build failed because APT's unprivileged downloader could not read a default 0400 public CA secret; the targeted retry uses an ephemeral 0444 public trust bundle without disabling TLS or signatures. Failed logs are retained.

## Release gates remain blocked

Fresh qualification scans inventory actual application, fixture, PostgreSQL and OPA images, retain every severity and emit six OS-inclusive CycloneDX inventories. Native Go advisory access failed with HTTP Forbidden. Rust/npm/control/fixture scans passed. Initial scans found Guard 43 high; workspace 1 critical/56 high; PostgreSQL 4 critical/96 high; OPA 1 unknown. The PostgreSQL remediation eliminated exactly 1 critical/27 high with published fixes; its new scan retains 3 critical/69 high, all without published fixes, plus other severities. The default unused upstream snakeoil key is also retained as an unresolved scanner finding. The fresh tmpfs database boot, gosu privilege drop, native verified TLS 1.3, existing restored-volume boot and exact all-application-data hashes before/after passed. The old scan was preserved separately from remediation evidence. No severity filters, ignore files or waivers were introduced.

Actual live GovCloud account/model/customer identity, approved cryptographic modules, application infrastructure, operational controls and required assessments remain deferred. Historical main push attempts were rejected with HTTP 403 for the then-presented GitHub identity `getmoneyjj`. Publication subsequently succeeded, as recorded below. No authentication workaround or force push was used.

Raw test/build/failed-run logs and private runtime evidence remain local under `/tmp/nex-alpha03-*` and ignored `.local/qualification-release-evidence`, with consistent private backup evidence under `.local/qualification-backups`. Runtime credentials, PKI keys, receipts and backup contents are not committed. See [BUILD_PLAN.md](BUILD_PLAN.md) for the development path and [QUALIFICATION.md](runbooks/QUALIFICATION.md) for ordered operations and limits.

## Publication update — 2026-10-27 UTC

A normal push to `https://github.com/5dg/nex-os.git` succeeded. The remote `refs/heads/main` was independently read with `git ls-remote` and matched `5b7b34e5a540d21b47b5578123ca7d65953123de`. The earlier HTTP 403 errors remain historical evidence, not a current publication blocker. This source commit contains the exact candidate disclosures above; publication does not rebuild or requalify those images.

Hosted Actions status is **unknown**, rather than assumed unrun or passed: a read-only `gh run list` request for this repository returned `Forbidden` from `api.github.com`. Native Git publication and API access are separate observations.
