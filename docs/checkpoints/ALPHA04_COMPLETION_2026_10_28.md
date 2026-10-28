# Alpha 0.4 completion execution — 28 October 2026

Starting source and verified remote main: `341b0ceab13a79f13ed0f2eee89f2b80824bba49`.
This is an execution record, not a declaration of candidate qualification.
The [completion objective](../FINISH_GOAL_2026_10_28.md) remains active.

## Delivery and qualification checkpoint

Implemented a pinned-Next standalone packaging contract that removes unused
Server Action randomness and disables unused preview/revalidation without a
public secret or comparison exclusions. It requires the current app's absent
feature surface, known formats and unchanged frozen framework version; future
feature use fails packaging. See the [release contract](../architecture/ALPHA04_RELEASE_CONTRACT.md).

Added a required `packaged-shutdown` gate to candidate execution, sealing and
retained-artifact verification. Its real-service harness covers Guard, model,
export executor and control with actual workflow identities, independent export
approval, held existing-operation locks, SIGTERM, direct admission probes,
restart and receipt/protected-result/evidence checks. Runtime execution remains
pending at this checkpoint; compilation is not acceptance.

Source security inventories now include the isolated browser lockfile and
Dockerfile. Both npm packages are audited separately with lockfile-only,
script-disabled commands. Inventory regressions require those inputs and retain
their distinct dependency-source annotations.

Executed before publication:

- 67 offline release tests passed, including pinned packaging, actual framework
  helper behavior, required retained-gate negatives and browser-inventory tests.
- An isolated copy of the actual pinned Next standalone rendered workflow and
  session routes, rejected unknown/malformed actions and crafted preview/
  revalidation requests, and changed no packaged files at runtime. This is a
  diagnostic standalone check, not a fresh canonical build or full DOM pass.
- Packaged lifecycle integration source compiled with race instrumentation;
  relevant shell syntax and whitespace checks passed.
- Approved npm audits reported zero vulnerabilities for 101 workspace and one
  browser-fixture locked dependency; lockfiles were unchanged.

Local non-secret evidence is under `/workspace/nex-completion-20261028/`, including
`release-tests-current.log`, `packaging-proof/` and `security/`. These files are
local engineering evidence; durable hosted retention is not established.

## Runtime preflight and external dependencies

The inspected runtime uses VFS, five CPUs and sufficient initial reserve. Exact
pinned Go/Rust compiler pulls succeeded and matched their requested digests.
An earlier CLI manifest-inspection error was not reproduced by actual pulls.
The inspected `10.231.0.0/20` candidate pool did not overlap existing Docker
networks or host routes. Previous development state/images remain preserved.

The preserved development stack restarted successfully without a rebuild to
support isolated source integration tests. This does not qualify current images.
Each final build still requires measured resource admission and a fresh candidate.

`api.github.com` and `vuln.go.dev` returned proxy CONNECT 403 under the enforced
network policy. Hosted Actions/attestation/artifact verification and complete Go
advisory checking therefore remain blocked. Git publication and npm registry
access do not establish those gates. The earlier npm egress approval rejection
was resolved by explicit user consent; the approved audits then succeeded.

Canonical builds, two-build comparison, full current-image DOM/service checks,
packaged lifecycle execution, rotation/restore and actual-image scans remain
unrun at this checkpoint. No engineering-complete, reproducible, attested,
release-eligible or production-ready claim is made.

## Bounded history and workspace checkpoint

The compatible opt-in history endpoint now returns a stable, authenticated
cursor page, capped at 32 events and 96 KiB. Legacy arrays remain available within
the bound and otherwise return a typed pagination-required error. Snapshot
visibility excludes later commits and the new audit rows created by traversing
pages. Paginated signing-sequence order and central same-job write locking close
the earlier-transaction timestamp ordering issue without changing old event
timestamps, signatures or legacy array ordering.

The workspace now renders job state independently of history, provides explicit
continuation/refresh controls, schedules a single automatic read cycle at a time,
backs off errors and invalidates obsolete job/identity responses. The BFF accepts
a scoped `event_page` operation without changing historical `events` callers.

Independent PostgreSQL source integration passed with race instrumentation:
195 events / 168,509 encoded bytes across seven bounded pages, signatures,
stable snapshot exclusion, cursor integrity/scope/expiry, same-token permission
and delegation revocation, legacy oversized refusal, malformed historical sequence
data and a real earlier-started transaction appending after the prior signed
prefix. A first fixture incorrectly assumed an event timestamped 30 seconds ago
must be oldest after approximately 49 seconds of signing work; that failed attempt
is retained. The corrected test traverses the complete fresh snapshot and checks
exact membership rather than making that wall-clock assumption.

Workspace unit/security checks and type checking passed. Independent browser
acceptance helpers reject reordered/substituted history, oversized pages, overlap,
unexpected errors and excessive read growth. Real DOM drivers now include long
signed history, stale-job response, history failure/recovery, terminal polling,
in-flight logout and same-session revocation cases. Actual browser execution
against the new packaged source remains pending at this checkpoint.

## Maintenance, hosted CI diagnosis and current source scans

Removed the unmaintained `rustls-pemfile` dependency using the existing Rustls
`pki_types::pem::PemObject` API, with no new crate or cryptographic implementation.
Certificate-chain order, first PKCS#1/PKCS#8/SEC1 key selection and the existing
workload identity/key checks remain. All 12 Rust tests passed, including three
malformed-input/key-format regressions; formatting passed. The updated lockfile
audit reported zero vulnerabilities and zero warnings against the same current
RustSec database. The earlier maintenance warning is retained in its original
scan record.

Explicitly approved read-only Go metadata resolution completed without changing
Go lock inputs. The current-source SBOM contains 445 external components: 67 Go,
276 Cargo and 102 npm, including the isolated browser dependency. It must be
regenerated for the captured final source. Go advisory scanning reached the real
feed and received Forbidden; that gate remains blocked rather than clean.

Connected GitHub tools established actual hosted status despite the cloud shell's
API restriction. [Run 40769426263](https://github.com/5dg/nex-os/actions/runs/40769426263)
for `6fe65018dda7b09b25b4519e9955970f6dc66e31` failed in static checks: positive
custody fixtures assumed Go's `t.TempDir()` was private. Go 1.27 creates those
directories subject to the process umask; hosted `022` exposed mode `0755`, while
the local default `077` hid the assumption. The failure was reproduced locally.
Positive fixtures now use private child directories created by the production
constructor. Production permission rejection is unchanged. A regression verifies
the public parent remains unchanged while the child/lock are `0700`/`0600`.
All Go unit packages passed again with race instrumentation under umask `022`.
This local correction does not establish a successful later hosted run.

The isolated host-image packaged lifecycle diagnostic passed: actual Guard,
model, executor and control shutdown/drain/restart with real protected effects,
independent approval and unchanged replay receipts. Its approximately 12-second
run belongs to diagnostic input
`9c7bd0d57f125f2da92393e8502da7882b53bc6bc987c7579217e63074432905`,
which precedes the PEM maintenance change. Final images must repeat it.

The real browser fixture's native sandbox probe failed with a namespace permission
restriction. The lead approved sandbox-disabled execution only for this isolated
synthetic cloud fixture, retaining read-only/capability restrictions, private
storage, frontend/issuer-only links and normal certificate validation. The
effective mode is recorded; no production browser or TLS bypass is implied.

## Candidate tooling and supported security remediation checkpoint

Published Go dependency changes in
`abbe8188885b9140ac0185ae19d9ee4f8d8737e1` target the image scanner's JOSE and
network-library findings: `go-jose/v4` 4.1.6 and `x/net` 0.62.0, plus only their
required indirect updates. Targeted auth/trust/contract checks, the full uncached
Go race suite under umask `022`, and module verification passed. A rebuilt-image
scan is still required before calling those image findings resolved.

Current tooling adds measured, externally predeclared second-build admission,
the required native history-pagination gate, trusted-main hosted opt-in, and
separate gosu-overlay inventory. The gosu overlay preserves verified upstream
code while updating frozen dependencies. Signed-repository probes confirmed the
exact available Debian package revisions before image pins were updated. These
source changes are not substitutes for image behavior or fresh scan results.
All 95 offline release tests passed before this checkpoint, covering those
contracts, CI event/admission behavior, inventories and packaging negatives.

Connected hosted status now distinguishes two actual attempts. The custody
fixture correction allowed static checks to pass on `e08ad9f`; its subsequent
development build failed because newer Compose delegated to Bake, which required
an additional filesystem entitlement for the public CA secret. The scoped
compatibility fix disables only that optional delegation for the owned Compose
build call; BuildKit, the secret mount and certificate/signature verification
remain. An actual-script regression passed; a later hosted run is still required.

Browser TLS diagnosis measured an inherited-proxy problem, not a certificate
validation success: both trusted and untrusted test hosts initially returned
`ERR_PROXY_CONNECTION_FAILED`. An exact browser-only internal hostname bypass
restored strict `ERR_CERT_AUTHORITY_INVALID` for the wrong root and HTTPS 200 for
the trusted workspace. A normal source2 diagnostic then passed wrong-CA, trusted
render and OIDC login assertions, but document-scope acceptance still failed.
Safe follow-up probes confirmed the documents API returned 200, the permitted
option was selected and the other tenant's option was absent. The exact label
locator matched no control while the unique Document-prefix combobox matched
one; the drivers now use that observed accessible name and preserve the scope
checks. Full workflow execution remains pending; no full browser pass is claimed
here. Failed attempts, isolated probe results and separately hashed
diagnostic drivers remain retained. Canonical source verification is unchanged.

Six complete diagnostic-source1 image reports contain 807 finding rows, including
cross-binary/package repeats. Raw reports, all severities, vendor statuses and
SBOMs are retained. Supported fixes are being applied; remaining vendor findings
without published fixes are not suppressed or waived. The latest official OPA
release still contains the affected network dependency, so no verified fixed
vendor image was substituted. Final candidate image scans, complete ordered
qualification, two-build measurements and hosted artifact verification remain
required. Release eligibility remains blocked.

## Browser acceptance and final build-boundary corrections

The separately hashed source2 diagnostic drivers now pass the complete rendered
workflow and operator regressions against the preserved diagnostic images. Alice
signed in, reviewed the admitted document, requested its exact export, signed
out, obtained independent Carol approval, and resumed the recorded result.
Chromium and the Node request client both accepted the intended public fixture
root and rejected the foreign root. Node receives that same read-only public CA
through `NODE_EXTRA_CA_CERTS`; certificate validation remains enabled.

The healthy 2.5-second delayed-response test observed at most one automatic job
read in flight, zero errors, a 1,591 ms drain within the unchanged five-second
budget, and three new signed reads within the predeclared bound of five. The
exact ordered signed-history prefix was preserved. Operator assertions passed
terminal polling, history failure/recovery, job switching with zero obsolete
writes, and logout with an in-flight response. Genuine authorized reads produced
a 136,699-byte signed snapshot: 151 rendered events across five bounded pages,
with complete stable traversal and exact prefix/order checks. Evidence is in
`direct-browser-source2-attempt3/{dom,operator}/browser-results.json` under the
local evidence root. This source2 diagnostic predates the latest dependency and
build changes; it cannot qualify final candidate images.

The final build-boundary correction compares every captured workspace file's
bytes, mode and regular-file identity against both the original capture and the
actual staged tree, before and after `npm ci`. Only the exact generated root
`node_modules` is permitted after installation. The canonical copy no longer
silently excludes nested authored names. Thirteen actual-verifier regressions
cover mutations, missing/injected files, symlinks, modes and capture binding.

Hosted run `40774852003` on `018e94e` passed static checks, built the application
images, migrated and seeded, then failed because the fresh runner had not fetched
the pinned external OPA image before offline startup. The supported development
launcher now explicitly pulls only that existing pinned OPA reference after its
build. Four actual-launcher tests retain pull-failure refusal and offline restart
behavior. A successful later hosted run is still required.

Same-session browser revocation subsequently passed both committed authority
changes. Permission and delegation requests returned typed denials while the
original session remained unexpired. Coordinator acknowledgements arrived in
543 and 686 ms, within the unchanged 20-second bound. Job/operation and receipt
snapshots were byte-equal across each denial, the original authority hash was
restored exactly, and all twelve application image/container identities remained
unchanged. The independently reviewed evidence is in
`direct-browser-source2-attempt4`. The prior trust-maintenance rotation preserved
the signing key, fourteen receipt bytes, existing proof prefixes and effect
counts; it was operational maintenance, not final rotation acceptance.

All 111 offline release-tooling tests passed after these browser and build
corrections. Final fresh canonical builds, complete ordered current-image
verification, reproducibility, refreshed image scans and hosted
provenance/retention remain separate required gates. No final candidate or release
completion is inferred from these diagnostic passes.

## Independent gate-recording and retention review

Pre-capture review found that an outer recorded command could overwrite child
gate records with its earlier manifest snapshot. The recorder now reloads after
execution, preserves the existing result prefix and newly appended child
results, and revalidates source/archive/run/build bindings and tested binary
bytes. Substitution fails without overwriting the changed manifest; a separate
attempt record and log remain. Actual nested CLI regressions cover native and
DOM children, parent/child failures, erased results and source/build substitution.

The canonical pipeline now rejects contradictory inherited build, project, run
or state identities before runtime admission, then explicitly selects the first
build and primary stack. Actual-shell tests verify rejection and failed-attempt
retention. Independent service review accepted both corrections and confirmed
native fixtures, packaged lifecycle and ordered DOM/revocation/rotation/restore
gate wiring. All **127** offline release-tooling tests passed after the final
corrections; the full log is `release-tests-nested-gate-fix.log`.

Connected GitHub artifact retrieval independently downloaded the ordinary
`018e94e` foundation artifact: 135,530 bytes, SHA-256
`b0f0ab817bbe2b7194301fe774411445056b245c223289c22043859eb6abb01f`
matched both GitHub metadata and the upload log. Its source/SBOM identity matched
that revision and its incomplete security gates remained blocked. It was not a
candidate artifact. The origin job now also retains its successful pinned
attestation action's signed bundle as a separate artifact, preserving the exact
attested subject. This enables independently retrieved bundle verification with
the existing pinned cryptographic verifier; it does not replace completed-run,
source, signature, retained-consumer or security checks.

Original polling/history defects were identified from source. A subsequent
network-isolated Chromium probe executed the unchanged `640ce8f` React component
with explicit fake API responses: a 2.5-second delay produced three automatic
reads and maximum concurrency two in the fixed 6.5-second window. The original
source/compiler/bundle hashes and observations are retained under
`original-ui-reproduction-runtime-2`. This reproduces the original UI overlap;
the same attempt failed before stale-write/history observations and did not run
the original BFF byte cap. It is a UI baseline measurement, not service, TLS,
authorization or signature qualification. Final canonical execution and hosted
qualification remain pending.

## Final phase-capacity admission

Measured diagnostic runtime layers require a separate post-build forecast.
Qualification now checks a reviewed 6 GiB addition plus the unchanged 2 GiB
reserve on actual Docker/output filesystems, grouping shared devices, both
before supplemental browser packaging and immediately before stack startup.
Host and temporary filesystems retain 2 GiB independently. The 6 GiB value is a
conservative reviewed forecast, not a measured final-run guarantee.

Every bundle path, including failed-pipeline retention, verifies the exact sealed
file list and computes a conservative archive bound from actual tar/PAX headers,
logical sparse-file sizes, padding and gzip expansion. A capacity denial records
source/run/build-bound observations without opening an archive or deleting prior
evidence. Output symlinks are rejected and exclusive creation protects a target
introduced after admission. Independent review accepted boundary, incompressible,
sparse, mutation and failure-retention regressions.

Hosted execution metadata now has a separate explicit non-secret allowlist
artifact, so admission decisions and incomplete manifests remain retrievable even
when capacity blocks the full bundle. Private state, keys, backups and compilation
trees are outside that allowlist. These metadata bytes are separate from the
attested subject and establish neither signature verification nor release
approval. All **146** integrated offline release-tooling tests passed after this
final batch; `release-tests-final-bundle-output.log` retains the full output.
Final canonical execution remains required.
