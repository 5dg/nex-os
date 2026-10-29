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

## First canonical execution failures and scoped correction

Published `5e0f6a34260ab909ab387d5271c8f80a16b71dc0` explicitly selected hosted
canonical run `40779933916`. Local run `b099720733b9` first failed because the
launcher forwarded an outer-only proxy hostname over Docker's reachable managed
proxy defaults. Its blocked bundle was retained. A normal-TLS pinned compiler
probe verified the existing configured proxy; local retry `45158dc3631f` used
those same enforced defaults without changing source, CA, network policy or
Docker configuration.

Both that local retry and the hosted canonical job compiled Go and the verified
gosu overlay successfully, then failed deleting read-only Go module directories.
No Rust compiler, application image or candidate runtime gate followed. Sealing
also encountered a legitimate gosu scratch symlink before excluding the scratch
tree. Raw local attempts remain unchanged; the hosted execution-metadata artifact
retained the incomplete candidate, build manifest and pipeline log despite the
missing full bundle. Its verified source identity matched the reviewed revision.

The scoped correction restores owner access only on directories inside the
original owned build scratch inode, uses directory file descriptors without
following links, and leaves file modes and hardlinked export targets unchanged.
Phase and final scratch cleanup share that path. Sealing prunes only the exact
two builds' unretained work/package roots before traversal; retained-tree links,
nonregular files and traversal errors still fail. These changes require a new
reviewed source and fresh candidate; earlier attempts are not resumed or relabeled.
An actual unprivileged regression reproduces the original permission error and
verifies both cleanup boundaries while external directory/file modes and
hardlinked export bytes remain unchanged. All **156** offline release tests
passed after the correction, including realistic gosu scratch links, retained
links and failed traversal. Independent review accepted the fixes; the full log
is `release-tests-readonly-scratch-retention.log`.

## Go scanner compatibility and finding enforcement

The completed `5e0f6a3` hosted foundation run passed functional, qualification and
Terraform checks, but its pinned `govulncheck` 1.1.4 crashed in old SSA tooling on
Go 1.27 syntax. This is distinct from the local advisory feed's network-policy
denial. The official 1.9.0 release, tag commit
`e672cbe8fbc8c76e28fcb6db0efd9ce354e0dac5`, uses `x/tools` 0.52.0 with explicit
Go 1.27 support. Independent proxy/SumDB evidence verified the module and module
manifest hashes. The installer checks both identities; Go remains pinned at
1.27.3. No downstream scanner overlay or reduced analysis level is used.

Actual compatibility cases exercise a promoted-field literal and an imported
vulnerable symbol against an explicitly synthetic local advisory database. The
reachable case has a real multi-frame call trace; uncalled and fixed-version
cases remain separate. They are scanner validation, not project advisory
clearance. The old binary and panic evidence are retained.

Those cases also demonstrated that JSON mode returns zero with reachable
findings. Release auditing now requires complete supported source/symbol JSON,
retains every finding, and blocks reachable vulnerable symbols independently of
the exit code. Malformed/incomplete streams and conflicting repeated advisory
data fail closed. Identical repeated advisory records are accepted because the
official emitter may report one advisory for multiple modules. Module/package
findings remain explicit in raw output and counts rather than being labeled
absent. Final source and actual-image scans still require fresh evidence.
All **162** offline release tests passed after the reviewed parser correction.
The actual end-to-end audit fixture blocks the reachable case despite scanner
exit zero, retains two lower-precision findings in the uncalled case, and passes
the zero-finding fixed-version case. Exact source/tool/raw-result hashes are in
`security/govulncheck-compatibility/validation-reviewed-record.json`; full test
output is retained in that directory's `release-tests-reviewed.stderr`.

The same hosted foundation image scans contained 793 retained finding rows,
fourteen fewer than the earlier diagnostic baseline: control and fixtures zero,
Guard 162, workspace 228, PostgreSQL 400 and OPA three. Supported fixes cleared
their advertised fixed rows; vendor findings were not suppressed. These were
host-build qualification images for `5e0f6a3`, not a completed canonical candidate.

## Measured OCI differences and hosted browser dependency

Hosted `50c1a4f` and `bdefbbc` completed both fresh builds. Native binaries matched.
The workspace and PostgreSQL runtime payload differences were confined to
`/var/cache/ldconfig/aux-cache`. Upstream glibc evidence identifies this as an
inode/ctime/size/device cache for accelerating `ldconfig`; the runtime loader
uses `/etc/ld.so.cache`. The bounded fix removes only the auxiliary cache and
asserts the active loader cache remains nonempty.

Required history-pagination, proof-parity, native shutdown and actual packaged
shutdown gates passed in those runs. Browser, combined qualification,
reproducibility and image vulnerability gates did not pass. Source scans with the
upgraded official Go tool completed against the live database with zero module,
package and symbol findings. These partial results do not qualify a candidate.

Actual probes also isolated OCI differences: unchanged OPA exports differed only
in an outer tar directory timestamp; authored APT layers contained variable
whiteout timestamps generated by Moby after RUN. The current Docker driver
accepted the rewrite option without applying it and rejected an explicit Docker
export destination. Generated COPY timestamps can be controlled, but RUN cannot
touch the later whiteout headers. No comparison target or security field was
excluded. A supported pinned exporter requires a separately bounded canary and
resource review before adoption.

Diagnostic checkpoint `89ac2a65f995459964ee200fac15d73ce6a81b9a` moved browser
startup ahead of cold compilation and retained explicit sanitized diagnostics.
Hosted run `40786456380` reported `BROWSER_SANDBOX_UNAVAILABLE` after 637 ms and
stopped before cold compilation. The lead approved the existing isolated-fixture
exception for this hosted synthetic runner. Native mode remains the default;
disabled fixture mode requires the exact reviewed run reference and matching
engine/image/output checks, with no automatic fallback. Read-only/capability
restrictions, private temporary storage, certificate validation and the full DOM
gate remain required. Thirteen workflow and ten preflight tests passed. Published
checkpoint `0297f7d676d75d56887307f98288c980fb01d031`, hosted run `40787853494`,
passed the actual early startup check with that explicit exception. Its full
candidate run subsequently failed: the DOM fixture reported
`BROWSER_FIXTURE_UNAVAILABLE` after 1.517 seconds, before driver results. Operator,
revocation, rotation and restore did not run. The startup preflight had passed
in 3.357 seconds; these are separate measurements. Metadata and origin artifacts
were independently retrieved and hash-checked, while full-subject retrieval and
signature verification remain blocked as described below. Browser startup alone
is not DOM qualification.

The connector refused the approximately 810 MB full subjects at its 512 MiB
limit. Smaller metadata and origin artifacts were retrieved and hash-checked;
the 579 KB failed diagnostic subject was also independently checked against its
artifact manifest and captured source. Strict signature verification first hit
an unwritable default cache; a supported writable cache exposed `Forbidden` from
the default Sigstore TUF endpoint. Both failures remain retained. No custom trust
root or successful origin/release-verification claim was substituted.

An isolated official BuildKit v0.34.1 exporter canary subsequently produced
identical raw archive, image configuration, compressed layer and uncompressed
layer bytes for both scratch and pinned-APT build pairs. Independent review
checked the actual archives, thirteen generated whiteouts and unchanged vendor
uncompressed layer bytes/diffIDs. The four raw exports are retained under
`buildkit-container-canary-1/execution/`; the APT pair SHA-256 is
`d3ad84437842a9c6e18c2f86660b359bf426b25af06b78699ca0a6c239cef387`.

The canary's later Docker-save check crossed its reviewed 4 GiB growth forecast
and stopped with more than 10.4 GB free. Its failed resource record remains
preserved. A separately approved bounded completion used the existing direct
exports, loaded the second APT image, verified its full configuration and seven
layer diffIDs, and prepared identical 84,012,544-byte archives with SHA-256
`667d0be55a9114a6f8d2675beacc2c5d9fa815086189d71828b760c3a5c69711`.
Completion used approximately 168 MB additional space, preserved the original
evidence inventory exactly, and normally removed only the inspected owned
builder container, remote profile and cache volume. Its acceptance, cleanup and
resource records are under `buildkit-container-canary-1/completion-1/`.

The producer uses the official export directly, verifies its loaded immutable
image, and prepares only outer tar timestamps; it does not rewrite configuration,
layer or filesystem payload bytes. Fresh per-image builder caches bound
accumulation. Canonical integration passed independent review and all 203 offline
release tests. Actual process regressions cover parent/child termination,
descendant-held pipes, low-disk/report failure and exact ownership. The second
build inherits only explicitly reviewed phase settings while retaining the fixed
measured admission formula. Measured final admission and a new two-build candidate
remain pending; canary success is not candidate qualification.

The hosted fixture failure exposed a separate portability defect: top-level
public CA creation requests mode0644 under umask077, while the fixture uses
UID1000 and the hosted coordinator has another UID. The early preflight projects
its public CA as readable; the full coordinator had mounted the original file.
Source2 diagnostics used coordinator UID1000 and did not exercise this boundary.
A controlled paired probe used the same immutable image, public CA bytes and
dependency driver: a UID1001-owned mode0600 CA failed in 506 ms with the same
fixture-unavailable code and no engine result; an equal-byte mode0444 copy passed
the real entry, engine and dependency driver in 4,438 ms. Original CA bytes,
owner and mode remained unchanged, and only exact owned probe containers were
removed. Evidence is in `browser-public-ca-mode-probe-1/acceptance.json`.

The browser coordinator now validates a single current public CA, projects only
those exact bytes into a fresh attempt-private mode0444 file, mounts it read-only
and records its hash against all three browser engines. Private keys and original
PKI permissions remain intact. Four focused regression cases cover projection
under umask077 and rejection of keys, mixed/multiple/non-CA certificates,
oversized input, symlinks and existing outputs. Independent code/metadata review
and the combined 207-test offline release suite passed. Cleanup review confirmed
active consumers and no additional justified deletion; D removed three unused
new-code assignments identified during that review. The combined test log is
`release-tests-candidate-export-browser-final.log`, SHA-256
`2730f40560e685a936bd8e249db24c4715162bc9706bde8200d3ba6acb33fe06`.
New source publication, measured admission, fresh capture and full captured-image
qualification remain required. No final-candidate or release-eligibility claim
follows from these component results.

## First complete reproducibility result and runtime corrections

Published `852269a64adfc41f01361bed639a7064dabdcd36` was captured locally as
run `3dde8e20ab27`, input digest
`8cec60744ca01104c027f00186f3c1ff27735a205dd72d5ca3a15c8346e04497`.
J independently matched all 21 published files, captured bytes/modes, source
companion and input map to the reviewed batch. The final source inventory has
447 components across all 27 dependency input hashes.

Hosted run `40790684153`, candidate `161e1a70f135`, completed both independent
builds and passed native binary, all-six runtime payload, OCI configuration/layer
and emitted archive comparisons. Raw OPA Docker-save differences remained
separately reported with exact outer-header transformation proofs. This is a
measured reproducibility pass for that source, not functional qualification.

The local first build passed all four cold compilers and control, Guard,
fixtures and workspace packaging. PostgreSQL crossed its declared 4 GiB phase
growth forecast and stopped safely: sampled growth was 4,335,747,072 bytes, and
the exact owned daemon stopped in 1.09 seconds. No second build or application
stack was admitted. The failed attempt was sealed into a 220,731,254-byte bundle,
SHA-256 `4f27d30fe73df38c7be8a787623735e650696b7b465aa2a884b56d97a9c951eb`.
The original reserve remained intact. Any revised PostgreSQL budget requires
measured capacity and a fresh run; old compilation outputs cannot be resumed.

Hosted qualification then failed during migration. Actual control/fixture
payloads showed mode0444 on `/etc`, `/etc/ssl` and `/etc/ssl/certs`: the public
CA file's COPY permission had also applied to its newly created parent chain.
The nonroot process could not traverse `/etc` to read Docker's resolver file,
so the Go resolver fell back to localhost. An isolated run of the exact captured
control image under UID65532 reproduced `EACCES` on the CA and resolver paths
without making a DNS request. Native/browser/recovery gates were not executed.

The bounded correction stages only the frozen public CA in a fresh runtime-root
tree, explicitly sets directory traversal and read-only certificate modes, and
copies that tree into both scratch images while retaining their nonroot user.
Nine focused layout regressions passed independent review. A fresh diagnostic
image exported and loaded by the official backend then passed the actual
UID65532 probe: parent modes0555, public CA0444, exact CA hash, readable CA and
Docker resolver file, with no DNS query. Its receipt is
`runtime-root-probe-results-1/acceptance.json`, SHA-256
`e7587c601e5c121dfc09d9264084069ed77f9d44b2e4e0b8c6e1db4285a94d78`.
Only its exact owned reader, builder, profile and cache were normally removed.
The original failed capture remains preserved.

Failed-phase analysis also exposed discarded buffered command output and a
termination exception swallowed by Python's selector polling. The packaging
helper now retains canceled public output once, hashes private output, preserves
the original failure cause through logging errors, and reaches owned cleanup on
actual termination during communication. Nineteen focused process tests passed
independent review. The combined 220-test release suite passed in 38.963 seconds,
log SHA-256 `2d1b3a5e14ac4d796b5cf15a3fd40291588c91ef15048d48878c6d751b4c7da3`.
An earlier mock startup test hit its 20-second harness deadline under load; that
failed run and the unchanged isolated ten-test pass remain retained. Cleanup
review matched all six frozen source files and found no additional justified
deletion. These tooling fixes preserve all qualification limits. Publication,
fresh capture, measured PostgreSQL admission and full qualification still follow.

Source Go, Rust and both npm audits passed in the hosted run. Its foundation
images retained 793 finding rows; exact canonical scan data remains in the full
subject. The 819,937,286-byte subject again exceeded the connector's 512 MiB cap.
Successful small downloads return a file ID rather than a local path, and their
next download stage has a separate documented 32 MiB limit. A roughly 400 MiB
compressed subject would still exceed that stage; no such large second-stage
attempt or successful full retrieval is claimed. No compression, chunking,
external release service or alternative trust mechanism was added for this.

## Hosted workflow acceptance and cross-environment follow-up

Hosted `4f27015bf042890f5b99fa473c630fa46f0c9fc2`, run `40793940587`, candidate
`98e474b7f9e0`, completed all functional gates and both fresh-build comparisons.
The source-input digest was
`baf59d7a7d456849313e2a2a3efc873fb621eb2c61146657411b24ca9dd4c422`.
Independent F/G reviews verified 315 source hashes, twenty retrieved artifact
hashes, gate commands/image bindings and the actual ordered wrapper's rotation
and restore completion. The browser passed twelve DOM, five operator and three
revocation assertions: one automatic cycle maximum, zero healthy-delay errors,
1,519 ms drain, signed-read growth three within the predeclared five, and 151
signed records / 136,689 bytes across five stable pages with exact prefix
preservation. All three engine trust hashes matched the public projection.

The local first build completed all six images, including PostgreSQL with a
6,438,526,976-byte phase peak. The second build was blocked before any compiler
command: unchanged measured admission required 12,428,763,136 bytes and only
11,460,579,328 were available. Its sealed record was preserved, without a floor
waiver, metadata-only retry or reuse of failed outputs. This remains separate
from the completed hosted cohort.

Additional cross-environment comparison found differences that the passing
hosted pair cannot resolve: all twelve native binaries and four complete image
archives/configurations/layers/payloads matched across environments. PostgreSQL's
merged payload matched while its OCI bytes differed; workspace payload and OCI
bytes differed. The old hosted payload path maps were unavailable in the large
subject, so no blanket equivalence or causal attribution was claimed. Local
scans retained 793 findings with exact image applicability; they cannot stand
in for a different hosted workspace image.

Investigation found an unbound frontend resource setting: pinned Next derives
its default worker count from host CPUs and serializes it into runtime config.
The actual local image contained four in both server and required-files config.
An actual framework-loader regression confirmed defaults of four and sixteen
under simulated five- and seventeen-CPU hosts. Explicitly selecting two now
produces identical complete serialized configurations while preserving headers
and build-ID validation. The builder also explicitly selects and verifies the
native snapshotter instead of leaving filesystem selection automatic.

The real pinned-daemon probe verified one OCI/native worker, BuildKit v0.34.1
revision `f5b59a1f2fb25a0cb7072c398cab9aed7835da4e`, disabled CDI and the copied
configuration hash. It built no product image and performed no application work;
its exact owned resources were normally removed. Evidence is in
`native-worker-probe-results-1/`. PostgreSQL's default and reviewed minimum
forecast are now 8 GiB because the earlier successful 6 GiB run left only
3,923,968 bytes below its phase cap. The reserve and measured second-build
formula remain unchanged.

Four exact public payload maps are added to the separate diagnostic artifact,
with a pre-upload raw/ZIP size and file-safety budget below the tool's 32 MiB
download limit. Current projected metadata is approximately 8.83 MB. This does
not replace the complete signed subject or relax its verification. Ten workspace
tests and fourteen workflow tests passed; independent source review accepted
the resource/metadata changes, and all 226 offline release tests passed in
29.381 seconds (log SHA-256
`65c0a2a212bba41b383e3dca84cb99e36da19de8ae2550e8d9a0126766b82a76`).
The changes require new publication, capture and an actual cross-environment
comparison. Existing mismatches, vendor findings, TUF denial and full-artifact
retrieval limits remain retained and unresolved at this checkpoint.


## Final captured candidate decision — 28 October objective

Selected implementation `16edb6a68ca2a91770239c7220acb670d2d080d1` passed the complete hosted functional verifier and fresh pair in run `40798668756`, candidate `2895df3aa4df`, input `54e9f209b74b18aef885be997aca8c0521da580356287377253178da247e0c48`. Independent E/F/G reviews verified the available retained records, including all twenty browser assertions, required native/history/packaged lifecycle gates and ordered rotation/restore completion. Raw inner artifacts remain outside the independently retrieved metadata.

Fresh local first build `edbcc110b45d` completed with observed exit 0. All twelve native binaries and six actual archives/configurations/encoded and uncompressed layers match both hosted builds. All six complete filesystem maps were regenerated from archive bytes; downloaded workspace and PostgreSQL maps match exactly, with zero differing paths. A brief transport outage recovered without restarting the builder. Required disk reserves held. No local second build or local combined verifier was claimed.

The exact six local canonical images were scanned and independently bound to both hosted manifests. All 47 scan/SBOM files are retained; 793 finding rows remain, including four critical and 168 high, without waivers. Fourteen earlier cleared rows comprise nine Go-binary and five OS rows. Origin production succeeded, but independent signature verification and full retained-subject verification remain blocked by actual delivery limits and default trust-service access. The complete subject was uploaded but not independently downloaded or verified.

The [final gate decision](ALPHA04_RELEASE_DECISION_2026_10_28.md) and [public evidence index](ALPHA04_RELEASE_EVIDENCE_2026_10_28.json) separate implementation, synthetic functional acceptance, measured reproducibility and blocked release eligibility. Any documentation commit publishing this report is distinct from the tested implementation above. Production dependencies remain explicit; project completion is not claimed.
