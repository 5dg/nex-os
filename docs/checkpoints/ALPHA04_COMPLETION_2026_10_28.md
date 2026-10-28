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
