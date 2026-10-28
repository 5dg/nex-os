# Next goal: Alpha 0.5 synthetic release qualification

Reviewed against published `main` through `56adf29` and the current authored
working tree on 2026-10-28. This is the next execution goal, not a statement that
unfinished code, candidate builds or release gates passed. Preserve the
[Alpha 0.4 plan](NEXT_GOAL_ALPHA_0_4.md), [operation boundaries](architecture/ALPHA04_OPERATION_BOUNDARIES.md)
and [release contract](architecture/ALPHA04_RELEASE_CONTRACT.md).

## Goal

> Deliver one independently verified synthetic release candidate of Nex.os:
> captured source, fresh pinned builds, immutable image identities, real browser
> and service qualification, reproducibility measurements, complete security
> evidence and an explicit release decision all refer to the same candidate.
> Finish the remaining Alpha 0.4 work before starting Alpha 0.5 product expansion.
> Keep a dedicated agent publishing audited checkpoints to `main` and a separate
> agent removing confirmed dead code behind completed changes.

The Go control plane, Rust governance kernel and gRPC boundary remain the right
implementation foundation. The next improvement is proving the complete delivery
path and its integrity, rather than adding another subsystem. This goal permits
only bounded fixes demonstrated by qualification or integrity failures.

## What the current code establishes

| Status | Grounded result and practical limit |
|---|---|
| Published | `ada368e` binds Rust acceptance to the exact submitted signed evidence content; existing Go-produced v1 bytes/signatures and v2/v3 history remain compatible. |
| Published | `1819277` rechecks the original HTTP caller across awaited operations and commit/dispatch boundaries. Four independent expiry/cancellation cases passed, including actual worker `{}` disconnect handling. |
| Published | `25c7d68`, `958e775` and `56adf29` remove independently reviewed unused fields/declarations. These are source checkpoints, not proof that later images were qualified. |
| Implemented and locally exercised; candidate qualification pending | Real qualified TLS SIGTERM/admission/drain, a real PostgreSQL held-grant/restart/no-repeat fixture, post-dispatch unavailable classification and bounded RPC saturation/cancellation tests passed against explicitly identified diagnostic source/binaries. They do not establish a complete packaged release. |
| Authored/in progress | Candidate capture, clean-archive identity, canonical builds, isolation, evidence indexing, provenance consumption and browser tooling/drivers exist in the working tree. Some independent integrity negatives passed after fixes. Full closure and execution remain required. |
| Not established | A complete fresh canonical build/ordered verifier, two-build reproducibility, actual DOM workflow/polling measurement, same-session DB revocation, durable verified hosted artifacts and hosted CI/provenance success. API access to hosted CI remains blocked/unknown. |

Retained image findings and denied advisory access remain release concerns. Earlier
Alpha 0.3 results retain their disclosed source/build identities; never relabel
those artifacts as a newer candidate.

## Development path

### 1. Close integrity contracts before spending a build

C and D first settle two concrete open gaps found in the current tooling:

- `source_record.py` ignores names such as `bin` and `target` recursively. An
  authored Rust `src/bin` file could be compiled while excluded from source
  identity. Define explicit generated-output exclusions and require every
  admitted build input to be hashed or rejected. Negative acceptance: adding,
  changing or mode-changing an authored nested `bin` source invalidates identity;
  ignored generated outputs cannot secretly become compiler inputs.
- `image_record.py` hashes merged file content, modes, owners, links and devices,
  but omits PAX extended attributes, including `security.capability`. Bind
  security-relevant metadata or reject unsupported encodings. Negative acceptance:
  capability/xattr-only changes alter the measured rootfs identity or fail closed.
  Preserve correct whiteout, hardlink, ownership and special-mode interpretation.

Retain existing negatives for changed source, special permission bits, symlinks,
stale tools, host-mode substitution and arbitrary provenance-verifier replacement.
A mutable local record cannot authenticate a substituted verifier. A locally
constructed manifest is engineering evidence; it is not trusted provenance.

Freeze the input, resource, shutdown and reproducibility contracts before runtime
qualification. Existing bounds are Rust aggregate drain 20 seconds, Go HTTP drain
70 seconds and Compose grace 75 seconds; qualified Rust RPC admission is 16.
Measure changes against those contracts rather than adjusting limits after a
failure to obtain a pass.

### 2. Finish the bounded implementation lanes

Browser and local fault runs in this wave are diagnostic. Repeat the required
checks against the captured images in wave 3 before claiming candidate
qualification. Preserve the six v1 golden vectors, v2/v3 semantics and immutable
migrations 001–008; started/unknown outcomes never authorize automatic replay.

A completes only operator fixes supported by actual browser evidence. D executes
Chromium DOM login → fixed-question review → exact preview → independent Carol
approval → Alice export/evidence with native CA validation. An untrusted-CA
negative must fail before the trusted workflow succeeds. Keep browser trust and
profile isolated; retain no callback codes, tokens, cookies, HAR or traces.

Freeze response/error/queue and evidence-growth metrics with an approved load
budget, then measure polling with bounded slow responses before changing it.
Record overlap, cancellation and signed read-event growth; preserve authorization
and the existing evidence-history prefix. If reproduced, bound polling/backoff and
stale-response handling, then repeat the same measurement.

D/E prove permission and delegation revocation with the same unexpired BFF
session. E commits each mutation before the next authoritative create request;
D requires typed denial, and E independently checks zero new job/provider/artifact
effects. Preserve legitimately accepted work and started/unknown outcomes.

B/D finish packaged shutdown, restart, custody and receiver checks. Diagnostic
Evaluate-only tests do not replace real database/effect qualification. A lost
remote reply must remain unavailable/unknown without resetting a committed result
or permitting another effect. C completes deployment/build/evidence/CI wiring;
E alone executes shared builds and mutations.

### 3. Capture and qualify one final candidate

Finish applicable cleanup first. Root audits the coherent source; E captures it,
then releases editors and builds the immutable snapshot using fresh pinned
compiler outputs. Pin the Dockerfile frontend and transitive builders too; the
current floating `docker/dockerfile:1` is not a fully pinned build. No stale host
binaries, writable source, inherited compilation outputs or old PKI may satisfy
canonical prerequisites. Include coordinator tools
and verify Rust ABI in its actual runtime.

E admits one build at a time under the reviewed disk/memory budget, records peak
usage and preserves reserve. Use unique primary/restore state and non-overlapping
networks. Do not delete prior volumes, signing keys or receipts to force a rerun.
Generate short-lived PKI after compilation.

Run the entire ordered verifier against the captured images, including protocol,
actual DOM, database roles/trust, authority mutations, receiver provenance,
readiness, graceful lifecycle, rotation and quiescent restore. Retain each command,
exit status, source/image identity and result hash. Component passes do not equal
a passed combined wrapper. Later code changes produce a new candidate and rerun
affected gates; they never inherit a previous candidate's results automatically.

### 4. Establish reproducibility and the release decision

Build the same captured source again with independent empty output/cache trees.
Compare native binaries, frontend/runtime payloads and OCI bytes separately.
Document allowed timestamp/compression differences before comparison. Changed
executables, libraries, security metadata or frontend payload fail the relevant
gate; do not normalize unexplained differences away.

Produce complete source/OS SBOMs and raw vulnerability/advisory reports for the
actual images. Fix supported findings with behavioral/ABI verification. Preserve
unresolved findings and unavailable feeds without lowering severities, exclusions
or invented waivers. CI producer, downloader and durable retrieval integration must be completed.
Hosted GitHub attestations require an actual successful run,
retrievable artifacts and verification bound to repository, workflow, exact source,
`main` and GitHub OIDC. Mock command tests do not prove signature verification.

## Seven-seat execution map

| Seat | Exclusive responsibility and handoff |
|---|---|
| Root — auditor | Freeze contracts; audit changes, independent evidence and staged paths; decide pass/fail/blocked. Delegates implementation and resolves ownership. |
| A — application/contracts | Go control, migration runner, shared trust/broker/contracts and workspace. Owns caller/operator fixes and browser-tool source; requests exclusive shared-contract handoffs. No integration-test or migration-SQL edits. |
| B — governance/effects | Rust, policies, receivers/worker/evidence and new SQL migrations. Preserves old migrations, proof formats, custody and protected outcomes. |
| C — delivery/supply chain | Scripts, deployment, CI, build/inventory/security tooling and operational release documents. Closes source/rootfs integrity gaps and supplies commands; does not run competing shared stacks. |
| D — independent verifier | `tests/**` and service integration tests; adversarial fixtures, DOM/revocation/load/lifecycle checks and candidate binding. Reports exact scope and limitations independently of implementation owners. |
| E — dedicated publisher/runtime coordinator | Sole Git index/commit/push owner and shared Docker/build/DB/PKI/restore scheduler. Publishes audited coherent checkpoints normally to `main`, checks staged paths for secrets/runtime artifacts and verifies remote SHA. Never force-pushes. |
| F — trailing dead-code purger | Follows completed published batches, proves consumer closure, obtains exclusive owner handoff, removes only confirmed obsolete code and records checks in a deletion ledger. D/root independently review; E publishes a separate cleanup checkpoint. |

Keep A/B/C productive in parallel, D independent, and E/F dedicated to their
requested roles. E never stages another agent's unfinished work. File handoffs
include paths, compatibility promises, evidence and return of ownership. Source
freezes are brief capture windows, not long build/network locks.

F has no deletion quota. Preserve development routes, deferred provider seams,
generated/framework dispatch, SQL lock sentinels, v2/v3 codecs, migrations,
historical proofs and uncertain receipts. Cleanup occurs before the final
candidate freeze; subsequent deletions invalidate affected candidate checks.

## Definition of done and deferred work

Publish a durable non-secret candidate bundle and a gate table with **passed**,
**failed**, **blocked** or **not run**, each tied to evidence, owner and next action.
Engineering completion requires a successful clean canonical build, the complete
combined functional qualification and a completed measured reproducibility report;
unrun internal gates cannot satisfy it. Release/security eligibility remains a
separate decision: required external feeds or hosted CI may remain explicitly
blocked. No release is called reproducible, attested or security-cleared without
the corresponding measured evidence.

Live GovCloud/Bedrock account/model setup, customer identity/MFA, approved
cryptographic modules, independent evidence custody, production storage/IAM/network
implementation and assessment remain deferred. Using an authorized AWS service
does not authorize the Nex.os application. No CUI, FedRAMP authorization, NIST
control completion or CMMC certification is claimed. On-premises packaging, arbitrary shell execution,
connectors, distributed sessions/custody and Kubernetes remain outside this goal.

**First actionable ticket:** C defines complete build-input and rootfs security
metadata coverage; D supplies independent nested-`src/bin` and capability/xattr
substitution negatives; root accepts the contract before E captures the candidate.
