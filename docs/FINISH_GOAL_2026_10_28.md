# Nex.os completion goal and ten-agent execution plan

Date: **28 October 2026, America/New_York (EDT)**. Target decision: **23:59 EDT today**.
Reviewed baseline: `640ce8f2553a1ba18039e9dc9ec19369b20a9163`, verified equal to remote
`main` during this review. This document is the current execution plan for finishing
Alpha 0.4. It supersedes stale task ordering in the earlier Alpha 0.4/0.5 plans;
their historical evidence and compatibility contracts remain valid.

## The goal

> Finish the existing Nex.os synthetic product slice and deliver one traceable,
> independently tested release candidate: a user signs in, reviews an authorized
> synthetic record, sees current job state and verifiable history, requests an
> exact export, obtains an independent person's approval, and retrieves the
> recorded result without losing state or repeating an uncertain effect.
>
> Close demonstrated application and qualification gaps first. Bound audit-history
> responses and UI polling; prevent stale requests from replacing the selected
> job; test actual browser behavior, same-session revocation, packaged shutdown,
> restart and recovery. Preserve the Go control plane, Rust governance kernel,
> gRPC contracts, protected database ownership, exact evidence verification,
> immutable migrations, historical v2/v3 interpretation and conservative unknown
> outcomes. Extend the existing implementation instead of starting a replacement.
>
> Capture reviewed source after relevant cleanup, build it twice using the pinned
> container toolchains and fresh compilation outputs, and qualify the exact
> resulting images. Bind source, compiler inputs, images, tests, inventories,
> vulnerability reports and retained artifacts to that candidate. Resolve real
> failures without weakening the acceptance criteria. A build, push, test harness
> or documentation update is not proof of an executed release gate.
>
> Use up to ten subagents with exclusive ownership. Keep one dedicated to reviewed
> commits and normal pushes, and another dedicated to evidence-backed dead-code
> cleanup. Keep one runtime coordinator so builds, database mutations, rotation
> and restore cannot race. The lead audits handoffs and decides which gates pass.
> Publish coherent checkpoints as they become ready, then publish the exact
> end-of-day result: completed gates, remaining defects, blocked dependencies,
> owners and next actions. Do not call unfinished work complete to meet the date.

The achievable target today is the **synthetic release candidate**. The current
code deliberately refuses production configurations. Completing the full CUI
product also requires substantial deployment implementation and customer/cloud
decisions; those are listed below, rather than being silently removed from the
meaning of “finished.” There is no basis to promise production completion today.

## What the code review establishes

| Area | Current evidence | Remaining action |
|---|---|---|
| Core workflow | Authenticated synthetic review, independent approval, exact export and signed outcomes already exist. Earlier service checks are recorded in [Alpha 0.3](ALPHA_0_3.md). | Execute the complete current candidate, including the real browser. Historical passes do not qualify new images. |
| Governance fixes | Exact signed-event content checking is implemented in `services/guard-kernel/src/evidence.rs:182`; caller fencing in `services/control/api/request_authority.go:25`; SIGTERM/drain support in `services/guard-kernel/src/main.rs`. | Preserve them and prove packaged behavior. Do not reopen them as missing implementations. |
| History size | `services/control/api/workflow_http.go:283` reads all job events; authorized reads append `document.read` events (`workflow_store.go:113`). The BFF caps responses at 128 KiB (`apps/workspace/lib/trust.ts:124,157`). | Add bounded complete history traversal. `Workflow.tsx:27` currently waits for history before displaying a successfully fetched job, so history failure also stalls job-state display. |
| UI concurrency | `Workflow.tsx:40–44` starts a refresh every two seconds. `:27` checks identity but not the selected job/generation. | Prevent overlapping polls and an old job's late response overwriting the newly selected job. Runtime reproduction is still required. |
| Browser assertions | `tests/qualification/browser/qualification-browser.mjs:32–46` measures overlap/errors/growth but does not enforce limits. Its “prefix preserved” check compares only event-ID membership. | Assert fixed limits and exact ordered immutable history content; fail the gate when they are violated. |
| Lifecycle evidence | `scripts/qualification-native-check.sh:2,20–25` explicitly tests native exported binaries and Go-source fixtures. | Add actual candidate-container SIGTERM/restart/effect acceptance. Native tests remain useful but cannot establish container-runtime behavior. |
| Build integrity | Source closure, nested authored inputs, xattrs/capabilities, hardlinks, pinned frontends and candidate evidence tooling are implemented. | Exercise actual vendor layers, compiler/runtime compatibility and end-to-end execution. Old Alpha 0.5 first-ticket wording is stale. |
| Frontend reproducibility | Cold Next builds are independent (`canonical-compiler.sh:34`); supplied environment (`canonical-build.py:141`) does not define the framework key boundary. Installed pinned Next generates fresh encryption material in build manifests. | Reproduce the expected payload mismatch early and design a secure solution. This is a source-supported risk, not a measured two-build failure yet. |
| CI and retention | Canonical producer, origin/attestation and retained-artifact consumer code exists. Git publication works. | Run and independently verify it. The current Actions API probe returned proxy CONNECT 403; hosted CI status is **unknown/access blocked**. |
| Cleanup | Earlier deletions are documented; the current delivery batch has reachable consumers. | Continue the consumer audit after each completed batch. This review found no justified additional executable deletion. |

Fresh checks during this review: **54 offline release-tooling tests passed** using
`PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/release -v`;
the workspace's existing `npm test` security suite also passed. Five focused Go
race suites passed with `-count=1`: model, tool-executor, worker, evidence and
broker. Evidence/broker initially could not open test listeners in the network
sandbox and passed when rerun with loopback access. These are limited
checks, not DOM, candidate, load, reproducibility or production qualification.
No complete current-candidate bundle was found in the inspected workspace.

## Ten subagent responsibilities

These are ten work assignments, not a demand for ten simultaneous processes.
This environment supports six subagents plus the lead at once. Run dependency
waves and hand off completed seats; keep stateful execution serial.

| Agent | Exclusive normal ownership | Deliverable and acceptance |
|---|---|---|
| **A — workspace behavior** | `apps/workspace/**`, excluding browser test harnesses | Bounded polling, stale-response invalidation, independent current-state rendering and complete paginated history UI. Demonstrate slow-response, job-switch, logout, terminal-state and history-error behavior. Coordinate the API shape with B before editing. |
| **B — API and contracts** | `services/control/**` excluding integration tests and migration SQL; `packages/contracts/**`, `packages/trust/**`, `packages/broker/**` | Bounded, authorized, proof-preserving history API and contract compatibility. Own generated-contract updates and Go dependency changes. Test tenant/job scope, cursor tampering, complete traversal and response bounds. |
| **C — governance and effects** | `services/guard-kernel/**`, `policies/**`, model/executor/evidence/worker services, `packages/evidence/**`, new migration SQL | Fix only demonstrated governance/lifecycle defects; preserve exact grants, protected results and no-repeat semantics. Keep existing migrations immutable. Supply component tests and shutdown/effect expectations to G. |
| **D — builds and reproducibility** | Canonical build/capture/image/evidence scripts, build Dockerfiles and reproducibility contracts | Resolve the Next build-key boundary safely, close actual packaging/ABI defects, and supply two-build commands and interpretation. No public hash as secret; no unexplained byte exclusions. Coordinate shared deployment files with I. |
| **E — security and release provenance** | Scanner/inventory/retained-provenance tooling, `.github/**`, release security records | Complete raw source and six-image scans; remediate supported findings with owner handoffs; obtain exact-source CI, attestation and retrieval evidence when accessible. Preserve unresolved findings and blocked feeds. No automatic waiver or severity suppression. |
| **F — independent browser verifier** | `tests/qualification/browser/**`, browser harness tests and the browser coordinator through an explicit script handoff | Reproduce A/B findings; enforce DOM/polling/history budgets; exercise same-unexpired-session permission and delegation revocation. Verify ordered signed-history preservation and long histories. Report failures independently. |
| **G — independent service verifier** | Service integration tests, nonbrowser `tests/**`; packaged lifecycle harness through explicit handoff | Prove packaged admission/drain/restart, no repeated effects, receiver provenance, database ownership and recovery. Run adversarial integrity regressions. Independently verify candidate/source/image/test binding. |
| **H — dedicated commit/push owner** | Git index, commits, pushes and publication receipts only | Stage exact reviewed paths, inspect the staged diff for unintended files/secrets, commit coherent batches, push normally to `main`, and verify remote SHA. Publish cleanup separately when it changes executable code. Never force-push or stage another owner's unfinished work. |
| **I — runtime and qualification coordinator** | Execution schedule, run directories, resource/IPAM admission and shared Docker/Compose/DB/PKI state | Sole operator of builds, stacks, fault injection, rotation and restore. Execute D/F/G/E commands in order, retain logs and identities, preserve previous data/keys/receipts, and stop admission when resource reserve is threatened. Runtime ownership does not confer Git ownership. |
| **J — dedicated dead-code cleanup owner** | `docs/checkpoints/ALPHA04_CLEANUP.md`; temporary exclusive source handoffs | Audit consumers after completed batches; delete only proven obsolete code, run relevant checks and obtain independent review. Record “reviewed, no deletion justified” when appropriate. Finish applicable cleanup before capture. No deletion quota. |

The **lead** owns this goal, acceptance contracts, integration decisions and the
final release decision. Every handoff names paths, interfaces, compatibility,
checks actually run, outstanding limitations and readiness. No two agents edit
one file simultaneously. A normal edit to a shared lock/contract/script requires
a short ownership handoff, not a separate branch of competing implementations.

Suggested waves: A/B/D/F/G work on implementation and independent negatives while
H publishes reviewed batches. C joins when a governance failure is reproduced;
E starts access/scanner preflight early as a seat becomes free. J reviews completed
batches before capture. I then serializes expensive/runtime execution, while E,
F and G inspect evidence and owners handle isolated fixes. Resume H for each
publication handoff. Do not keep idle agents occupying all execution seats.

## Ordered work and acceptance

### 1. Establish the baseline and remove predictable blockers

H records local/remote source identity and preserves unrelated work. I inventories
tool versions, Docker driver, free space, memory, existing projects and networks.
Use the existing [release contract](architecture/ALPHA04_RELEASE_CONTRACT.md):
one image build at a time, at most two Cargo jobs, initial 8 GiB Docker / 6 GiB
temporary-output free-space budgets and 2 GiB reserve, unless the lead accepts a
measured alternative strategy that preserves the reserve. Do not prune existing
data to create apparent capacity.

E tests actual access to required advisory feeds, `api.github.com`, artifact
retrieval and configured credentials without printing secrets. Record a denied
destination as blocked; do not bypass network policy. Current Git access is not
evidence of Actions API access. The canonical CI job requires explicit
`workflow_dispatch` with `canonical_candidate=true` on `main`; an ordinary push
only running foundation CI cannot close that gate.

D first performs a bounded frontend two-build investigation. Identify the exact
changed files and whether runtime secrets, generated IDs or ordinary payloads
explain them. Any key handling must preserve cryptographic strength and appropriate
custody and keep keys out of public evidence. If the architecture cannot satisfy
the existing reproducibility contract safely today, record that failure; do not
silently weaken the contract or derive keys from public source identity.

### 2. Finish the operator path

B and A agree a compatible history response and cursor contract before coding.
Bound both page bytes and item counts below the existing BFF limit, including
proof overhead. Scope every continuation to the authorized tenant/job and current
authority. Use a stable snapshot/high-water boundary so newly audited page reads
cannot create an endless traversal. Preserve original signed bytes, ordering and
history; never trim or suppress security evidence to make the UI pass.

A updates current job state even if history fetch fails, displays a recoverable
history error, and provides access to all pages. Pending requests are invalidated
on job/identity changes and unmount; automatic polling is single-flight, stops at
terminal states and backs off on errors. A delayed response for A must never
replace selected job B. Aborted reads must not imply cancellation of accepted jobs.

F reproduces the old behavior and verifies the repair in an actual browser. Use
legitimately generated, signed history exceeding 128 KiB; prove the current job
remains visible and the entire bounded snapshot is traversable without missing,
duplicated, altered or reordered prior events. Include cursor misuse and tenant
denials with B/G. Do not fabricate protected completion rows for these fixtures.

Freeze the browser budget before acceptance: at most **one automatic refresh
cycle in flight**, zero unexpected errors in the healthy delayed-response case,
zero obsolete UI writes after a selection change, and the existing **5-second
fixture drain** budget for the **2.5-second response delay** case. Record polling
attempts and an expected signed-read-growth bound derived from the agreed API
call sequence, including measurement/pagination reads. F/B must write that exact
growth formula before the measured run; do not choose a threshold after observing
results. Verify the exact ordered immutable history prefix, not ID membership.

### 3. Prove actual packaged behavior

G supplies a test that holds admitted work in real packaged services, sends
SIGTERM to the containers, checks new-admission closure, and restarts them.
Runs before final capture are diagnostic; repeat acceptance against step 4's
final immutable images before rotation/restore. G/D wire this harness into the
recorded required shutdown gate, or add a required gate consistently across the
producer, seal, retained consumer and CI. The existing native-only gate cannot
satisfy this acceptance, and a standalone unrecorded test is insufficient.
Keep the existing bounds: Rust aggregate drain **20 seconds**, Go HTTP drain
**70 seconds**, Compose grace **75 seconds**, qualified Rust RPC admission **16**.
Measure outcomes against these values; do not extend them after a failed test.

I executes shared-state cases serially. G checks that protected results and
receipts survive, already-started or unknown effects are not replayed, and the
provider/artifact effect count does not increase on denied or duplicate grants.
Known-not-started retry must remain distinct from unknown outcome. Test committed
permission/delegation revocation before the next grant using the same unexpired
session; preserve legitimately accepted delegated work. Retain the existing
native fault suites as complementary evidence.

### 4. Capture and qualify the final source

J finishes consumer review; H publishes reviewed changes; the lead accepts the
capture. I uses a new candidate directory and inspected nonoverlapping private
network block. The existing entry points are:

```bash
python3 -B scripts/candidate.py capture --output /absolute/new-candidate-directory
bash /absolute/new-candidate-directory/source/scripts/candidate-pipeline.sh \
  /absolute/new-candidate-directory/candidate.json INSPECTED_PRIVATE_BLOCK/20
```

Paths and the network block above are placeholders that I must resolve from the
current runtime. Capture requires clean committed source. Never reuse an existing
candidate directory or bypass refusal by deleting retained evidence.

Run both fresh canonical builds and compare native binaries, frontend/runtime
payloads and OCI bytes separately. Verify actual Rust runtime ABI and vendor-layer
metadata interpretation. Run the complete ordered verifier against those images:
API, real DOM, database roles/trust, authority mutations, receiver proofs,
packaged lifecycle, rotation and isolated restore. Require actual wrapper exit
status; selected passing tests do not replace it. Generate short-lived PKI after
compilation. Retain failed attempts with their own source and image identities.

A later code fix creates a new candidate and reruns affected gates. Do not relabel
the previous candidate's results. Freeze source briefly for capture, not throughout
all builds; unrelated edits may continue but cannot enter the captured candidate.

### 5. Decide and publish

E scans the actual candidate and retains complete raw findings, tool/database
versions and source/OS SBOMs. Remediation changes go to the relevant file owner,
then through independent review and a new capture as required. Obtain a completed
hosted run, verified attestation and independently downloaded matching artifact
before marking those gates passed. Temporary workspace logs alone are not durable
release retention.

H publishes the reviewed source and final non-secret decision records. The final
handoff includes the revision, image IDs, candidate bundle/checksum, test commands
and statuses, reproducibility comparison, raw scan references, hosted run/artifact
references when verified, startup/recovery instructions and every remaining owner.
Do not commit private keys, credentials, session data, receipts or database dumps.

## Today's checkpoints and stopping rule

These are planning checkpoints, not measured duration guarantees. Parallelize
independent source work; reserve time for two builds and a complete rerun.

| Time today (EDT) | Required checkpoint |
|---|---|
| By 17:30 | Assign owners; confirm capacity/access; freeze API, browser and lifecycle acceptance; perform early frontend reproducibility investigation. Escalate external blockers immediately. |
| By 19:00 | Aim to finish the bounded application/test fixes and cleanup review; publish a coherent candidate source. If not ready, report the specific failure and revised execution forecast. |
| 19:00–22:30 | Run fresh builds, comparison and serialized full qualification; remediate only candidate-blocking defects; preserve failure evidence and rerun requirements. |
| 22:30–23:59 | Finish independent evidence review, security/CI retrieval if available, publication and the explicit release decision. Report unfinished work honestly if earlier stages overrun. |

The date never authorizes skipped tests, removal of safeguards or invented passes.
If time or external access prevents closure, publish the working checkpoint and
an itemized unfinished queue. That is a useful handoff, **not project completion**.

## Definition of done

| Claim | Required evidence |
|---|---|
| Implementation finished | Bounded history/polling and qualification gaps closed, independent regressions passed, applicable cleanup reviewed, code committed/published. |
| Synthetic engineering complete | Fresh canonical builds, actual packaged full qualification and completed reproducibility measurement tied to one source. Internal gates cannot be merely unrun. |
| Reproducible | The declared binary/runtime payload targets actually match; OCI differences are reported separately under the existing contract. |
| Release eligible | Required scan disposition, successful exact-source hosted CI, verified provenance and durable independently retrieved artifacts all pass. |
| Production ready | All deployment work and external decisions below are completed and tested in the approved boundary. Synthetic success alone does not establish this. |

Every gate uses **passed / failed / blocked / not run**, with evidence, owner and
next action. Engineering completion and a blocked release decision can coexist
only when the engineering gates themselves passed. A known payload mismatch
must still be reported; it cannot support a reproducible or release-eligible claim.

## What remains to finish the full production project

The production backlog is real work, not a setting to enable. Terraform currently
provides foundation resources, not deployed application services
([deployment scope](../deploy/terraform/README.md)). Workspace profiles and multiple
services intentionally reject production; do not remove those guards prematurely.

| Workstream | Completion requirement / external dependency |
|---|---|
| Product/deployment boundary | Confirm customer, authorized users/data, tenancy, hosting region/account, required service level and approval/assessment scope. Additional workflows/connectors require explicit requirements. |
| Customer identity and sessions | Integrate customer OIDC/MFA, configurable trust, operational rotation/revocation and an appropriate multi-instance session design. The fixture identity and in-memory sessions are not that deployment. |
| Application infrastructure | Implement ECS task definitions/services and execution roles, database, ingress/TLS/DNS, secret delivery, workload identities, endpoint/resource policies and tested backend isolation. |
| Data and model path | Implement approved document ingestion/storage and export destination, evidence/key custody and the fixed authorized Bedrock route; verify exact model/region/API entitlements and live denied-path behavior using synthetic data first. |
| Cryptography and operations | Select required cryptographic modules/configuration; implement monitoring, alerting, backup/restore, retention, access review, incident handling and measured recovery objectives. |
| External acceptance | Establish customer/AWS/shared control responsibilities, required contractual and assessment evidence, and operational authorization before real CUI use. An AWS service's status does not authorize this application. |

Keep arbitrary shell execution, broad connectors, Kubernetes, vector search,
on-premises packaging and multiregion expansion outside today's finish line.
Revisit them only against an actual product requirement. No certification or
real-CUI readiness is claimed by this plan.

**Start here:** A/B/F close the history/polling contract and regression; D checks
frontend reproducibility; E/H preflight external access/publication; G specifies
packaged lifecycle acceptance; J reviews each completed batch; I executes only
the coherent candidate accepted by the lead.
