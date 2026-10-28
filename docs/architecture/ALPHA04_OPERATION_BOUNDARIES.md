# Alpha 0.4 operation and cancellation boundaries

This contract preserves the Alpha 0.3 synthetic profiles, exact v2/v3 manifests,
minimal database roles and conservative receipt recovery. It does not enable
production, live providers, customer identity or distributed custody.

## Original HTTP caller

The control API authenticates the verified Workspace or Worker TLS peer at
request entry. That original peer and the control process's own identity must
still be current after awaited database, policy or signing work, immediately
before a control transaction commits and before a new protected RPC is
dispatched. The request context must also remain live. No forwarding header or
user-supplied claim substitutes for the verified TLS connection.

The entry check alone is not sufficient for a request held across certificate
expiry or cancellation. The regression fixture must hold an actual dependency,
prove a valid positive control, then show the unaccepted transition is absent
when the original caller expires or cancels before its admission boundary.

Worker claim consumes the bounded empty request body (`{}` or the existing
no-body form) before awaiting its database work. Leaving an HTTP/1 body unread
can prevent the server from observing a disconnected client during that wait.
Cancellation checks apply once cancellation is observed by the server; they do
not promise atomic knowledge of a remote client's cancellation across a network.

## Acceptance and authoritative grants

| Boundary | Acceptance or grant point | Required outcome |
|---|---|---|
| Create, retry, export-request or cancel a durable job | Control SQL transaction commit, after the final caller/context check | Before commit, a failed caller/context check rolls back the transition. After commit, loss of the browser request or session does not undo accepted work. |
| Claim a worker lease | Control SQL transaction commit, after the final Worker/context check | A lease is not returned as accepted before that commit; its existing token/expiry fencing remains authoritative. |
| Prepare a manifest or submit an approval decision | Dispatch from control to Guard while the original HTTP caller, control identity and context are valid | Cancellation remains best effort. Once dispatched, a lost response cannot establish that Guard did not commit. Do not fabricate denial or reset protected state. |
| Start a model/export effect | Fresh dispatch from control to its fixed receiver, followed by the receiver's independent Rust authorization | Recheck the original Worker/context before dispatch after any previous await. Receivers and Rust continue independently checking exact payload, current DB authority, service identity, limits and custody. |
| Rust execution grant | Guard transaction commit after locked current authority, canonical payload/context, candidate signing and final freshness/peer checks | A signed candidate alone is not a committed grant. After a committed start, ambiguous acknowledgements remain unknown until authenticated state/receipt reconciliation. |
| Record a real completion | Existing protected Rust result/receipt transition | Do not discard a genuine result or invent no-effect because a caller expired, disconnected, or its lease was later cancelled. Do not resurrect a cancelled job. |

The control API does not forward a browser certificate as Rust authority and
does not introduce a new schema, submission queue or capability format. An
independently accepted durable job does not require its initiating browser to
remain connected. Explicit job cancellation and current delegated authority
continue to follow the existing workflow and Rust grant rules.

## Cancellation and operational accounting

Request cancellation or a failed identity check prevents a new admission or
dispatch at the boundaries above. It cannot atomically cancel work in another
process, undo a committed grant, or prove a callback did not run. Preserve the
existing `not_started`, `in_progress`, `started` and unknown distinctions; only
positive authenticated evidence permits a safe retry of the same immutable
operation.

The existing `*_PREPARATION_NOT_STARTED` failure classifier means this attempt
did not dispatch a new receiver request. It does not assert that Rust preparation
did not commit, that a manifest does not exist, or that no earlier attempt ever
had an effect. Retry still requires Rust's pending/fresh-manifest predicate (or
the existing missing-preparation case) and the same operation. Started/unknown
operations remain ineligible regardless of the error-code suffix. Never create
this classification from receiver or approval post-dispatch ambiguity.

The existing bounded, lease-fenced cleanup of an already accepted worker job
may record an operational failure using an independent context. That narrow
accounting operation is not a new model/export grant and must not depend on the
continued presence of the expired/disconnected HTTP caller. It cannot overwrite
Rust's protected result, reset an operation or fabricate unsigned execution
evidence. Signing can fail separately without preventing fenced failure status.

An external journal append can survive a subsequent SQL rollback. Preserve that
history; a signed candidate or request event alone does not establish a durable
job, committed execution grant or completed artifact.

## Current database authority and revocation

An unexpired session or JWT is not cached permission authority. Test with valid
credentials while committing a database permission/delegation revocation before
the next authoritative check; require a specific denial and no newly permitted
effect. Row locks serialize concurrent authority changes. Define the order of a
grant and a revocation rather than promising that revocation undoes an earlier
grant. Logout still closes only the local application session and does not
cancel accepted delegated jobs or provide immediate global issuer revocation.

## Bounded operation and shutdown

Keep the existing qualification request bounds: 15 seconds for normal control
requests, 60 seconds for worker steps, model HTTP client 45 seconds, direct
database/policy/signing probes 3 seconds, receiver readiness 8 seconds under an
overall 10-second readiness bound. Preserve database connection/statement/lock
timeouts and admission limits.

The approved graceful HTTP drain is 70 seconds, with a 75-second Compose stop
grace. This covers the maximum admitted control request and its bounded failure
accounting. Shutdown stops accepting requests before waiting for admitted work.
If the bound is exceeded, terminate the process before releasing single-writer
custody; never release its lock while callbacks could still run. The shared
HTTP implementation and deployment configuration must use these matching
bounds; deployment behavior requires an actual controlled shutdown check.

## Polling and evidence

Job and timeline reads intentionally revalidate authority and append signed read
events. Automatic workspace polling waits for the entire read cycle before
scheduling the next attempt, stops for terminal states and invalidates old
identity/job selections. Backoff is bounded at 30 seconds. Current job state is
displayed independently of history availability. History is fetched initially
and on state/phase transitions, with explicit refresh/continuation controls;
unchanged pending polls need only the job read.

`GET /v1/jobs/{id}/events?page=1` returns at most 32 records and 96 KiB including
the envelope/cursor. An authenticated continuation binds actor, tenant, job,
visibility snapshot, original transaction, signing-sequence boundaries and a
15-minute expiry. Restart invalidates process-local cursors; users can start a
new snapshot without changing job execution. Every page rechecks current
authority and records its own read. Snapshot membership excludes later commits
and continuation-read audits, so complete traversal terminates.

Paginated history orders immutable signed sequence before original timestamp/ID.
Go and Rust same-job event writers serialize using the existing job row lock;
the Go best-effort preparation-failure evidence transaction acquires it too.
An older transaction-start timestamp cannot insert a newly admitted signed event
ahead of an already returned signed prefix. Existing event timestamps/proofs are
unchanged. Historical missing/malformed sequences remain available at sequence
zero. Legacy no-query arrays retain timestamp/ID ordering and fail explicitly
with `HISTORY_PAGINATION_REQUIRED` above their bound; they never truncate silently.

Measure actual DOM concurrency, cancellation, error and signed-read growth under
the fixed browser budget. The independent browser fixture counts audited request
attempts and allows one boundary read in its predeclared growth bound. Exact
ordered immutable content, not event-ID membership alone, establishes prefix
preservation. No authorization, audit events or proof history are removed to
meet polling or response-size budgets.

## Ownership and verification

Current ownership follows the [ten-agent completion plan](../FINISH_GOAL_2026_10_28.md):
A workspace, B control/contracts, C governance/effects, D builds, E security,
F independent browser and G independent service verification. H alone owns Git
publication; I alone coordinates shared runtime. J removes only proved dead code
after an exclusive handoff and independent review before final candidate capture.
Root audits contracts, reproduced failures and evidence.
