# Actual browser qualification fixtures

These drivers execute rendered React interactions in Chromium through Playwright
CDP at `http://127.0.0.1:9222`. They require the isolated browser fixture under
`apps/workspace/tests/browser`, its pinned Playwright module, a fresh NSS store
containing only the public qualification root CA, and the real synthetic stack.
They do not disable certificate validation or install host trust. E alone builds
and runs the container, creates shared PKI and coordinates DB mutations.

The Node drivers accept `NEX_PLAYWRIGHT_MODULE` (default
`/fixture/node_modules/playwright-core/index.mjs`). Example arguments:

```text
qualification-browser.mjs --base-url=https://workspace.nex.test:9443 --wrong-ca-url=https://untrusted.nex.test:9445 --output=/results/browser-results.json --measure-polling=true
revocation-browser.mjs --base-url=https://workspace.nex.test:9443 --directory=/results/revocation
```

`qualification-browser.mjs` first requires a native browser TLS failure for a
reachable HTTPS endpoint with an untrusted issuer. It then checks trusted TLS,
real OIDC login, scoped records, the fixed question, review completion, exact
preview/digest, Carol's independent approval, Alice's resumed export and rendered
verified evidence. It never saves callbacks, network bodies, cookies, credentials,
HAR or traces. Polling acceptance delays actual job API responses by 2.5 seconds
for a bounded 7.5-second window. `acceptance.mjs` freezes these limits before
execution: at most one automatic job read in flight, zero unexpected errors for
healthy delayed responses, and a five-second drain. The driver compares the exact
ordered prior signed-event contents, including proofs, rather than only event-ID
membership. This is a browser response-latency test, not database throughput.

The signed-read-growth bound is declared before execution:

```text
maximum observed document.read growth = audited request attempts + 1
```

The request observer starts before the first snapshot fetch and ends after the
last snapshot fetch. It counts every actual `job` and `event_page` attempt for
that job, including all measurement and continuation pages. Each successful
authorized call appends one read event. The extra one covers a single automatic
read already in flight at the first observation boundary. Counting baseline and
post-snapshot continuation reads is conservative; those reads cannot all appear
in the measured difference. Healthy errors and overlap fail independently, and
zero automatic requests also fails rather than passing an unused test.

`operator-browser.mjs` creates genuine synthetic review jobs through rendered
controls. It verifies terminal polling stops, a history-only failure cannot hide
current job state, delayed responses for an older selection cannot write over a
new selection, and logout removes displayed private state. It grows history with
authorized job reads until the signed snapshot exceeds 128 KiB, then traverses
the rendered pagination controls with bounded 32-item/96-KiB pages. Every page's
contents, unique event IDs, exact ordered historical prefix and final DOM order
are checked. Continuation-read audits must not extend that snapshot indefinitely.
No completion, protected result, approval or receipt is invented for the fixture.

The operator history generator allows at most 512 authorized reads and 90 seconds
before failing its fixture budget. The coordinator retains only status, counts
and public build identities, not event bodies or session credentials. Each driver
container has a 240-second wait limit. The existing outer browser gate remains
bounded separately.

Run independent acceptance-helper negatives without a browser:

```bash
node tests/qualification/browser/acceptance.test.mjs
```

`revocation-browser.mjs` uses one fresh Alice session throughout a positive review
and two denials. E must coordinate the following protocol in a new, owned
synthetic qualification state; never mutate public/customer data:

1. Wait for `permission-ready.json`. Capture job/provider/artifact counters and
   permissions, then commit Alice's DB permission removal. Write
   `permission-committed.json` with `{"stage":"permission","committed":true}`.
2. The driver clicks the rendered create button and requires typed
   `403 DENIED_BY_POLICY` while the same session remains authenticated/unexpired.
   On `permission-denied.json`, verify no new job or provider/artifact effect.
3. Before acknowledging `delegation-ready.json`, restore the original permissions
   and commit revocation of `delegation-alice`. Capture counters, then write
   `delegation-committed.json` with `{"stage":"delegation","committed":true}`.
4. On `delegation-denied.json`, verify unchanged effect counters, restore only the
   owned synthetic fixture state, and preserve results. A failed/expired test
   requires a new run; do not fabricate acknowledgements or relabel it passed.

Each acknowledgement must arrive within 20 seconds. The driver requires more
than 30 seconds remaining in the same session before each stage, preventing an
expired credential or fresh login from masquerading as DB revocation. The E-side
counter comparisons are required additional evidence: browser status alone cannot
prove no provider/artifact effect. These fixtures make no production, MFA, CUI,
FedRAMP or CMMC claim.

For a host diagnostic build, the runtime coordinator may explicitly invoke
`scripts/qualification-browser.sh --diagnostic`. It refuses a canonical candidate
manifest and requires the `nex-qualification` project, an absolute dedicated
`NEX_QUAL_EVIDENCE_DIR`, and an absolute `NEX_QUAL_DIAGNOSTIC_RECEIPT`. The JSON
receipt must contain `schema_version: 1`,
`build_mode: "local-host-synthetic-qualification"`, the exact
`source_input_sha256`, and an `images` map of actual image IDs for control, guard,
model, executor, worker, evidence, workspace, issuer, workspace-edge, opa-edge,
postgres and opa. The coordinator creates that receipt from its reviewed build
and running stack. The wrapper rechecks source/native artifact hashes, actual
container image IDs and Compose ownership. This mutable diagnostic receipt is
engineering evidence only: its output is explicitly labeled diagnostic, it never
writes a canonical candidate result, and final qualification still requires a new
captured source and exact canonical images. Both modes retain native TLS checks.
