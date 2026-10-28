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
HAR or traces. Optional polling measurement delays actual job API responses by
2.5 seconds for a bounded 7.5-second window and records only concurrency/counts;
that measurement alone is not an acceptance threshold or proof of DB throughput.

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
