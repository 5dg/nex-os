# Nex.os synthetic candidate decision — 28 October 2026

**Functional acceptance and measured reproducibility passed. Release eligibility is blocked.**

Selected implementation: [`16edb6a68ca2a91770239c7220acb670d2d080d1`](https://github.com/5dg/nex-os/commit/16edb6a68ca2a91770239c7220acb670d2d080d1). The documentation commit containing this report is not a newly built candidate. Project completion and production readiness are not claimed.

The complete hosted verifier, two fresh hosted builds and a separate fresh local build completed successfully. Independent reviews checked the actual retained browser records, source/image bindings, native bytes, complete image archives and recomputed filesystem maps. Security failed; complete-subject retrieval and independent signature verification remain blocked.

## Delivered implementation

The workspace now refreshes through one completion-scheduled request cycle at a time, backs off failed refreshes, stops at terminal states and discards responses belonging to an obsolete job or identity. Current job state updates independently of history retrieval. Logout and unmount abort the UI request without asserting cancellation of already accepted service work.

History traversal returns bounded pages containing at most 32 events and 96 KiB, including signed proofs and the continuation. Continuations are authenticated, time limited and scoped to the current tenant, actor and job. Stable PostgreSQL visibility and sequence boundaries prevent reads from extending their own traversal. Ordering, signed event bytes and historical evidence interpretation remain intact. Legacy callers retain bounded array responses and receive an explicit pagination requirement when necessary.

The real browser acceptance exercises legitimately generated signed history beyond the BFF's 128 KiB ceiling, slow responses, job switching, logout, the exact immutable history prefix, independent human approval and revocation using the same unexpired session. The original UI overlap and BFF size refusal were independently reproduced, with the original failed broader attempt retained.

Packaged lifecycle acceptance now runs against actual candidate containers and is a required recorded producer/seal/consumer gate. It tests admission closure, bounded drain, restart, protected state and conservative no-repeat handling of denied, started or uncertain effects. Existing shutdown bounds, tenant boundaries, exact payload binding and independent approval remain required.

Fresh builds use pinned compiler containers, explicit frontend CPU concurrency, a pinned isolated BuildKit backend with a verified native snapshotter and direct timestamp-controlled exports. Comparison treats native binaries, complete runtime payloads and OCI configuration/layers/archive bytes separately. Only the documented outer archive header timestamps/checksums are transformed; raw-export hashes and exact header/member proofs remain recorded. Executables, libraries, security metadata and unexplained frontend differences are never excluded.

Supported dependency repairs include the maintained PEM reader, current Go vulnerability tooling and fail-closed finding interpretation, updated Go dependencies, a source-bound gosu dependency overlay and available supported OS updates. Raw unresolved image findings remain visible. Dedicated cleanup review found no additional justified deletion.

## Execution and evidence

[Hosted run 40798668756](https://github.com/5dg/nex-os/actions/runs/40798668756) captured candidate `2895df3aa4df`. Local capture `edbcc110b45d` has the same 316 source inputs, input digest `54e9f209b74b18aef885be997aca8c0521da580356287377253178da247e0c48`, companion digest `fd4f8f1d212b13cc79caa72fa9beed0fc38216f932306aa98d24f129b7841154` and source archive SHA256 `625086b876767f493d87cbfea090c8ba3b8d71e06299c102bd74647cf821533a`.

The hosted pipeline supplied two fresh builds and the complete ordered verifier. Local execution supplied one independent fresh build and six actual-image scans. It recorded builder/helper exit 0; no local second build or local combined verifier ran. A brief execution transport outage recovered automatically while the original builder continued; it was never restarted. The PostgreSQL phase entered with 11,246,567,424 bytes free against a 10,737,418,240-byte floor. Docker's whole-build minimum free space was 4,807,544,832 bytes, above the unchanged 2 GiB reserve.

All twelve native binaries and all six image archives, configurations, encoded layers and uncompressed layer identities match both hosted builds. All six merged filesystem maps were independently regenerated from actual local archive bytes; complete downloaded workspace and PostgreSQL maps match exactly, with zero differing paths. The previous source's mismatches remain historical failed evidence. Raw OPA export archives differ; the documented outer-header preparation, exact member proofs and identical emitted archives remain separate evidence.

The [public evidence index](ALPHA04_RELEASE_EVIDENCE_2026_10_28.json) records exact six-image/native identities, manifest and artifact checksums, scanner/database identities, raw scan file hashes and separate review receipts. Receipt paths are relative to the separately retained completion-evidence directory outside Git; the index does not embed all raw reviews or assert complete subject retrieval. Exact commands and observed exit statuses are in the captured build manifests and candidate records.

## Gate decision

| Gate | Status | Evidence / owner | Next action |
|---|---|---|---|
| Implementation and source regressions | passed | B/D/E/F/G: 226 release-tool tests, ten workspace tests, source integration and final browser acceptance. | Preserve tested source and regression coverage. |
| `dom-browser` | passed | F/G: all 12 DOM, five operator and three revocation assertions; strict TLS and exact fixture/image bindings. | Preserve qualification scope. |
| `history-pagination` | passed | B/G: required final recorded gate, source/run/image/command/exit bindings verified. | Preserve bounded stable traversal and historical proofs. |
| `proof-parity` | passed | G: required final recorded gate passed. | Preserve v2/v3 interpretation. |
| `shutdown` | passed | G: required final native shutdown gate passed. | Preserve drain/admission bounds. |
| `packaged-shutdown` | passed | G: required gate against actual captured containers passed. | Preserve accepted/unknown effects and no-repeat behavior. |
| `qualification` | passed | F/G: ordered API/DB/trust/authority/receiver verifier completed, including rotation and isolated restore. | Inspect raw inner artifacts when full subject delivery becomes available. |
| `reproducibility` | passed | D/E/G: two fresh hosted builds match all declared native/runtime/OCI targets. | Preserve pinned inputs and explicit producer contract. |
| Independent local build and cross-host comparison | passed | I/E/G: observed exit 0, all twelve native bytes and six complete images/maps match both hosted builds. | Preserve exact comparison and resource receipts. |
| Local second build / local combined verifier | not run | I/root: intentionally outside the local execution scope; hosted execution supplies both required builds and the full verifier. | No additional local execution is required for the reported scope. |
| Source inventory and source vulnerability audits | passed | E: 447 components/27 dependency inputs; hosted Go, Rust and both npm audits passed. | Refresh on source/dependency changes. |
| `vulnerability-scans` | failed | E/I: raw scans and SBOMs for all six exact local canonical images, independently hash-matched to both hosted builds; 793 finding rows. | D/E/I: obtain supported fixes, review changed runtime inputs, rebuild and rescan. |
| `hosted-ci` | blocked | E: retained release gate remains blocked; actual canonical and foundation jobs concluded failure on vulnerabilities despite functional success. | Resolve all release prerequisites; selected passing steps are not a green workflow. |
| Origin producer | passed | E/G: job `123209080725` succeeded; retrieved statement's decoded subject matches the producer log. | This does not provide independent signature clearance. |
| `provenance-attestation` | blocked | E/G: no independent cryptographic verification of this candidate; exact subject unavailable and default TUF access remains denied. | root/I/G: approved full-subject delivery and default trust-service access, then strict verification. |
| `durable-retention` | blocked | E/G: full subject download rejected; small metadata and origin artifacts retrieved and hash checked. | Run the strict retained consumer on the complete matching subject. |
| Applicable dead-code cleanup | passed | J/G: consumer closure and 316-input publication binding reviewed; no additional deletion justified. | Preserve active interfaces, provider seams, migrations and uncertain receipts. |
| Reviewed implementation publication | passed | H: normal push to main, exact remote SHA verified. | Keep this report's selected implementation distinct from its documentation commit. |
| Release eligibility | blocked | root: security failed and independent provenance/retention requirements remain unresolved. | Complete the explicit prerequisites below. |
| Production readiness | blocked | Product/customer/cloud owners: synthetic acceptance does not admit a production profile. | Complete the production dependency backlog. |

Browser measurements were concurrency **1**, healthy-delay errors **0**, obsolete writes **0**, drain **1,501 ms** within 5 seconds, and signed-read growth **3** within the predeclared **5**. The operator traversed **151 signed records / 136,694 bytes / five stable pages**, preserving the exact ordered prefix. Same-unexpired-session permission and delegation revocations passed after committed authority changes; independent Carol approval and Alice result retrieval passed.

Available metadata binds recorded proof/history/native/packaged lifecycle gates and the ordered wrapper's rotation/restore completion. Raw inner service/effect/transition snapshots and complete hosted image archives were not independently materialized. The completed execution and available-record reviews do not substitute for the blocked full retained-consumer check.

## Security and external release prerequisites

Trivy **0.76.1**, binary SHA256 `d1dfca6ae10a1ad4540bb94e64f0510077c47008920a9b554986b39dca573d83`, used database v2 SHA256 `1c66d0d801a194ed5df7a9c334d7991a6529d82952ab07a23cff1047c637c598`, updated 28 October at 19:18 UTC. All six scans and SBOM conversions completed without timeout/feed failure. Findings: **4 critical, 168 high, 301 medium, 311 low and 9 unknown**; vendor statuses: 610 affected, 146 deferred, 35 will-not-fix and two fixed-version rows. There are no exclusions, severity reductions or waivers.

| Image(s) | Critical package / installed version | CVE | Vendor status / fixed version |
|---|---|---|---|
| Workspace and PostgreSQL (two rows) | `zlib1g` `1:1.2.13.dfsg-1` | CVE-2023-45853 | `will_not_fix`; none reported |
| PostgreSQL | `libsqlite3-0` `3.40.1-2+deb12u2` | CVE-2025-7458 | `affected`; none reported |
| PostgreSQL | `libxml2` `2.9.14+dfsg-1.3~deb12u6` | CVE-2026-6653 | `fix_deferred`; none reported |

Fourteen earlier finding rows were cleared: nine Go-binary rows and five OS rows, counted per finding rather than unique CVE. Only the two remaining OPA `golang.org/x/net` findings advertise a fixed version (`0.62.0`); no reviewed supported official fixed image was established. D/B/E own the supported OPA replacement or reviewed vendor remediation; D/E/I own supported runtime updates and exact-image rescans. A vendor status is retained evidence, not release approval.

Hosted source audits match all captured authored files/modes and dependency inputs. Generated Next typecheck files give the foundation inventory a different whole-input digest; it is not presented as the canonical capture identity. The canonical build and verifier use the exact captured identity above.

The full subject artifact `12865776887` is **820,027,680 bytes** and was actually rejected by the connector's **536,870,912-byte** limit. Its ZIP SHA256 is `09933136ffc90753261abb568de9f32fe9183d6a363945595359908c33d5e638`. The subsequent file materializer separately documents a 32 MiB maximum; no oversized second-stage attempt, chunking or alternative trust service was used.

The **8,762,832-byte** public metadata artifact `12864959694` was independently retrieved: SHA256 `a383a6cc913b80ca66a1ecbd3b0fabba47d51b5420ddbc273dc965dc9aa27247`, with **24 available sealed file hashes** checked. Origin artifact `12865489522` was also retrieved and hash checked. Its decoded **unverified** subject `3884c61f6feb44a88d4461108246108580e80dc878ece82cbe86d434100f33d3` matches the actual producer log. No final-candidate cryptographic verification attempt or clearance is claimed. A retained historical strict verifier attempt under the unchanged network policy received HTTP 403 from the default Sigstore TUF service; no custom root or weakened verification was substituted.

To clear release eligibility, obtain supported reviewed image fixes that satisfy the release contract, produce fresh exact-image evidence, materialize the complete matching subject through a supported delivery path, and complete default-trust origin and retained-consumer verification. Current controls remain in force until those requirements pass.

## Operational boundaries

Follow [candidate runbook](../runbooks/ALPHA04_CANDIDATE.md) and [release contract](../architecture/ALPHA04_RELEASE_CONTRACT.md) for captured-source execution, pinned tools, qualification order and retention. Preserve previous failed runs, volumes, keys, receipts, backups and raw scanner outputs. Keep private session/custody/database material outside Git and public diagnostic artifacts.

The approved local plan retains a 2 GiB reserve, 10 GiB whole-build peak/12 GiB initial minimum, an 8 GiB PostgreSQL phase forecast and 4 GiB forecasts for other image roles. It disposes only the fresh Node workspace/npm-cache/node-cache after complete exports and writer absence are verified by the frozen external helper; source, native outputs, full package closure and image exports remain protected. Every actual phase admission still applies. No local second build, broad prune or application-state deletion follows from this plan.

The browser's explicitly approved disabled sandbox is limited to the isolated synthetic fixture. Normal TLS verification, network restrictions and private temporary storage remain required. This is not a production configuration.

## Production dependencies

The supported synthetic implementation deliberately rejects production profiles. Full production completion still requires:

| Workstream | Owner / required dependency | Acceptance before deployment |
|---|---|---|
| Customer and authorized boundary | Product/customer | Confirm tenant/users/data, account/region, service level and authorization scope. |
| Customer identity and sessions | Identity/application owners | Real OIDC/MFA, trust/rotation/revocation and multi-instance session behavior. |
| Admitted production profile | Service/governance owners | Reviewed startup guards/configuration and live denied-path tests within the approved boundary. |
| Exact Bedrock routing | Model/cloud/customer owners | Approved model, region, account and API entitlements; exact route binding and denied-path proof. |
| Managed storage and exports | Data/application/cloud owners | Authorized ingestion, managed document/result storage, destination binding, retention and isolation. |
| Evidence and key custody | Security/custody owners | Approved custody, cryptographic modules/configuration, rotation and historical verification. |
| Application infrastructure and workload identity | Cloud/platform owners | Application tasks/services, ingress/TLS/DNS, database, secret delivery, roles and endpoint/resource policies. |
| Operational recovery | Operations/security owners | Monitoring/alerts, tested backup/restore, measured recovery objectives, access review and incident handling. |
| External acceptance | Customer/security | Control responsibilities, contractual/assessment evidence and operational authorization before real CUI use. |

No synthetic pass, cloud service status or documentation checkpoint establishes production readiness.
