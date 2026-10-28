# Nex.os development goal and implementation path

## Current goal: finish Alpha 0.4 synthetic release qualification

Finish the remaining Alpha 0.4 engineering and qualify one exact-source synthetic
release candidate before expanding the product. Bind clean pinned builds,
immutable images, actual browser/service tests, reproducibility measurements and
retained security evidence to the same captured revision.

The active execution goal is the [28 October completion plan](FINISH_GOAL_2026_10_28.md),
with ten bounded agent assignments, explicit acceptance tests and a same-day
decision target. It continues Alpha 0.4; it does not claim completion or start
Alpha 0.5 product expansion. The earlier [Alpha 0.4 plan](NEXT_GOAL_ALPHA_0_4.md)
and [Alpha 0.5 proposal](NEXT_GOAL_ALPHA_0_5.md) retain historical context.

## Starting evidence and open work

Published checkpoints include exact signed-event verification
(`ada368e`), original HTTP caller authority checks (`1819277`) and three separately
reviewed cleanup checkpoints. Diagnostic shutdown/restart/load and post-dispatch
tests have local evidence. The lifecycle batch and delivery machinery are now
published through `640ce8f`, but are not a qualified canonical image set.

Independent regression tests now cover authored nested `src/bin` inputs,
canonical physical-tree closure and security xattrs/capabilities. The narrow
integrity checkpoint initially failed closed on hardlinks; a bounded inode/layer
model is now implemented with independent synthetic regressions. Actual vendor
layer compatibility and canonical runtime payload qualification remain execution
gates. Candidate build, browser/revocation, CI and retained-artifact tooling are
implemented; their complete candidate execution remains unverified. Passing
offline tests do not establish canonical builds, two-build reproducibility,
the combined verifier, actual DOM/revocation/polling, hosted CI, attestation or
durable artifact retrieval; those execution gates remain unfinished or unverified.

[Alpha 0.3](ALPHA_0_3.md) and [VALIDATION.md](VALIDATION.md) retain earlier executed
results and their exact tested identities. GitHub publication works; hosted CI
status remains unknown because its API is blocked. Unresolved image findings and
advisory access remain explicit release blockers.

## Ordered development path

1. Preserve the implemented source/rootfs integrity protections and run their
   independent negatives. Preflight capacity/access and investigate frontend
   build randomness before expensive canonical builds.
2. Bound history responses and polling, prevent stale UI updates, enforce browser
   measurement limits and add packaged lifecycle acceptance. Execute actual DOM,
   same-unexpired-session DB revocation and measured polling/load qualification.
3. Complete applicable cleanup, audit/capture the coherent source, and build all
   required images and coordinator tools from fresh pinned containers. Preserve
   previous state and keys; verify actual runtime ABI and isolated namespaces.
4. Run the complete ordered verifier against those exact images and independently
   rebuild the same source. Compare binaries, runtime payloads and OCI bytes
   separately; retain full inventories and raw security findings.
5. Execute hosted CI/provenance production, retrieval and verification when
   access permits. Publish a durable evidence bundle and explicit passed/failed/
   blocked/not-run gate decision without substituting source publication for
   release eligibility.

## Team and publication

The current ten-role map is defined in the [completion plan](FINISH_GOAL_2026_10_28.md).
A/B own workspace/API, C governance, D builds, E security/provenance, F browser
verification and G service verification. H is the **sole Git publisher**; I is the
**sole shared-runtime coordinator**. J is the **separate dead-code cleanup owner**,
with no deletion quota. Root audits contracts, changes, evidence and release decisions.
Schedule these roles in waves within the available concurrency limit.

Keep ownership exclusive and freezes brief. H does not stage other agents' WIP.
Finish relevant cleanup before final candidate capture; later code changes create
a new candidate and rerun affected gates. Preserve active development/deferred
provider paths, framework dispatch, SQL sentinels, v2/v3 codecs, migrations,
historical proofs and uncertain receipts. No deletion quota applies.

## GovCloud production path after synthetic release qualification

Cloud identifiers and access are deferred at the user's request. Once available, confirm the target account, exact region and approved Bedrock model/features, then implement the application deployment rather than treating the current Terraform scaffold as a deployed service.

1. Establish the customer boundary and applicable contract clauses, NIST revision, CMMC level/assessment path, and FedRAMP authorization or equivalency requirements. Map each control to AWS, Nex.os, the customer or shared responsibility with dated scope evidence.
2. Replace synthetic identity and PKI with approved customer identity, workload certificates, rotation and revocation operations. Select and verify the required cryptographic modules and deployment configuration; ordinary TLS libraries do not establish FIPS qualification.
3. Implement approved storage, secret delivery, evidence/key custody and the fixed live Bedrock route. Validate service/model/region/API authorization scope and entitlement. Never silently fall back to another provider, model or region.
4. Deploy distinct task identities and private backend boundaries in GovCloud. Execute real worker-denial, provider, network, outage and recovery tests using synthetic payloads before any CUI.
5. Close software supply-chain and operating controls: reproducible provenance, vulnerability disposition, access review, monitoring, retention, backups, incident handling and assessor-reviewable evidence. Obtain the required operational and assessment approvals before real CUI use.

Keep on-premises packaging, Kubernetes, arbitrary terminal execution, broad connectors, vector search and multiregion deployment deferred until an actual requirement justifies them. A dedicated Ubuntu server is not required for managed AWS compute; Ubuntu remains a practical development host or a separately scoped future on-premises target.

## Readiness boundary

Engineering completion requires a successful clean canonical build, the complete
combined functional qualification and a completed measured reproducibility report.
Unrun internal gates do not satisfy it. An engineering-complete synthetic
candidate may have a documented blocked release decision while required external
scans/CI are unavailable. It cannot be called
release-eligible, reproducible or cryptographically attested without the matching
verified evidence. Preserve raw findings and failed attempts; no invented waivers,
severity reductions or normalization of unexplained payload differences.

No CUI, FedRAMP authorization, NIST control completion or CMMC certification is
claimed. Cloud preparation is optional only after candidate qualification; no
live AWS setup or product expansion is included in the current goal.
