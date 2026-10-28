# Nex.os development goal and implementation path

## Current goal: Alpha 0.5 synthetic release qualification

Finish the remaining Alpha 0.4 engineering and qualify one exact-source synthetic
release candidate before expanding the product. Bind clean pinned builds,
immutable images, actual browser/service tests, reproducibility measurements and
retained security evidence to the same captured revision.

The executable goal, dependency waves, gate criteria and seven-seat ownership map
are in [NEXT_GOAL_ALPHA_0_5.md](NEXT_GOAL_ALPHA_0_5.md). The
[Alpha 0.4 plan](NEXT_GOAL_ALPHA_0_4.md) remains historical context; Alpha 0.4 is not
being declared complete by naming the next goal.

## Starting evidence and open work

Published `main` through `56adf29` includes exact signed-event verification
(`ada368e`), original HTTP caller authority checks (`1819277`) and three separately
reviewed cleanup checkpoints. Diagnostic shutdown/restart/load and post-dispatch
tests have local evidence, but the corresponding lifecycle batch and new delivery
machinery are not a qualified canonical image set.

Current source integrity tooling can exclude authored nested `src/bin` files;
rootfs identity omits security xattrs/capabilities. Close those gaps before making
complete input/rootfs binding claims. Eleven passing offline tooling tests cover
specific negatives, not those missing guarantees. Canonical builds, two-build
comparison, the combined verifier, actual DOM/revocation/polling and hosted
CI/attestation/artifact retrieval remain unfinished or unverified.

[Alpha 0.3](ALPHA_0_3.md) and [VALIDATION.md](VALIDATION.md) retain earlier executed
results and their exact tested identities. GitHub publication works; hosted CI
status remains unknown because its API is blocked. Unresolved image findings and
advisory access remain explicit release blockers.

## Ordered development path

1. Close source-input and rootfs security-metadata integrity gaps with independent
   negatives; freeze performance, resource and reproducibility contracts.
2. Finish bounded lifecycle and operator fixes, then execute actual DOM,
   same-unexpired-session DB revocation and measured polling/load qualification.
3. Complete applicable cleanup, audit/capture the coherent source, and build all
   required images and coordinator tools from fresh pinned containers. Preserve
   previous state and keys; verify actual runtime ABI and isolated namespaces.
4. Run the complete ordered verifier against those exact images and independently
   rebuild the same source. Compare binaries, runtime payloads and OCI bytes
   separately; retain full inventories and raw security findings.
5. Complete hosted CI/provenance production, retrieval and verification when
   access permits. Publish a durable evidence bundle and explicit passed/failed/
   blocked/not-run gate decision without substituting source publication for
   release eligibility.

## Team and publication

A owns application/contracts/workspace, B governance/effects, C delivery/security
tooling and D independent verification. E is the **sole Git publisher and shared
runtime coordinator**; E pushes audited coherent checkpoints normally to `main`
and verifies the remote SHA. F is the **separate trailing dead-code purger**;
F proves consumer closure, receives an exclusive handoff, makes small deletions,
obtains independent review and sends a separate cleanup checkpoint through E.
Root audits contracts, implementation, evidence and release decisions.

Keep ownership exclusive and freezes brief. E does not stage other agents' WIP.
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
