# Initial control responsibility matrix

This is a scoping/evidence worksheet, not a completed control assessment. Confirm applicable NIST publications/revisions, CMMC level and assessment path, contractual clauses, and FedRAMP baseline/authorization or equivalency requirements with the customer and assessors. No real CUI is approved for this development environment.

| Area | AWS contribution to verify | Nex.os contribution | Customer/operator responsibility | Current evidence |
|---|---|---|---|---|
| Infrastructure | Exact authorized services/features/regions and inherited package | Constrain deployment to verified scope | Approve boundary and inheritance | Terraform validation/mock tests only; cloud deferred |
| Identity/access | IAM and selected identity capabilities | Go token verification; Rust live authorization; separate service and DB roles | Customer IdP, MFA, lifecycle, access reviews, trusted identity-adapter operation | Local OIDC/tenant/delegation and role tests |
| Data protection | Approved S3/RDS/KMS and cryptographic capabilities | ACL/classification/version checks; revalidation before result reuse and effects | Data scope, classification, retention and destinations | Synthetic SQL fixture storage; cross-tenant/version/integrity tests |
| Approvals | Infrastructure only | Exact request binding, independent human authority, single-operation consumption in Rust | Approver assignments and process | Expiry/replay/mutation/concurrency/revocation tests |
| Audit | CloudTrail, logging/storage and key-management capabilities | Producer-bound signed chain; intent/outcome separation; proof verification | Independent custody, retention, review, external anchors and response | Local signing, tamper detection, source isolation and restore checks |
| Configuration/supply chain | Managed service configuration evidence | Pinned tools/dependencies/images, migrations, CI definition | Release approval, vulnerability management and administrative access | Local builds/static checks; hosted CI and full scanning/provenance remain unrun |
| Recovery | Approved backup capabilities | Durable jobs, lease fencing, receipts and state consistency | Production encrypted backups, key recovery, RPO/RTO and exercises | Disposable local DB restore and pinned journal verification |
| Operations/personnel | Applicable inherited provider controls | Support/update procedures and auditable boundaries | Screening/training, incident response, reporting and organizational controls | Not assessed |
| Model processing | Exact approved Bedrock model/API/region scope | Typed adapter, bounds, no fallback; model output cannot grant authority | Entitlements, quotas, classification/use approval and residency | SDK provider-stub tests; live invocation deferred |

The development signing key and plaintext local storage/transport are not asserted to satisfy a required FIPS configuration. Production must use an approved cryptographic and custody path. CMMC assesses the scoped organization/systems; AWS authorization does not automatically authorize Nex.os.
