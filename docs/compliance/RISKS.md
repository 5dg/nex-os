# Local-alpha limitations and deployment gates

| Item | Current state | Required before regulated production |
|---|---|---|
| GovCloud and Bedrock | Deferred at user's request; SDK and infrastructure foundation prepared | Intended identity/account, exact model/feature scope, entitlements, quotas, residency and successful live checks |
| Customer identity | Qualification has synthetic OIDC sign-in, strict API access tokens and bounded in-memory browser sessions; development personas remain separate | Approved customer issuer, actual MFA, account lifecycle/revocation operations and production session design |
| Transport/crypto | Qualification has verified TLS 1.3 workload identities and targeted expiry regression checks; PostgreSQL TLS is checked at connection establishment; development plaintext paths remain | Approved production trust/rotation/revocation, applicable validated modules and key management; production configuration remains rejected |
| Data storage | Controlled synthetic PostgreSQL fixture adapter and local receipts | Governed S3 ingestion, approved encrypted persistence/retention and secret delivery |
| Authority boundaries | Rust-owned immutable manifests, exact receiver binding, protected outcomes and approval consumption; separate DB/executor identities | Production provisioning/rotation and live IAM/VPC/DNS/metadata/IPv4/IPv6 tests |
| Trusted administrator | Local bootstrap uses an explicitly trusted development administrator | Protected administrator credentials, separation of duties, approved operating access and review |
| Audit custody | Signed producer-bound local journal and proof verification | Protected retention, independent key custody and external checkpoint anchors; combined host/key compromise is outside local guarantees |
| Unknown effects | Durable receipt states prevent blind repetition | Provider-specific reconciliation procedures and operational review; do not claim exactly-once external effects |
| Budgets/abuse controls | Bounded prompt/output and one fixed review invocation per job | Tenant budgets, quotas, ingress/rate limits and monitoring for the intended workload |
| Recovery | Actual PKI rotation and isolated quiescent database/custody restore preserved protected results and signed history; original state retained | Encrypted production backups, key recovery and tested operational RPO/RTO |
| Supply chain | Locked dependencies/images, source and six-image OS inventories, retained vulnerability findings and local qualification checks; main publication verified; hosted CI status unknown/API lookup forbidden | Verified hosted CI, executed pinned Rust builder and complete verifier, artifact provenance, unresolved-finding disposition and update/response process |
| Assessment | Control matrix and engineering evidence only | Agreed boundary/baseline/contracts, SSP, inherited package evidence, assessment and required authorization/certification |

Development identities, fixture contents and storage are deliberately synthetic. These limitations prevent a CUI production-readiness claim. They do not invalidate the local governed review/approval/export demonstration.
