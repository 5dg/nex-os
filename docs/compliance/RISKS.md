# Local-alpha limitations and deployment gates

| Item | Current state | Required before regulated production |
|---|---|---|
| GovCloud and Bedrock | Deferred at user's request; SDK and infrastructure foundation prepared | Intended identity/account, exact model/feature scope, entitlements, quotas, residency and successful live checks |
| Customer identity | Development issuer/personas; JWT verification functional | Customer issuer, browser sign-in/session controls, MFA and lifecycle procedures |
| Transport/crypto | Local authenticated HTTP/gRPC; development signing | Approved TLS/workload identity, applicable validated modules and key management; current production configurations fail rather than silently use local transport |
| Data storage | Controlled synthetic PostgreSQL fixture adapter and local receipts | Governed S3 ingestion, approved encrypted persistence/retention and secret delivery |
| Authority boundaries | Rust-owned immutable manifests, exact receiver binding, protected outcomes and approval consumption; separate DB/executor identities | Production provisioning/rotation and live IAM/VPC/DNS/metadata/IPv4/IPv6 tests |
| Trusted administrator | Local bootstrap uses an explicitly trusted development administrator | Protected administrator credentials, separation of duties, approved operating access and review |
| Audit custody | Signed producer-bound local journal and proof verification | Protected retention, independent key custody and external checkpoint anchors; combined host/key compromise is outside local guarantees |
| Unknown effects | Durable receipt states prevent blind repetition | Provider-specific reconciliation procedures and operational review; do not claim exactly-once external effects |
| Budgets/abuse controls | Bounded prompt/output and one fixed review invocation per job | Tenant budgets, quotas, ingress/rate limits and monitoring for the intended workload |
| Recovery | Local state/manifest/result/journal/receipt restore with controlled quiescence demonstrated | Encrypted production backups, key recovery and tested operational RPO/RTO |
| Supply chain | Locked dependencies/images, reproducible contracts, source software inventory and local checks; unavailable vulnerability feeds are reported explicitly | Hosted CI, continuous vulnerability scanning, SBOM/provenance, update/response process |
| Assessment | Control matrix and engineering evidence only | Agreed boundary/baseline/contracts, SSP, inherited package evidence, assessment and required authorization/certification |

Development identities, fixture contents and storage are deliberately synthetic. These limitations prevent a CUI production-readiness claim. They do not invalidate the local governed review/approval/export demonstration.
