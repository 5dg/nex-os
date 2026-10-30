# Managed export adapter

The S3 export adapter in `services/tool-executor/s3_export.go` is a preparatory component. It is not connected to the executor server or any production profile. Passing its local tests does not establish that a deployment is production ready.

A trusted service configuration must identify one AWS partition, account, region, bucket, regional S3 endpoint, regional STS endpoint, KMS key ARN, assumed-role name, destination identifier, object prefix and bounded request timeout. Endpoints must match the AWS SDK's exact standard or FIPS resolution for that route. Each operation captures one credential set, checks its lifetime, and uses that same set for STS caller identity and S3 requests. TLS verification, configured CA trust and proxy behavior remain in force. The adapter restricts requests to the resolved hosts and disables SDK retries and redirects.

The export operation binds the object key and receipt to the tenant, operation and canonical execution digest. It writes once with an expected bucket owner, `If-None-Match: *`, a SHA-256 checksum and the configured SSE-KMS key. It requires a version ID and checks the precise version, contents, metadata and encryption. A failed or ambiguous provider response, including a conditional conflict, is unknown and must not trigger a second write. Reading or replaying a receipt requires a fresh, independently authenticated current-authority check. Retrieval additionally requires the complete original, trusted `contracts.Export` payload so its canonical digest and contents can be verified; any future control flow must supply it securely.

Before activation, the deployment must establish and verify:

- Real Guard-authenticated caller and workload identity, tenant and result-scope authorization, including a fresh authority check for every read and replay, plus a one-shot effect authorization.
- A durable receipt store and recovery protocol that fences admission across in-flight operations and pauses and reconciles potentially lost or uncertain operations after failover or restore. A point-in-time fence check alone is insufficient.
- An explicitly approved account, role, regional route and KMS custody policy; least-privilege workload permissions; private bucket access; bucket ownership and versioning; and retention, Object Lock where needed, deletion, replacement and lifecycle policies that prevent keys from being reopened or rewritten. Conditional PUT alone does not establish these properties.
- Real AWS integration tests, operational monitoring and recovery procedures for the selected target. The current tests use an in-memory receipt stub and a local TLS server behind the actual AWS SDK transport; they do not validate live AWS policies or infrastructure.

Production server wiring and readiness must remain closed until these prerequisites and the deployment configuration are verified.
