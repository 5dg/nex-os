# Policy edge candidate

This process is a candidate mTLS boundary for an OPA engine listening only on
`127.0.0.1:8182` in the same task network namespace. It does not deploy OPA,
enable any application production profile, or prove production readiness. OPA
must contain exactly the Guard-pinned policy and must not expose its management
API outside that task. The edge exposes only policy-source reads and decision
requests, forwards no caller-controlled headers, limits request and response
sizes and concurrent requests, and revalidates both certificate chains after
the upstream response.

Startup requires `APP_ENV=production`, explicit `NEX_POLICY_EDGE_ENABLED=true`,
`NEX_POLICY_LISTEN_ADDR`, `NEX_POLICY_SERVER_CA_FILE`,
`NEX_POLICY_CLIENT_CA_FILE`, `NEX_POLICY_CERT_FILE`, `NEX_POLICY_KEY_FILE` and
the exact configured `NEX_POLICY_GUARD_URI`. The URI must be a SPIFFE URI; only
a client certificate containing that single URI and chaining to the configured
client CA is accepted. The server key pair must chain to the separately
configured server CA and have the single URI `spiffe://nex.local/service/opa`
expected by the current Guard verifier. That compatibility does not establish
production certificate issuance or trust custody. TLS 1.3 and client certificates are mandatory. Paths
refer to operator-controlled private files, not tenant input. TLS peer checks
must also be enforced by clients; this process does not establish DNS identity
on their behalf. Secrets and private keys do not belong in Terraform state,
logs or image layers.

Credentials are loaded at startup; rotation requires a reviewed restart and
overlap of trusted issuers where appropriate. Certificate revocation, issuance,
provisioning, trust-root custody and live rotation are not implemented here.
Verify those controls, certificate DNS names and URI uniqueness independently.
All containers in an ECS task share a network namespace and task role: isolate
OPA and edge from unrelated containers, restrict task inspection and ECS Exec,
and test that OPA management endpoints are inaccessible from other workloads.
Network rules are not workload identity.

The pinned canonical Go compiler emits `bin/policy-edge` and binds its hash and
mode in the compiler-phase export record. The standalone
`deploy/production/Dockerfile.policy-edge.runtime` is a scratch candidate
recipe for the canonical runtime-root and bin build context. It is not part of
the current release image set, and it has not been built or scanned here. The
host development build also records the binary hash without claiming an
attestation. Verify exact source and provenance before using either output.

This candidate has not been packaged into an approved, scanned image or wired
to an ECS service. Guard's production profile and production execution remain
closed. Before deployment, verify the exact image and policy bytes, security
findings, service identity issuance and rollover, private routing, authentication,
failure handling, platform behavior and monitoring in the approved environment.
