# Nex.os — governed AI workspace

A governed AI workspace for defense-contractor CUI use cases. Alpha 0.3 is a **synthetic-data qualification profile** using Go orchestration, a Rust Nex.Guard kernel, gRPC, PostgreSQL, OPA, and a Next.js workspace. Actual local identity, workflow and lifecycle checks passed; release and regulated-production gates remain open. Live GovCloud deployment, approved Bedrock invocation, and customer identity configuration are deferred at the user's request.

Start with the [Alpha 0.4 goal and agent plan](docs/NEXT_GOAL_ALPHA_0_4.md), [current build plan](docs/BUILD_PLAN.md), [Alpha 0.3 executed evidence](docs/ALPHA_0_3.md), and [qualification runbook](docs/runbooks/QUALIFICATION.md).

## Working demonstration

In the qualification profile, Alice signs in through the synthetic OIDC fixture, reviews Contractor A's admitted synthetic record using a fixed question, and requests an export. Carol signs in independently, inspects the exact preview/destination/digest, and approves or rejects it. Alice loads the job reference to inspect delivery and signed evidence. Bob and Dave provide Contractor B identities for isolation checks. Persona minting is disabled in this profile.

The separate development lab retains explicit persona selection for Alice, Carol, Bob and Dave. Its historical workflow remains supported.

The development issuer deliberately mints personas without authentication. The qualification issuer has fixture credential-based login; neither is a customer identity provider or evidence of real MFA. Model responses are deterministic and clearly labeled. No real CUI is permitted in either profile.

## Architecture and ownership

| Component | Implementation | Authority |
|---|---|---|
| Workspace | Next.js/TypeScript | Presents jobs, approvals, previews and evidence |
| Control plane | Go | OIDC token verification, trusted identity resolution, scheduling, job state and integration APIs |
| Nex.Guard | Rust + gRPC | Immutable operation preparation, exact payload revalidation, approval/consumption, protected result provenance and signed evidence |
| Policy rules | OPA/Rego | Versioned deny/allow/approval rules; source digest validated by both runtimes |
| Model adapter | Go | Receives broker-bound requests; asks Rust directly before invoking its configured provider |
| Export executor | Go | One controlled local destination; asks Rust directly before effects |
| Evidence writer | Go | Hash-chained, signed records; separate control/kernel producer identities; signing seed mounted only here |
| State | PostgreSQL | Separate runtime roles; Go cannot rewrite protected inputs, manifests, operation digests, results or approval decisions |
| Cloud foundation | Terraform | GovCloud preparation only; no live application deployment |

Go/Rust contracts are in [guard.proto](packages/contracts/proto/nex/guard/v1/guard.proto). HTTP contracts are in [openapi.json](packages/contracts/openapi.json). See [the boundary decision](docs/architecture/GO_RUST_BOUNDARY.md).

An `Evaluate` response is a policy decision. Rust `PrepareExecution` resolves and seals an immutable v3 manifest in qualification (v2 remains supported for development/history), and receivers independently call `AuthorizeExecution` with a digest of the actual semantic payload. Rust reconstructs the expected content and rechecks current authority before granting one start. Receivers report durable results through `CompleteExecution`; Go cannot write protected answers/artifacts directly. Human approval remains independent of model output and binds permanently to one logical export operation.

The workspace can check a recorded outcome after an interrupted completion. This path never repeats execution. A retry reuses the same pending operation and is available only after a positively known pre-execution failure. Missing storage or an uncertain effect cannot justify a retry. Legacy/unsealed history is preserved; a new governed review is required to produce a verified result from a legacy answer.

## Reproduce locally

For the current TLS/OIDC profile use the [qualification runbook](docs/runbooks/QUALIFICATION.md). Its `build-host` path is an explicitly labeled diagnostic candidate; the pinned container build and complete combined verifier remain Alpha 0.4 execution gates. The commands below reproduce the separate development lab.

Prerequisites: Docker/Compose, Make, Python 3, Node 24.19.0, Go 1.27.3, Rust 1.99.1, and Terraform 1.17.0 for infrastructure checks. Linux amd64 cloud tasks can use the verified/pinned installers:

```bash
./scripts/bootstrap.sh
./scripts/bootstrap-rust.sh
export PATH="/workspace/.tools/go/bin:/workspace/.tools/cargo/bin:/workspace/.tools:$PATH"
export GOPATH=/workspace/.tools/gopath GOCACHE=/tmp/nex-go-cache
export CARGO_HOME=/workspace/.tools/cargo RUSTUP_HOME=/workspace/.tools/rustup
./scripts/check-contracts.sh --install-tools
make dev
make verify-local
make terraform-check
terraform -chdir=deploy/terraform test
```

On another machine, install the versions in `.tool-versions`/`rust-toolchain.toml`, fetch frozen Go/Cargo/npm dependencies, and run `make dev`. Go Protobuf output is checked in; `check-contracts.sh` reproduces it with pinned plugins. Cargo generates Rust types using a lock-file-verified vendored compiler.

`make dev` compiles Go/Rust, builds thin local images, applies checksum-protected migrations, ingests the synthetic fixture set without replacing existing records, provisions local service/database identities, starts services and waits for readiness. Compilation occurs on the host because the managed Docker daemon uses VFS and duplicates large build layers. TLS and package checksum verification remain enabled. The combined CA reaches networked Docker build steps through a BuildKit secret; registry credentials and proxy defaults are preserved.

`make start` restarts prepared images without building. Use it for unchanged restored environments. `make down` preserves the database volume. Never use `down --volumes` without authorizing data deletion. Tools, images, local identities, receipts and data may be retained; live processes must restart.

The workspace uses local port 3000; the review page is `/workflow`. API, development issuer, OPA debug access and PostgreSQL use loopback-only ports 8080, 8081, 8181 and 5432. No hosted preview is configured. Internal readiness/smoke commands validate managed cloud instances.

## Verification

The [Alpha 0.3 evidence](docs/ALPHA_0_3.md) records actual HTTPS/OIDC/BFF and Go/Rust service checks, receiver negatives, PKI rotation and isolated restore. These browser-flow tests use HTTP clients; actual browser-engine/React acceptance is planned for Alpha 0.4.

`make verify-local` includes reproducible Go code generation and Go/Rust digest vectors, race-enabled Go tests, actual Rust gRPC/PostgreSQL/OPA integration, policy tests, workspace requests, database ownership checks, worker network probes, recovery requests and a disposable restore. Integration tests require their dependencies and do not silently skip.

`python3 scripts/verify-restore.py` first stops this project's ingress and state writers, then restores synthetic PostgreSQL data into a disposable database, compares application/security/manifest/result/audit fingerprints, verifies a copied journal against its pinned signed checkpoint, and verifies copied receiver receipt bytes and completed/uncertain lookup behavior. It preserves the original data and restarts the existing service images. This controlled local quiescence does not qualify a production live backup, encryption, custody, RPO or RTO.

The worker has only its broker identity mounted and cannot reach database, model, executor, Guard, evidence or OPA endpoints directly. These are local container results, not proof of AWS IAM/VPC enforcement.

Signed records distinguish `control` and `kernel` producers. The API verifies event contents against their signatures and returns the metadata/proof needed for independent verification with `packages/evidence.VerifyEvent`. The public verification key is `.local/evidence-public`; private signing material is not mounted into Go control, Rust Guard, or workers. Pin public keys/checkpoints outside this host to detect privileged rollback. `bin/evidence verify .local/evidence .local/evidence-public` verifies the local chain.

## Explicit remaining deployment gates

The local database/admin bootstrap, synthetic issuer, plaintext internal development transport, local receipt/document storage, and development cryptography are not approved CUI infrastructure. Real document bodies currently use a synthetic PostgreSQL fixture adapter; S3-backed ingestion is part of cloud integration. Export goes only to the executor's private local directory. Production configurations reject these local services or require an approved transport configuration.

The Bedrock SDK adapter is implemented and tested with a provider stub for exact routing, bounds and failure behavior. No live model invocation occurred. GovCloud identity, exact model/feature authorization scope, entitlements, quotas, customer OIDC, production workload identity/TLS, applicable validated cryptographic modules, managed storage/secrets/key custody, full ECS/RDS/ingress infrastructure, operational assurance and assessment remain required before real-CUI production use.

See [historical Alpha 0.2 validation](docs/VALIDATION.md) and [Alpha 0.3 evidence](docs/ALPHA_0_3.md), [control responsibilities](docs/compliance/CONTROL_RESPONSIBILITIES.md), [risk register](docs/compliance/RISKS.md) and [the build plan](docs/BUILD_PLAN.md). AWS inheritance, NIST requirements, CMMC scope and FedRAMP authorization/equivalency must be established for the deployment; this alpha confers no certification.
