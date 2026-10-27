# Nex.os: goal and implementation path

## Product goal

Build Nex.os Alpha 0.1 as a governed AI workspace for defense contractors handling Controlled Unclassified Information (CUI). Deploy the reference environment into an isolated customer AWS GovCloud account, use an explicitly approved Amazon Bedrock route for inference, and require Nex.Guard to authorize every protected model, data, and tool operation.

An authenticated user must be able to start a durable document-review job, retrieve only permitted information, receive a model-generated response, request an export, obtain approval for that exact export, and inspect the resulting execution evidence. Unauthorized requests, modified or replayed approvals, revoked delegation, and direct worker access to protected resources must fail within the documented threat model.

Build the application controls and operating evidence needed to support the applicable NIST requirements, CMMC assessment, and FedRAMP requirements. AWS controls may be inherited only within their verified scope. An alpha demonstration is not an authorization or certification.

## First-release demonstration

Use synthetic documents and two test tenants. One user starts a compliance-record review. The job retrieves authorized excerpts and calls an approved Bedrock model. The worker proposes exporting the result to one configured destination. Nex.Guard pauses the job, presents the precise export to an authorized approver, rechecks current permissions, and permits one logical export operation. The workspace shows the result, citations, approval, and sanitized audit history.

Repeat with another tenant's document, an altered export destination, an expired or reused approval, revoked delegation, a failed policy dependency, an unavailable model, and a worker restart. Show the expected denial or recovery for each case. Verify actual IAM and network restrictions in GovCloud before claiming those controls work.

## Decisions to hold stable during the alpha

| Area | Initial choice |
|---|---|
| First customer | Defense contractor handling CUI |
| Deployment unit | One isolated customer GovCloud account and one approved region |
| Region candidate | `us-gov-west-1`, subject to service and model preflight |
| Application compute | ECS/Fargate if the verified capabilities meet the workload requirements; record any necessary alternative |
| Workspace | Next.js, React, TypeScript; administration inside the same application |
| Control plane | Go: API, identity integration, job scheduling, registries, and integration adapters |
| Governance kernel | Rust: authoritative execution revalidation, approval decisions/consumption, and required evidence |
| Internal contracts | Versioned Protobuf/gRPC for Go and Rust |
| Policy engine | OPA/Rego, accessible through trusted services only |
| Model adapter | Separate Go workload using the AWS SDK and its own restricted IAM role |
| Agent worker | Go initially; add Python only when a concrete requirement justifies it |
| Tool executor | Separate controlled workload; one fixed export implementation initially |
| State and job queue | PostgreSQL, versioned migrations, leases, heartbeats, and transactional claims |
| Document bodies | S3 in GovCloud; a clearly identified local adapter for development |
| Initial retrieval | Metadata and text search with permission filtering; add embeddings/pgvector only when retrieval quality requires them |
| Infrastructure | Terraform and GovCloud ECR |
| Development | Docker Compose; no dedicated Ubuntu server required |
| Identity | Customer OIDC provider in deployment; explicit development issuer locally |

Use one repository. Keep logical modules together while maintaining separate credentials, permissions, and deployment boundaries for trusted services, agent workers, and tool executors. Do not give agent workers direct access to the database, S3, Bedrock, or connector secrets.

## Scope and deployment gates

The alpha includes identity, tenant isolation, bounded delegation, deny-by-default authorization, a durable job, one model route, controlled document ingestion and retrieval, one approval-protected export, and inspectable audit evidence.

Defer arbitrary customer code, terminal execution, broad connector support, a marketplace, self-hosted models, on-premises packaging, Kubernetes, multiregion operation, and elaborate agent planning. Start with an explicit review workflow that can pause and resume.

Before processing real CUI, confirm the system boundary, applicable contract clauses, NIST publication and revision, CMMC level and assessment path, and FedRAMP baseline and authorization/equivalency requirements. Obtain appropriate assessment and operational sign-off. CMMC applies to the scoped organization and systems; AWS authorization does not automatically authorize Nex.os.

Record whether each control is inherited from AWS, implemented by Nex.os, operated by the customer, or shared. Include support access, software updates, identity, logging, backups, incident response, and external dependencies in that responsibility matrix.

Verify the exact Bedrock region, model, APIs/features, entitlement, destination-region behavior, permissions, and required service authorization scope. Record dated evidence. Never silently substitute a model, region, or provider. Local development uses synthetic data until its environment and tooling are approved for anything more sensitive.

## Implementation sequence

### 1. Establish contracts and a runnable foundation

Create the repository layout, pinned tool versions, local containers, database migrations, structured error format, and CI. Define versioned contracts for identity/delegation, jobs, action requests, policy decisions, approvals, model invocations, document references, and audit events. Resolve actor, tenant, resource classification, and approval validity from trusted records.

Add an explicit development model adapter with deterministic responses. Production configuration must reject it. Start Terraform scaffolding and the GovCloud service/model preflight in parallel with local implementation; unavailable cloud access blocks cloud validation, not independent local work.

**Acceptance:** A clean checkout can start dependencies and the application, apply migrations, and execute meaningful integration tests. Setup can be repeated without losing existing data. Development and real-provider modes are visibly distinguishable.

### 2. Implement identity, tenant boundaries, and Guard

Validate OIDC issuer, audience, signature, expiry, and server-side tenant membership. Define bounded delegation with expiry and revocation. Add a typed action catalog and default-deny policies. Guard derives authoritative facts and records policy digests and decision reasons. Protected operations fail closed when required authorization dependencies are unavailable.

Use a small predefined role set and tool catalog. Avoid building a general policy authoring interface before the enforcement path works.

**Acceptance:** Tests with two tenants demonstrate denied cross-tenant access, forged identity/metadata rejection, expired or revoked delegation rejection, and failure when policy evaluation is unavailable. Unregistered actions are denied.

### 3. Complete the first durable Bedrock job and deploy it early

Persist job transitions, claim work with leases, and support cancellation and crash recovery. The restricted worker requests model access through Guard. The trusted adapter validates a scoped execution authorization, selects the registered model route, enforces limits, and invokes Bedrock. Stream or poll job progress in the workspace.

Deploy this small slice into the reference GovCloud environment now. Establish distinct task roles, private backend access, a tested endpoint/egress design, secret delivery, and protected database access. Use synthetic payloads for the first live invocation.

**Acceptance:** An authenticated user submits a job and receives a real Bedrock response in the approved region. Worker restart preserves progress. An unavailable model produces an explicit error. Actual worker attempts to access Bedrock and protected storage directly fail. Record local and GovCloud results separately.

### 4. Add permission-aware document review

Ingest a controlled set of documents with tenant, owner, classification, source, version, and access metadata. Retrieve only authorized excerpts before creating model context. Return citations. Protect derived content, stored answers, and conversation history according to their sources. Recheck permissions when material is reused.

Do not add semantic search merely to satisfy a technology list. Demonstrate that simple retrieval meets the initial use case, then add embeddings behind the same authorization contract if necessary.

**Acceptance:** The job answers from permitted documents with correct citations. Another tenant's documents are excluded. Revoked access prevents subsequent retrieval or reuse. Retrieved prompt instructions cannot grant tool permissions or alter trusted identity.

### 5. Add exact approvals and one controlled export

Define a canonical export request covering actor/delegation, action, tenant, document versions or content digests, destination, and expiry. Require approval for the exact request. Recheck current authority before execution. Atomically consume approval while reserving one logical operation; retries refer to that operation rather than creating another authorized action.

Use an idempotency key and a controlled export destination. An action that may have succeeded before a crash must enter an explicit unknown/reconciliation state when its outcome cannot be established. Never promise exactly-once external effects without a supporting provider contract.

**Acceptance:** Approval-required jobs pause and resume. Changed destinations or content, unauthorized approvers, expired approvals, concurrent consumption, and replay attempts fail. Crash/retry tests demonstrate the supported duplicate-prevention behavior and surface uncertain outcomes.

### 6. Complete evidence, recovery, and the pilot release gates

Persist authorization and execution-intent evidence before protected effects. Use a transactional outbox for reliable evidence delivery, then protected append-only storage, integrity checks, and separately controlled signing/key custody. Specify outage behavior and capture outcomes without logging prompts, secrets, or CUI bodies by default. An outbox alone is not immutable evidence.

Complete vulnerability and dependency management, artifact provenance, hardened configurations, encryption-module requirements, access reviews, incident procedures, retention, and backup/restore testing. Validate controls with actual commands and requests, not only Terraform declarations. Collect assessor-reviewable evidence and track unresolved risks.

**Acceptance:** A reviewer can trace the user, delegation, resource, model route, policy decision, approval, execution, and outcome. Defined tampering is detected within the documented threat model. Backup restoration preserves application, policy, and audit consistency. Required controls and operational responsibilities have evidence and owners.

## Repository layout

```text
apps/workspace/
services/control/
services/guard-kernel/
services/model/
services/worker/
services/tool-executor/
packages/contracts/
policies/
deploy/local/
deploy/terraform/
tests/integration/
tests/security/
docs/architecture/
docs/compliance/
docs/runbooks/
```

## Rules for efficient implementation

1. Build one end-to-end workflow before expanding the service catalog. Each milestone must leave a runnable system.
2. Keep changes small and testable. Implement contracts, persistence, behavior, and relevant tests together. Update shared contracts deliberately.
3. Avoid additional frameworks, languages, services, or abstractions without a current requirement. Preserve the few provider interfaces needed for explicit development adapters and future deployment options.
4. Make local development reproducible and noninteractive. Provide documented commands for startup, migration, tests, local verification, and GovCloud verification. Use pinned dependencies and preserve signature/TLS verification.
5. Test the properties that can break: isolation, authorization, concurrency, approval integrity, crash recovery, provider errors, and actual cloud restrictions. Do not substitute a mock result for live cloud evidence.
6. Use synthetic data in CI and ordinary development tools. Keep secrets outside the repository and model context. Reuse configured authentication; never invent credentials or request secret values in chat.
7. Keep a short decision record, control matrix, and evidence index current. Report passed, failed, blocked, and unrun checks distinctly.
8. Use the existing checkout in this isolated cloud task. Do not create a Git worktree unless the user explicitly requests one.
9. Stop expanding scope once the milestone's required checks pass. Diagnose failures before retrying. Preserve working outputs and focus on the next unmet acceptance criterion.

## Alpha definition of done

Nex.os can be installed reproducibly, deployed into the verified GovCloud reference environment, and complete the synthetic document-review/approval/export demonstration using real Bedrock inference. Required denial, restart, reconciliation, network, and recovery checks pass. The deployment has documented boundaries, inherited/customer/application control responsibilities, operating procedures, an evidence index, and an explicit unresolved-risk register.

Report local functionality, live cloud enforcement, assessment readiness, and formal authorization/certification as separate outcomes. Real-CUI production use requires the applicable assessment, contractual, and operational gates; a passing alpha demonstration does not satisfy those gates by itself.

## Current implementation and next deployment step

The local synthetic review/approval/export workflow is implemented using Go orchestration, Rust enforcement and gRPC. See docs/VALIDATION.md for executed checks and docs/architecture/GO_RUST_BOUNDARY.md for ownership and failure semantics.

Live GovCloud/Bedrock/customer identity setup is deferred at the user's request. When those prerequisites are available, validate the intended identity, exact service/model scope and approved region; complete the production storage/transport/cryptographic/infrastructure adaptations and run actual cloud enforcement tests. Preserve the local controls and explicit failure semantics. Do not substitute a development model result for real Bedrock evidence or claim production CUI readiness from local tests.
