# ECS runtime integration contract

This document defines the implementation work needed to connect the opt-in
database, execution-role, logging and service-network foundations. It is not a
task definition, deployment approval or production-readiness assertion.

## Task and image identity

The opt-in task templates register separate Fargate task revisions and execution
identities with exact ECR image digests, constrained Fargate CPU/memory, a
non-root application UID, read-only root filesystem and optional explicit port.
They scope image pulls to the service and bootstrap repositories and log writes
to the service log group. The application task role is separate from the
execution role; its final service-specific permissions still need review. The
model role's inline policy selects one approved regional Bedrock action.

Task definitions and services must remain gated until the application profile,
health checks, service discovery and production configuration exist and pass
tests. A syntactically valid task definition is not proof a service can start,
serve traffic or preserve state. Decide service counts from the proven custody
and recovery model; do not scale stateful receivers using ephemeral task disks.

## Secret and trust delivery

Current services consume private files, including database URLs, workload
credentials, TLS private keys and the shared control history-cursor key. The
workspace PostgreSQL session precursor uses separate private database URL and
32-byte encryption-key files, plus a CA file and exact DB hostname; its tested
synthetic integration does not open the production profile. Do not inject the
RDS administrator credential into applications.

ECS secret environment injection does not create these files. The opt-in task
templates use a reviewed bootstrap to materialize supplied values in a
task-private volume and gate application startup on its success. The intended
ownership, permissions, isolation, failure behavior and image digest still
require verification on the target Fargate platform. The bootstrap environment
is sensitive, and containers in one task share its network and task role; this
is not per-container IAM isolation. No secret values belong in Terraform
variables, state, task definitions, logs or public artifacts. Scope delivery to
exact secret ARNs and authorized KMS decryption; restrict task inspection and
ECS Exec. See `ECS_TASK_TEMPLATES.md` and `services/secret-bootstrap/README.md`.

Review TLS certificate issuance, per-service identities and SANs, trust roots,
rotation overlap and restart behavior. Changing a single shared cursor key can
invalidate live continuations; support and test the intended rotation window.
Verify PostgreSQL TLS using the exact endpoint hostname and trusted CA with
`sslmode=verify-full`. Verify service-to-service mutual TLS and authorization;
security-group membership alone is not service identity.

## Durable state and recovery

The current model and export receivers store receipts in private local
directories. The evidence service stores its journal locally and uses a local
Ed25519 seed. `packages/broker/custody.go` explicitly describes its file lock
as local custody, not a distributed lease. Its durability contract also uses
file and directory `fsync`, locks and atomic rename. Fargate task replacement
must not discard these records or make an uncertain effect replayable.

Implement and test transactional shared custody with fencing and independent
evidence anchoring before enabling the affected production services. A proposed
shared filesystem needs verified locking, sync, recovery, ownership and
cross-replica semantics; mounting it alone is not evidence of those properties.
Define service-specific database roles, grants, managed credentials, migration
ownership, backup/restore and no-repeat tests. Preserve existing signed evidence
interpretation and all accepted, started and unknown-effect records.

Database commit durability alone does not prove failover safety: an asynchronous
promotion or snapshot rollback can erase a previously acknowledged `started`
receipt. Establish and test a synchronous RPO-zero failover guarantee, or stop
admission and independently reconcile every operation potentially lost since the
last trusted recovery point before resuming. A database fence cannot cancel an
external effect already in flight; its outcome remains conservatively unknown.

## Network, ingress and acceptance

Explicit service-network groups may be combined with narrowly scoped endpoint
and database-client groups. Their rules are additive. Define actual directed
connections from reviewed application interfaces; test positive and negative
paths. The existing private foundation does not select an ingress boundary,
domain, external OIDC egress path, ALB-to-workspace TLS termination model,
DNS zone or service-discovery mechanism. Confirm and implement these with the
approved customer deployment inputs rather than introducing a general-purpose
internet route.

Before any service activation, verify account/region, image provenance,
private registry and logs endpoints, actual KMS key policies, customer identity
configuration, database and service credentials, durable custody, a reviewed
infrastructure plan, workload readiness and operational recovery. Then test
real service startup, authorization denial, mTLS, shutdown, task replacement,
rotation and restore against the approved environment. Production deployment
remains incomplete until these integration and acceptance checks pass.
