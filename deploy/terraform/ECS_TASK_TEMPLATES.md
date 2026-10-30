# Unactivated ECS task revisions

`production_task_templates` is null by default. With explicit inputs it creates
an immutable-tag bootstrap ECR repository, an optional separate workspace task
role, narrowly scoped per-service execution-role additions and Fargate task
definition revisions. It does not create ECS services, run tasks, attach network
groups, configure public ingress or claim production readiness. The task's
`APP_ENV` and `NEX_PROFILE` are set to `production`; current application guards
remain closed until their production dependencies are implemented and verified.
Restrict who can register or run task definitions in the actual account.

Select only services already present in `production_execution`, with exact
SHA-256 image digests from their corresponding ECR repositories. Publish and
verify the separately reviewed bootstrap image at its supplied digest before any
approved task execution. Each task uses a fixed service entrypoint, explicit
non-root UID/GID and supported Fargate CPU/memory combination, a read-only root
filesystem, all application capabilities dropped and a 75-second stop timeout.
Both entrypoint and command are explicit: workspace runs `node /app/server.js`,
other application binaries receive `serve`, and the bootstrap receives `run`.
Current binaries accept or ignore those arguments; future images must independently
verify this command contract before task activation.
The optional listen port must be 1024–65535. A subset of AWS Fargate CPU sizes
through 4096 CPU units is supported; choose reviewed resource and cost bounds.
Task revisions use `skip_destroy` to preserve older revisions for reviewed
rollback; retirement still needs an explicit operational procedure.

Every task has one nonessential bootstrap container and starts the application
only after the bootstrap exits successfully. Its two fresh task-private volumes
are mounted read/write for initialization; the application receives the secret
volume read-only and a distinct writable `/tmp` volume. The bootstrap runs as
root with the Docker default capabilities dropped individually except CHOWN,
and independently fails if effective or permitted capabilities exceed CHOWN.
AWS ECS API documentation permits individual capability drops on Fargate and
supports `SUCCESS` dependencies on nonessential containers; the actual Fargate
platform's capabilities, volume ownership, isolation and fsync behavior still
require direct verification before deployment. A local Linux probe does not
establish those properties for Fargate.

Each secret-file entry supplies an exact same-account/region Secrets Manager
secret ARN, an exact customer-managed KMS key ARN, the application `*_FILE`
environment name from a service-specific allowlist, and whether its string value
is base64 encoded. Values are
injected only into the bootstrap container by ECS; Terraform receives ARNs and
non-secret layout metadata, never secret contents. Application `*_FILE` values
refer to private files under `/run/nex-secrets`. Key policies and regional
private endpoint access must independently permit the approved execution role;
the IAM policy restricts retrieval to the specified ARNs and KMS decryption to
Secrets Manager with one exact key/secret encryption-context pair per statement.
ECS injection makes the
bootstrap's environment sensitive to authorized inspection and execution
mechanisms. Containers in one task share its network and task role; this setup
does not establish per-container IAM or network isolation. Restrict ECS Exec,
task inspection and related permissions, and review the complete task boundary.
The Terraform precondition checks the aggregate size of the two inline policies
managed here against the IAM role quota. Other inline policies attached outside
this module also consume the same quota and must be reviewed in the target
account; Terraform cannot infer their size from these definitions.

The extra `environment` map is for non-secret configuration only. Validation
rejects common secret-shaped names, private-key markers, credentials in URLs,
reserved AWS/profile variables, loader/trust/proxy overrides and `*_FILE` overrides, but cannot prove arbitrary
values are non-secret. Never put credentials or customer data there or in
Terraform state. Configure file names and environment keys to match the final
reviewed service interfaces; do not inject the database administrator secret.

Task revisions alone are insufficient for production. Service/task roles,
customer identity, mTLS trust and rotation, durable fenced receipt/evidence
storage, verified database roles and TLS, policy/OPA connectivity, health
checks, service discovery, ingress, monitoring, backups and tested recovery
remain required. Configure and independently test those controls before adding
or activating ECS services. No live AWS or Fargate validation is claimed here.
