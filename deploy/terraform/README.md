# GovCloud foundation

This is milestone-1 scaffolding, not a complete application deployment or an assessed compliance boundary. It creates private networking, optional verified interface endpoints, encrypted/versioned document storage, immutable-tag ECR repositories, an ECS cluster, and distinct task roles. Only the model role receives Bedrock permissions, bound to one explicit regional foundation-model ARN.

The inline model policy grants only `bedrock:InvokeModel`, the permission used
by the current non-streaming Converse adapter. Verify all effective attached
role policies in the target account before claiming the same live boundary.

Optional execution roles, digest-pinned task revisions, zero-desired-count ECS
services and utilization alarms are available as unactivated precursors; see
`ECS_EXECUTION.md`, `ECS_TASK_TEMPLATES.md`, `ECS_SERVICES.md` and
`SERVICE_ALARMS.md`. The production application profiles remain closed, and
these definitions do not establish that any service can start or serve traffic.
Ingress/TLS, service-to-service identity, endpoint resource policies, durable
audit storage/signing, DNS controls, application health monitoring, operational
recovery and live bypass tests remain required. Security groups alone do not
establish full egress isolation. S3 access through its gateway endpoint still
requires resource and identity controls.

An opt-in PostgreSQL 17 RDS foundation is available through `production_database`. Its engine minor version, instance class, storage size and backup retention must be explicitly chosen after verifying regional availability and cost; leaving the variable null adds no database resources. The provisioned instance uses private subnets, encrypted storage, AWS-managed master credentials, TLS-required PostgreSQL settings, Multi-AZ, backups and deletion protection. Terraform's destroy guard requires an intentional reviewed change before replacement or deletion. The fixed final snapshot identifier must be reviewed for uniqueness before any approved removal.

Optional database capacity alarms are described in [DATABASE_ALARMS.md](DATABASE_ALARMS.md). They require explicitly selected thresholds and notification configuration and do not establish database or application readiness.

Optional private Cloud Map discovery for selected zero-count ECS services is described in [SERVICE_DISCOVERY.md](SERVICE_DISCOVERY.md). It does not enable workloads or establish service identity.

The database-client security group is not attached by the database foundation
itself. The optional zero-count service scaffold can attach it only to
explicitly selected control, guard or workspace services when a database is
configured. Network access does not create SQL users or grants. The managed
master secret is for database administration and bootstrap, not an application
credential. This foundation does not provision per-service SQL users, configure
application connections, enforce client certificate verification, create
database monitoring/alerts, or establish tested backup restoration. The selected
RDS CA and application `sslmode=verify-full` trust configuration remain necessary.

Use Terraform 1.17.0. Run `terraform init -backend=false`, `terraform validate`, and `terraform test` here. Tests use mocked provider data and make no claims about live IAM enforcement or service availability. `.terraform.lock.hcl` pins provider versions/checksums.

Before planning against AWS, set `NEX_GOV_REGION`, `NEX_APPROVED_ACCOUNT_ID`, and `NEX_BEDROCK_MODEL_ID` to the confirmed non-secret deployment inputs and set `NEX_PREFLIGHT_REPORT` to a fresh, nonexistent report path. Run `scripts/govcloud-preflight.sh`. The preflight checks that the authenticated account and ARN match the approved account before querying the exact model and regional endpoint inventory. It creates the report exclusively with mode 0600 and refuses existing paths or symlinks, so an earlier report cannot be mistaken for a new run. Verify model and service authorization scope independently, and provide `account_id` and `model_arn` through non-secret Terraform inputs. Populate `verified_interface_services` only from the regional inventory. Use an approved encrypted remote state backend and access controls before a real deployment; this scaffold does not configure one automatically. Never put credentials or CUI in Terraform variables/state.

The standard regional `sts` interface endpoint is opt-in through that same
verified inventory. The managed export precursor uses STS `GetCallerIdentity`;
it needs a reachable approved regional endpoint and endpoint policy even though
that operation does not require an IAM allow. Confirm actual regional DNS,
endpoint availability, trust and policy behavior before use. STS FIPS endpoint
service names are not enabled by this scaffold and need separate verification.
