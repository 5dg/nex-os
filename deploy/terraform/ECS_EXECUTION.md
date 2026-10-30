# ECS execution foundations

`production_execution` is opt-in. It creates one ECS execution role and one
CloudWatch Logs group for each explicitly selected service. It does not create
task definitions, services, ingress, networking rules, task roles or production
secrets. Null preserves the original foundation behavior. Verify the account,
region, service inventory, logging retention and operating cost before enabling.

Each execution role can obtain an ECR registry token, pull only its corresponding
repository, and create streams/write events only in its own precreated log
group. It has no application or secret access. AWS requires the registry-token
action to use resource `*`. Keep task identities separate from execution roles.

The selected customer-managed CloudWatch Logs KMS key must be in the approved
account and region. Its independently reviewed key policy must permit the
regional CloudWatch Logs service to use the key for the intended log-group
encryption context. This module does not edit that key policy. Validate the
regional `ecr.api`, `ecr.dkr` and `logs` private endpoints, S3 gateway access,
KMS permissions, log delivery and retention against the actual account.

The current application cannot yet be deployed as a production Fargate service:
production profiles and workload settings must be completed first, including
separate per-service task identities, exact image digests, health checks and
service discovery, mTLS trust and rotation, narrowly scoped security groups,
file-based secret delivery, production PostgreSQL roles and CA verification,
and durable evidence and receiver receipts. ECS secret environment injection
alone does not satisfy the existing file-based secret interface. Choose ingress,
DNS, identity and operational recovery only within the approved deployment
boundary. Do not attach the database-client security group broadly.

Log groups use a Terraform destroy guard to protect retained operational
evidence. Any intended removal or change to retention requires a reviewed
state and evidence-preservation procedure.
