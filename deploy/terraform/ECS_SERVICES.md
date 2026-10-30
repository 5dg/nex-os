# Zero-task ECS service scaffolds

`production_service_scaffolds` is null by default. Explicitly selected service
names must have matching reviewed task revisions and per-service network
identities. Each created Fargate service has its desired count fixed at zero,
uses the existing private foundation subnets, has no public IP and disables ECS
Exec. The input cannot start application tasks or enable production traffic.
It configures no load balancer, external ingress, DNS or service discovery.
The zero count is Terraform's configured state, not an IAM boundary: an
authorized out-of-band `UpdateService`, `RunTask` or separate autoscaling
configuration can start tasks. Restrict and independently verify those
permissions and automation in the target account before applying this module.

Each scaffold attaches its own per-service security group and the existing
workload endpoint group. These rules combine: the latter allows only reviewed
endpoint and S3 egress but is shared across tasks. Review the resulting paths
and actual endpoint/resource policies; security groups do not establish identity.
Only explicitly selected control, guard or workspace services can additionally
receive the database-client group, and only when the opt-in database exists.
That network access does not create SQL users or grant database permissions.

The scaffold uses Fargate platform version 1.4.0, a deployment circuit breaker
and rollback, and the fixed task revision from the reviewed input. Confirm
regional platform support, subnet routing, network overlaps, KMS key policies,
account identity and cost in a real plan. A zero-task service has not been
observed starting an application and provides no availability or health claim.

Before changing the code to permit a nonzero task count, complete and independently
test the production profile, file-secret delivery, customer identity, service
discovery, mutual TLS, workload-specific SQL roles, fenced durable receipt and
evidence storage, readiness/health behavior, monitored recovery and release
evidence. Define and verify approved ingress separately. The required Fargate,
network, IAM and recovery checks must execute against the actual authorized
environment; mocked Terraform tests cover configuration behavior only.
