# GovCloud foundation

This is milestone-1 scaffolding, not a complete application deployment or an assessed compliance boundary. It creates private networking, optional verified interface endpoints, encrypted/versioned document storage, immutable-tag ECR repositories, an ECS cluster, and distinct task roles. Only the model role receives Bedrock permissions, bound to one explicit regional foundation-model ARN.

Application task definitions, execution roles, RDS, ingress/TLS, service-to-service identity, endpoint resource policies, audit storage/signing, DNS controls, monitoring, backups, and live bypass tests remain required before deployment readiness. Security groups alone do not establish full egress isolation. S3 access through its gateway endpoint still requires resource and identity controls.

Use Terraform 1.17.0. Run `terraform init -backend=false`, `terraform validate`, and `terraform test` here. Tests use mocked provider data and make no claims about live IAM enforcement or service availability. `.terraform.lock.hcl` pins provider versions/checksums.

Before planning against AWS, run `scripts/govcloud-preflight.sh`, verify the model and service authorization scope independently, and provide `account_id` and `model_arn` through non-secret Terraform inputs. Populate `verified_interface_services` only from the regional inventory. Use an approved encrypted remote state backend and access controls before a real deployment; this scaffold does not configure one automatically. Never put credentials or CUI in Terraform variables/state.
