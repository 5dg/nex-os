mock_provider "aws" {
  mock_data "aws_caller_identity" { defaults = { account_id = "111122223333" } }
  mock_data "aws_partition" { defaults = { partition = "aws-us-gov" } }
  mock_data "aws_availability_zones" { defaults = { names = ["us-gov-west-1a", "us-gov-west-1b"] } }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012" }
  }
  mock_resource "aws_ecr_repository" {
    defaults = {
      arn            = "arn:aws-us-gov:ecr:us-gov-west-1:111122223333:repository/mock"
      repository_url = "111122223333.dkr.ecr.us-gov-west-1.amazonaws.com/mock"
    }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws-us-gov:logs:us-gov-west-1:111122223333:log-group:mock" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws-us-gov:iam::111122223333:role/mock" }
  }
  mock_resource "aws_ecs_cluster" {
    defaults = { id = "arn:aws-us-gov:ecs:us-gov-west-1:111122223333:cluster/mock" }
  }
  mock_resource "aws_ecs_task_definition" {
    defaults = { arn = "arn:aws-us-gov:ecs:us-gov-west-1:111122223333:task-definition/mock:1" }
  }
  mock_resource "aws_service_discovery_private_dns_namespace" {
    defaults = { id = "ns-test" }
  }
  mock_resource "aws_service_discovery_service" {
    defaults = {
      arn                        = "arn:aws-us-gov:servicediscovery:us-gov-west-1:111122223333:service/srv-test"
      health_check_custom_config = [{ failure_threshold = 1 }]
    }
  }
}
variables {
  account_id = "111122223333"
  model_arn  = "arn:aws-us-gov:bedrock:us-gov-west-1::foundation-model/synthetic-test-model-v1"
  production_execution = {
    services           = ["control", "model"]
    logs_kms_key_arn   = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
    log_retention_days = 90
  }
  production_service_network = { services = ["control", "model"], connections = {} }
  production_task_templates = {
    bootstrap_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    services = {
      control = {
        image_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        cpu          = 256, memory_mib = 512, uid = 65532, gid = 65532
        secrets = { db-url = {
          app_file_env = "DATABASE_URL_FILE"
          secret_arn   = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:nex-db-abcdef"
          kms_key_arn  = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
          base64       = false
        } }
      }
      model = {
        image_digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        cpu          = 256, memory_mib = 512, uid = 65532, gid = 65532
        secrets = { model-key = {
          app_file_env = "MODEL_KEY_FILE"
          secret_arn   = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:nex-key-abcdef"
          kms_key_arn  = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
          base64       = true
        } }
      }
    }
  }
  production_service_scaffolds = { services = ["control", "model"] }
}

override_resource {
  target = aws_security_group.workloads
  values = { id = "sg-00000000000000001" }
}
override_resource {
  target = aws_security_group.production_service["control"]
  values = { id = "sg-00000000000000002" }
}
override_resource {
  target = aws_security_group.production_service["model"]
  values = { id = "sg-00000000000000003" }
}
override_resource {
  target = aws_subnet.private[0]
  values = { id = "subnet-00000000000000001" }
}
override_resource {
  target = aws_subnet.private[1]
  values = { id = "subnet-00000000000000002" }
}

run "discovery_disabled_by_default" {
  command = plan
  assert {
    condition = length(aws_service_discovery_private_dns_namespace.production) == 0 && length(aws_service_discovery_service.production) == 0 && alltrue([
      for service in values(aws_ecs_service.production_scaffold) : length(service.service_registries) == 0 && service.desired_count == 0
    ])
    error_message = "Default scaffolds must have no discovery and no tasks."
  }
}

run "discovery_details" {
  command   = apply
  state_key = "discovery_diagnostics"
  variables {
    production_service_discovery = { namespace = "nex.example.internal", ttl = 30, services = ["control"] }
  }
  assert {
    condition     = aws_service_discovery_private_dns_namespace.production[0].name == "nex.example.internal"
    error_message = "Namespace name differs."
  }
  assert {
    condition     = aws_service_discovery_private_dns_namespace.production[0].vpc == aws_vpc.main.id
    error_message = "Namespace VPC differs."
  }
  assert {
    condition     = length(aws_service_discovery_service.production) == 1 && aws_service_discovery_service.production["control"].name == "control"
    error_message = "Service selection differs."
  }
  assert {
    condition     = aws_service_discovery_service.production["control"].dns_config[0].namespace_id == aws_service_discovery_private_dns_namespace.production[0].id
    error_message = "Service namespace differs."
  }
  assert {
    condition     = aws_service_discovery_service.production["control"].dns_config[0].routing_policy == "MULTIVALUE"
    error_message = "Routing policy differs."
  }
  assert {
    condition     = one(aws_service_discovery_service.production["control"].dns_config[0].dns_records).type == "A" && one(aws_service_discovery_service.production["control"].dns_config[0].dns_records).ttl == 30
    error_message = "DNS record differs."
  }
  assert {
    condition     = aws_service_discovery_service.production["control"].health_check_custom_config[0].failure_threshold == 1
    error_message = "Health threshold differs."
  }
  assert {
    condition     = aws_ecs_service.production_scaffold["control"].service_registries[0].registry_arn == aws_service_discovery_service.production["control"].arn
    error_message = "Control registry differs."
  }
  assert {
    condition     = length(aws_ecs_service.production_scaffold["model"].service_registries) == 0
    error_message = "Unselected model has a registry."
  }
  assert {
    condition     = alltrue([for service in values(aws_ecs_service.production_scaffold) : service.desired_count == 0])
    error_message = "Scaffold count differs."
  }
  assert {
    condition     = output.production_service_discovery_names == tomap({ control = "control.nex.example.internal" })
    error_message = "Discovery output differs."
  }
}

run "attach_only_selected_service" {
  command   = apply
  state_key = "service_discovery"
  variables {
    production_service_discovery = { namespace = "nex.example.internal", ttl = 30, services = ["control"] }
  }
  assert {
    condition = (
      aws_service_discovery_private_dns_namespace.production[0].name == "nex.example.internal" &&
      aws_service_discovery_private_dns_namespace.production[0].vpc == aws_vpc.main.id &&
      length(aws_service_discovery_service.production) == 1 &&
      aws_service_discovery_service.production["control"].name == "control" &&
      aws_service_discovery_service.production["control"].dns_config[0].namespace_id == aws_service_discovery_private_dns_namespace.production[0].id &&
      aws_service_discovery_service.production["control"].dns_config[0].routing_policy == "MULTIVALUE" &&
      one(aws_service_discovery_service.production["control"].dns_config[0].dns_records).type == "A" &&
      one(aws_service_discovery_service.production["control"].dns_config[0].dns_records).ttl == 30 &&
      aws_service_discovery_service.production["control"].health_check_custom_config[0].failure_threshold == 1 &&
      aws_ecs_service.production_scaffold["control"].service_registries[0].registry_arn == aws_service_discovery_service.production["control"].arn &&
      length(aws_ecs_service.production_scaffold["model"].service_registries) == 0 &&
      alltrue([for service in values(aws_ecs_service.production_scaffold) : service.desired_count == 0]) &&
      output.production_service_discovery_names == tomap({ control = "control.nex.example.internal" })
    )
    error_message = "Only the matching zero-task service may attach to the selected private registry."
  }
}

run "reject_missing_scaffold" {
  command = plan
  variables {
    production_service_discovery = { namespace = "nex.example.internal", ttl = 30, services = ["guard"] }
  }
  expect_failures = [var.production_service_discovery]
}

run "reject_invalid_namespace" {
  command = plan
  variables {
    production_service_discovery = { namespace = "bad..domain", ttl = 30, services = ["control"] }
  }
  expect_failures = [var.production_service_discovery]
}

run "reject_invalid_ttl" {
  command = plan
  variables {
    production_service_discovery = { namespace = "nex.example.internal", ttl = 301, services = ["control"] }
  }
  expect_failures = [var.production_service_discovery]
}

run "reject_empty_service_set" {
  command = plan
  variables {
    production_service_discovery = { namespace = "nex.example.internal", ttl = 30, services = [] }
  }
  expect_failures = [var.production_service_discovery]
}
