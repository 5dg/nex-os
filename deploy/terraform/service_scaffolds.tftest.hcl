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
  mock_resource "aws_db_instance" {
    defaults = {
      master_user_secret = [{
        kms_key_id    = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
        secret_arn    = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:mock"
        secret_status = "active"
      }]
    }
  }
}
variables {
  account_id = "111122223333"
  model_arn  = "arn:aws-us-gov:bedrock:us-gov-west-1::foundation-model/synthetic-test-model-v1"
  production_execution = {
    services           = ["control"]
    logs_kms_key_arn   = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
    log_retention_days = 90
  }
  production_service_network = { services = ["control"], connections = {} }
  production_task_templates = {
    bootstrap_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    services = {
      control = {
        image_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        cpu          = 256, memory_mib = 512, uid = 65532, gid = 65532
        secrets = {
          db-url = {
            app_file_env = "DATABASE_URL_FILE"
            secret_arn   = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:nex-db-abcdef"
            kms_key_arn  = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
            base64       = false
          }
        }
      }
    }
  }
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
  target = aws_security_group.db_clients[0]
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

run "service_disabled_by_default" {
  command = plan
  assert {
    condition     = length(aws_ecs_service.production_scaffold) == 0
    error_message = "No ECS service should be created by default."
  }
}

run "zero_task_private_service" {
  command   = apply
  state_key = "isolated_service_scaffold"
  variables {
    production_service_scaffolds = { services = ["control"] }
  }
  assert {
    condition = (
      aws_ecs_service.production_scaffold["control"].desired_count == 0 &&
      aws_ecs_service.production_scaffold["control"].launch_type == "FARGATE" &&
      aws_ecs_service.production_scaffold["control"].platform_version == "1.4.0" &&
      !aws_ecs_service.production_scaffold["control"].enable_execute_command &&
      !aws_ecs_service.production_scaffold["control"].network_configuration[0].assign_public_ip &&
      toset(aws_ecs_service.production_scaffold["control"].network_configuration[0].subnets) == toset(aws_subnet.private[*].id) &&
      toset(aws_ecs_service.production_scaffold["control"].network_configuration[0].security_groups) == toset([aws_security_group.production_service["control"].id, aws_security_group.workloads.id]) &&
      length(aws_ecs_service.production_scaffold["control"].load_balancer) == 0 &&
      length(aws_ecs_service.production_scaffold["control"].service_registries) == 0
    )
    error_message = "The scaffold must have zero tasks, private network attachments, no ingress/discovery and ECS Exec disabled."
  }
}

run "reject_missing_network_identity" {
  command = plan
  variables {
    production_service_network   = null
    production_service_scaffolds = { services = ["control"] }
  }
  expect_failures = [var.production_service_scaffolds]
}

run "reject_missing_task_revision" {
  command = plan
  variables {
    production_task_templates    = null
    production_service_scaffolds = { services = ["control"] }
  }
  expect_failures = [var.production_service_scaffolds]
}

run "explicit_database_client" {
  command   = apply
  state_key = "service_with_database"
  variables {
    production_database = {
      engine_version        = "17.7"
      instance_class        = "db.m7g.large"
      allocated_storage_gib = 50
      backup_retention_days = 14
    }
    production_service_scaffolds = { services = ["control"], database_clients = ["control"] }
  }
  assert {
    condition = (
      aws_ecs_service.production_scaffold["control"].desired_count == 0 &&
      toset(aws_ecs_service.production_scaffold["control"].network_configuration[0].security_groups) == toset([
        aws_security_group.production_service["control"].id,
        aws_security_group.workloads.id,
        aws_security_group.db_clients[0].id
      ])
    )
    error_message = "Only an explicitly selected database client receives the additional client group."
  }
}

run "reject_database_client_without_database" {
  command = plan
  variables {
    production_service_scaffolds = { services = ["control"], database_clients = ["control"] }
  }
  expect_failures = [var.production_service_scaffolds]
}

run "reject_unselected_database_client" {
  command = plan
  variables {
    production_service_scaffolds = { services = ["control"], database_clients = ["model"] }
  }
  expect_failures = [var.production_service_scaffolds]
}

run "reject_model_database_client" {
  command = plan
  variables {
    production_execution = {
      services           = ["model"]
      logs_kms_key_arn   = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
      log_retention_days = 90
    }
    production_service_network = { services = ["model"], connections = {} }
    production_database = {
      engine_version        = "17.7"
      instance_class        = "db.m7g.large"
      allocated_storage_gib = 50
      backup_retention_days = 14
    }
    production_task_templates = {
      bootstrap_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      services = {
        model = {
          image_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          cpu          = 256, memory_mib = 512, uid = 65532, gid = 65532
          secrets = {
            model-key = {
              app_file_env = "MODEL_KEY_FILE"
              secret_arn   = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:nex-key-abcdef"
              kms_key_arn  = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
              base64       = true
            }
          }
        }
      }
    }
    production_service_scaffolds = { services = ["model"], database_clients = ["model"] }
  }
  expect_failures = [var.production_service_scaffolds]
}
