mock_provider "aws" {
  mock_data "aws_caller_identity" { defaults = { account_id = "111122223333" } }
  mock_data "aws_partition" { defaults = { partition = "aws-us-gov" } }
  mock_data "aws_availability_zones" { defaults = { names = ["us-gov-west-1a", "us-gov-west-1b"] } }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012" }
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
}
run "private_foundation" {
  command = plan
  assert {
    condition     = alltrue([for s in aws_subnet.private : !s.map_public_ip_on_launch])
    error_message = "Workload subnets must not assign public addresses."
  }
  assert {
    condition     = length(aws_vpc_endpoint.interface) == 0 && length(aws_iam_role_policy.model) > 0
    error_message = "Unverified interface endpoints must not be created."
  }
  assert {
    condition     = jsondecode(aws_iam_role_policy.model.policy).Statement[0].Resource == var.model_arn
    error_message = "Model permission must bind the exact approved model."
  }
  assert {
    condition     = toset(jsondecode(aws_iam_role_policy.model.policy).Statement[0].Action) == toset(["bedrock:InvokeModel"])
    error_message = "The model role must grant only the non-streaming invocation action used by the adapter."
  }
  assert {
    condition     = length(aws_db_instance.production) == 0 && length(aws_security_group.db_clients) == 0
    error_message = "The database must remain opt-in for existing foundation deployments."
  }
}

run "private_database" {
  command   = apply
  state_key = "isolated_database"
  variables {
    production_database = {
      engine_version        = "17.7"
      instance_class        = "db.m7g.large"
      allocated_storage_gib = 50
      backup_retention_days = 14
    }
  }
  assert {
    condition = (
      !aws_db_instance.production[0].publicly_accessible &&
      aws_db_instance.production[0].storage_encrypted &&
      aws_db_instance.production[0].manage_master_user_password &&
      aws_db_instance.production[0].multi_az &&
      aws_db_instance.production[0].deletion_protection &&
      !aws_db_instance.production[0].skip_final_snapshot &&
      aws_db_instance.production[0].backup_retention_period == 14
    )
    error_message = "The database must be private, encrypted, managed-credentialed, resilient and protected."
  }
  assert {
    condition = (
      one(aws_db_parameter_group.production[0].parameter).name == "rds.force_ssl" &&
      one(aws_db_parameter_group.production[0].parameter).value == "1" &&
      aws_vpc_security_group_ingress_rule.database_client[0].from_port == 5432 &&
      aws_vpc_security_group_ingress_rule.database_client[0].referenced_security_group_id == aws_security_group.db_clients[0].id
    )
    error_message = "Database connections must require TLS and a separately assigned client security group."
  }
}

run "reject_weak_database_configuration" {
  command = plan
  variables {
    production_database = {
      engine_version        = "16.9"
      instance_class        = "db.m7g.large"
      allocated_storage_gib = 19
      backup_retention_days = 0
    }
  }
  expect_failures = [var.production_database]
}
run "reject_commercial_region" {
  command = plan
  variables { region = "us-east-1" }
  expect_failures = [var.region]
}
run "reject_commercial_model" {
  command = plan
  variables { model_arn = "arn:aws:bedrock:us-east-1::foundation-model/synthetic-test-model-v1" }
  expect_failures = [var.model_arn]
}
run "reject_other_govcloud_region_model" {
  command = plan
  variables { model_arn = "arn:aws-us-gov:bedrock:us-gov-east-1::foundation-model/synthetic-test-model-v1" }
  expect_failures = [var.model_arn]
}
