mock_provider "aws" {
  mock_data "aws_caller_identity" { defaults = { account_id = "111122223333" } }
  mock_data "aws_partition" { defaults = { partition = "aws-us-gov" } }
  mock_data "aws_availability_zones" { defaults = { names = ["us-gov-west-1a", "us-gov-west-1b"] } }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012" }
  }
  mock_resource "aws_ecr_repository" {
    defaults = { arn = "arn:aws-us-gov:ecr:us-gov-west-1:111122223333:repository/mock" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws-us-gov:logs:us-gov-west-1:111122223333:log-group:mock" }
  }
}
variables {
  account_id = "111122223333"
  model_arn  = "arn:aws-us-gov:bedrock:us-gov-west-1::foundation-model/synthetic-test-model-v1"
}

run "execution_disabled_by_default" {
  command = plan
  assert {
    condition     = length(aws_iam_role.production_execution) == 0 && length(aws_cloudwatch_log_group.production_service) == 0
    error_message = "No execution identities or log groups should be created by default."
  }
}

run "isolated_execution" {
  command   = apply
  state_key = "isolated_execution"
  variables {
    production_execution = {
      services           = ["control", "workspace"]
      logs_kms_key_arn   = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
      log_retention_days = 90
    }
  }
  assert {
    condition = (
      length(aws_iam_role.production_execution) == 2 &&
      aws_cloudwatch_log_group.production_service["control"].name == "/ecs/nex-reference/control" &&
      aws_cloudwatch_log_group.production_service["workspace"].retention_in_days == 90 &&
      aws_cloudwatch_log_group.production_service["workspace"].kms_key_id == var.production_execution.logs_kms_key_arn
    )
    error_message = "Each selected service needs its own encrypted log group and execution role."
  }
  assert {
    condition = alltrue([for service in var.production_execution.services : (
      jsondecode(aws_iam_role_policy.production_execution[service].policy).Statement[0].Action == ["ecr:GetAuthorizationToken"] &&
      jsondecode(aws_iam_role_policy.production_execution[service].policy).Statement[0].Resource == "*" &&
      jsondecode(aws_iam_role_policy.production_execution[service].policy).Statement[1].Resource == aws_ecr_repository.application[service].arn &&
      jsondecode(aws_iam_role_policy.production_execution[service].policy).Statement[2].Resource == "${trimsuffix(aws_cloudwatch_log_group.production_service[service].arn, ":*")}:*" &&
      length(jsondecode(aws_iam_role_policy.production_execution[service].policy).Statement) == 3
    )])
    error_message = "Execution permissions must be limited to the registry token, the service's ECR repository and its own log group."
  }
}

run "reject_unapproved_key_and_retention" {
  command = plan
  variables {
    production_execution = {
      services           = ["control"]
      logs_kms_key_arn   = "arn:aws:kms:us-east-1:111122223333:key/unapproved"
      log_retention_days = 7
    }
  }
  expect_failures = [var.production_execution]
}
