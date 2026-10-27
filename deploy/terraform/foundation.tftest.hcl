mock_provider "aws" {
  mock_data "aws_caller_identity" { defaults = { account_id = "111122223333" } }
  mock_data "aws_partition" { defaults = { partition = "aws-us-gov" } }
  mock_data "aws_availability_zones" { defaults = { names = ["us-gov-west-1a", "us-gov-west-1b"] } }
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
