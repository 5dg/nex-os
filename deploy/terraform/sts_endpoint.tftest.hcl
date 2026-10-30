mock_provider "aws" {
  mock_data "aws_caller_identity" { defaults = { account_id = "111122223333" } }
  mock_data "aws_partition" { defaults = { partition = "aws-us-gov" } }
  mock_data "aws_availability_zones" { defaults = { names = ["us-gov-west-1a", "us-gov-west-1b"] } }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012" }
  }
}
variables {
  account_id = "111122223333"
  model_arn  = "arn:aws-us-gov:bedrock:us-gov-west-1::foundation-model/synthetic-test-model-v1"
}

run "sts_endpoint_disabled_by_default" {
  command = plan
  assert {
    condition     = length(aws_vpc_endpoint.interface) == 0
    error_message = "Unverified STS endpoints must not be provisioned by default."
  }
}

run "explicit_standard_sts_endpoint" {
  command   = apply
  state_key = "isolated_sts_endpoint"
  variables { verified_interface_services = ["sts"] }
  assert {
    condition = (
      aws_vpc_endpoint.interface["sts"].service_name == "com.amazonaws.us-gov-west-1.sts" &&
      aws_vpc_endpoint.interface["sts"].vpc_endpoint_type == "Interface" &&
      aws_vpc_endpoint.interface["sts"].private_dns_enabled &&
      toset(aws_vpc_endpoint.interface["sts"].subnet_ids) == toset(aws_subnet.private[*].id) &&
      toset(aws_vpc_endpoint.interface["sts"].security_group_ids) == toset([aws_security_group.endpoints.id]) &&
      aws_vpc_security_group_egress_rule.endpoint_https.referenced_security_group_id == aws_security_group.endpoints.id &&
      aws_vpc_security_group_egress_rule.endpoint_https.to_port == 443
    )
    error_message = "The selected standard STS endpoint must use private subnets, endpoint SG and scoped HTTPS egress."
  }
}

run "reject_unverified_sts_fips" {
  command = plan
  variables { verified_interface_services = ["sts-fips"] }
  expect_failures = [var.verified_interface_services]
}
