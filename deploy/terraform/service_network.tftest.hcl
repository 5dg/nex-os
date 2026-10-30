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

run "network_disabled_by_default" {
  command = plan
  assert {
    condition     = length(aws_security_group.production_service) == 0 && length(aws_vpc_security_group_ingress_rule.service_connection) == 0
    error_message = "No production service identities or connections should be created by default."
  }
}

run "only_explicit_directed_connections" {
  command   = apply
  state_key = "isolated_service_network"
  variables {
    production_service_network = {
      services = ["workspace", "control", "guard"]
      connections = {
        workspace-control = { source = "workspace", destination = "control", port = 8080 }
        control-guard     = { source = "control", destination = "guard", port = 50051 }
      }
    }
  }
  assert {
    condition = (
      length(aws_security_group.production_service) == 3 &&
      length(aws_vpc_security_group_ingress_rule.service_connection) == 2 &&
      length(aws_vpc_security_group_egress_rule.service_connection) == 2 &&
      aws_vpc_security_group_egress_rule.service_connection["workspace-control"].security_group_id == aws_security_group.production_service["workspace"].id &&
      aws_vpc_security_group_ingress_rule.service_connection["workspace-control"].security_group_id == aws_security_group.production_service["control"].id &&
      aws_vpc_security_group_ingress_rule.service_connection["workspace-control"].from_port == 8080 &&
      aws_vpc_security_group_egress_rule.service_connection["control-guard"].to_port == 50051
    )
    error_message = "Only the specified directed TCP edges may be configured between per-service groups."
  }
}

run "reject_unselected_destination" {
  command = plan
  variables {
    production_service_network = {
      services = ["workspace", "control"]
      connections = {
        control-guard = { source = "control", destination = "guard", port = 50051 }
      }
    }
  }
  expect_failures = [var.production_service_network]
}

run "reject_invalid_connection" {
  command = plan
  variables {
    production_service_network = {
      services = ["workspace", "control"]
      connections = {
        bad = { source = "control", destination = "control", port = 65536 }
      }
    }
  }
  expect_failures = [var.production_service_network]
}

run "reject_duplicate_connection" {
  command = plan
  variables {
    production_service_network = {
      services = ["workspace", "control"]
      connections = {
        first  = { source = "workspace", destination = "control", port = 8080 }
        second = { source = "workspace", destination = "control", port = 8080 }
      }
    }
  }
  expect_failures = [var.production_service_network]
}
