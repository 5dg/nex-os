mock_provider "aws" {
  mock_data "aws_caller_identity" { defaults = { account_id = "111122223333" } }
  mock_data "aws_partition" { defaults = { partition = "aws-us-gov" } }
  mock_data "aws_availability_zones" { defaults = { names = ["us-gov-west-1a", "us-gov-west-1b"] } }
}
variables {
  account_id = "111122223333"
  model_arn  = "arn:aws-us-gov:bedrock:us-gov-west-1::foundation-model/synthetic-test-model-v1"
  production_export_access = {
    bucket_name           = "nex-reviewed-exports"
    prefix                = "approved/tenant-exports/"
    kms_key_arn           = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
    s3_bucket_key_enabled = false
  }
}

run "historical_access_disabled_by_default" {
  command = plan
  assert {
    condition     = length(aws_iam_role_policy.production_export_history_access) == 0
    error_message = "Historical KMS access must not be granted by default."
  }
}

run "only_reviewed_key_context_pairs" {
  command   = apply
  state_key = "isolated_export_history"
  variables {
    production_export_history_access = [
      { kms_key_arn = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/87654321-4321-4321-4321-210987654321", s3_bucket_key_enabled = false },
      { kms_key_arn = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012", s3_bucket_key_enabled = true },
      { kms_key_arn = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/87654321-4321-4321-4321-210987654321", s3_bucket_key_enabled = true }
    ]
  }
  assert {
    condition = (
      aws_iam_role_policy.production_export_history_access[0].role == aws_iam_role.task["tool-executor"].id &&
      aws_iam_role_policy.production_export_history_access[0].role != aws_iam_role.task["model"].id &&
      length(jsondecode(aws_iam_role_policy.production_export_history_access[0].policy).Statement) == 3 &&
      alltrue([for statement in jsondecode(aws_iam_role_policy.production_export_history_access[0].policy).Statement : (
        toset(statement.Action) == toset(["kms:Decrypt"]) &&
        statement.Condition.StringEquals["kms:ViaService"] == "s3.us-gov-west-1.amazonaws.com"
      )]) &&
      jsondecode(aws_iam_role_policy.production_export_history_access[0].policy).Statement[0].Resource == var.production_export_history_access[0].kms_key_arn &&
      jsondecode(aws_iam_role_policy.production_export_history_access[0].policy).Statement[0].Condition.StringLike["kms:EncryptionContext:aws:s3:arn"] == "arn:aws-us-gov:s3:::nex-reviewed-exports/approved/tenant-exports/*" &&
      jsondecode(aws_iam_role_policy.production_export_history_access[0].policy).Statement[1].Resource == var.production_export_access.kms_key_arn &&
      jsondecode(aws_iam_role_policy.production_export_history_access[0].policy).Statement[1].Condition.StringLike["kms:EncryptionContext:aws:s3:arn"] == "arn:aws-us-gov:s3:::nex-reviewed-exports" &&
      jsondecode(aws_iam_role_policy.production_export_history_access[0].policy).Statement[2].Resource == var.production_export_history_access[2].kms_key_arn &&
      jsondecode(aws_iam_role_policy.production_export_history_access[0].policy).Statement[2].Condition.StringLike["kms:EncryptionContext:aws:s3:arn"] == "arn:aws-us-gov:s3:::nex-reviewed-exports" &&
      length(aws_iam_role_policy.production_export_history_access[0].policy) + length(aws_iam_role_policy.production_export_access[0].policy) <= 10240
    )
    error_message = "Historical decrypt grants must preserve each exact key/context pair, executor role and IAM aggregate size."
  }
  assert {
    condition = (
      jsondecode(aws_iam_role_policy.production_export_access[0].policy).Statement[1].Condition.StringEquals["s3:x-amz-server-side-encryption-aws-kms-key-id"] == var.production_export_access.kms_key_arn &&
      toset(jsondecode(aws_iam_role_policy.production_export_access[0].policy).Statement[3].Action) == toset(["kms:GenerateDataKey", "kms:Decrypt"])
    )
    error_message = "Historical decrypt permissions must not widen the current-key write policy."
  }
}

run "reject_missing_current_destination" {
  command = plan
  variables {
    production_export_access = null
    production_export_history_access = [
      { kms_key_arn = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/87654321-4321-4321-4321-210987654321", s3_bucket_key_enabled = false }
    ]
  }
  expect_failures = [var.production_export_history_access]
}

run "reject_foreign_key" {
  command = plan
  variables {
    production_export_history_access = [
      { kms_key_arn = "arn:aws-us-gov:kms:us-gov-west-1:999988887777:key/87654321-4321-4321-4321-210987654321", s3_bucket_key_enabled = false }
    ]
  }
  expect_failures = [var.production_export_history_access]
}

run "reject_duplicate_pair" {
  command = plan
  variables {
    production_export_history_access = [
      { kms_key_arn = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/87654321-4321-4321-4321-210987654321", s3_bucket_key_enabled = false },
      { kms_key_arn = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/87654321-4321-4321-4321-210987654321", s3_bucket_key_enabled = false }
    ]
  }
  expect_failures = [var.production_export_history_access]
}

run "reject_current_pair_duplicate" {
  command = plan
  variables {
    production_export_history_access = [
      { kms_key_arn = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012", s3_bucket_key_enabled = false }
    ]
  }
  expect_failures = [var.production_export_history_access]
}
