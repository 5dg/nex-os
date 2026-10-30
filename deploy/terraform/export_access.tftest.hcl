mock_provider "aws" {
  mock_data "aws_caller_identity" { defaults = { account_id = "111122223333" } }
  mock_data "aws_partition" { defaults = { partition = "aws-us-gov" } }
  mock_data "aws_availability_zones" { defaults = { names = ["us-gov-west-1a", "us-gov-west-1b"] } }
}
variables {
  account_id = "111122223333"
  model_arn  = "arn:aws-us-gov:bedrock:us-gov-west-1::foundation-model/synthetic-test-model-v1"
}

run "export_disabled_by_default" {
  command = plan
  assert {
    condition     = length(aws_iam_role_policy.production_export_access) == 0
    error_message = "Export access must not be granted by default."
  }
}

run "object_key_mode" {
  command   = apply
  state_key = "isolated_export_object_key"
  variables {
    production_export_access = {
      bucket_name           = "nex-reviewed-exports"
      prefix                = "approved/tenant-exports/"
      kms_key_arn           = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
      s3_bucket_key_enabled = false
    }
  }
  assert {
    condition = (
      aws_iam_role_policy.production_export_access[0].role == aws_iam_role.task["tool-executor"].id &&
      aws_iam_role_policy.production_export_access[0].role != aws_iam_role.task["model"].id &&
      length(jsondecode(aws_iam_role_policy.production_export_access[0].policy).Statement) == 4 &&
      toset(jsondecode(aws_iam_role_policy.production_export_access[0].policy).Statement[0].Action) == toset(["s3:GetBucketVersioning"]) &&
      jsondecode(aws_iam_role_policy.production_export_access[0].policy).Statement[0].Resource == "arn:aws-us-gov:s3:::nex-reviewed-exports" &&
      toset(jsondecode(aws_iam_role_policy.production_export_access[0].policy).Statement[1].Action) == toset(["s3:PutObject"]) &&
      jsondecode(aws_iam_role_policy.production_export_access[0].policy).Statement[1].Resource == "arn:aws-us-gov:s3:::nex-reviewed-exports/approved/tenant-exports/*" &&
      jsondecode(aws_iam_role_policy.production_export_access[0].policy).Statement[1].Condition.StringEquals["s3:x-amz-server-side-encryption"] == "aws:kms" &&
      jsondecode(aws_iam_role_policy.production_export_access[0].policy).Statement[1].Condition.StringEquals["s3:x-amz-server-side-encryption-aws-kms-key-id"] == var.production_export_access.kms_key_arn &&
      jsondecode(aws_iam_role_policy.production_export_access[0].policy).Statement[1].Condition.StringEquals["s3:if-none-match"] == "*" &&
      toset(jsondecode(aws_iam_role_policy.production_export_access[0].policy).Statement[2].Action) == toset(["s3:GetObjectVersion"]) &&
      jsondecode(aws_iam_role_policy.production_export_access[0].policy).Statement[2].Resource == "arn:aws-us-gov:s3:::nex-reviewed-exports/approved/tenant-exports/*" &&
      toset(jsondecode(aws_iam_role_policy.production_export_access[0].policy).Statement[3].Action) == toset(["kms:GenerateDataKey", "kms:Decrypt"]) &&
      jsondecode(aws_iam_role_policy.production_export_access[0].policy).Statement[3].Resource == var.production_export_access.kms_key_arn &&
      jsondecode(aws_iam_role_policy.production_export_access[0].policy).Statement[3].Condition.StringEquals["kms:ViaService"] == "s3.us-gov-west-1.amazonaws.com" &&
      jsondecode(aws_iam_role_policy.production_export_access[0].policy).Statement[3].Condition.StringLike["kms:EncryptionContext:aws:s3:arn"] == "arn:aws-us-gov:s3:::nex-reviewed-exports/approved/tenant-exports/*"
    )
    error_message = "Export access must be restricted to the executor, exact bucket/prefix and reviewed SSE-KMS key and actions."
  }
}

run "bucket_key_mode" {
  command   = apply
  state_key = "isolated_export_bucket_key"
  variables {
    production_export_access = {
      bucket_name           = "nex-reviewed-exports"
      prefix                = "approved/tenant-exports/"
      kms_key_arn           = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
      s3_bucket_key_enabled = true
    }
  }
  assert {
    condition = (
      jsondecode(aws_iam_role_policy.production_export_access[0].policy).Statement[3].Condition.StringLike["kms:EncryptionContext:aws:s3:arn"] == "arn:aws-us-gov:s3:::nex-reviewed-exports" &&
      jsondecode(aws_iam_role_policy.production_export_access[0].policy).Statement[1].Resource == "arn:aws-us-gov:s3:::nex-reviewed-exports/approved/tenant-exports/*"
    )
    error_message = "Bucket-key mode must use the bucket KMS context while retaining the S3 object-prefix boundary."
  }
}

run "reject_wildcard_prefix" {
  command = plan
  variables {
    production_export_access = {
      bucket_name           = "nex-reviewed-exports"
      prefix                = "approved/*/"
      kms_key_arn           = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
      s3_bucket_key_enabled = false
    }
  }
  expect_failures = [var.production_export_access]
}

run "reject_foreign_key" {
  command = plan
  variables {
    production_export_access = {
      bucket_name           = "nex-reviewed-exports"
      prefix                = "approved/"
      kms_key_arn           = "arn:aws-us-gov:kms:us-gov-west-1:999988887777:key/12345678-1234-1234-1234-123456789012"
      s3_bucket_key_enabled = false
    }
  }
  expect_failures = [var.production_export_access]
}

run "reject_ip_bucket" {
  command = plan
  variables {
    production_export_access = {
      bucket_name           = "192.168.0.1"
      prefix                = "approved/"
      kms_key_arn           = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
      s3_bucket_key_enabled = false
    }
  }
  expect_failures = [var.production_export_access]
}
