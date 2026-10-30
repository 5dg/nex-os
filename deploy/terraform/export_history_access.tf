locals {
  # Invalid history without a current destination is rejected by variable
  # validation; the conditional avoids evaluating an absent current policy.
  export_history_pairs = var.production_export_access == null ? [] : var.production_export_history_access
  export_history_policy = {
    Version = "2012-10-17"
    Statement = [for item in local.export_history_pairs : {
      Effect = "Allow", Action = ["kms:Decrypt"], Resource = item.kms_key_arn,
      Condition = {
        StringEquals = { "kms:ViaService" = "s3.${var.region}.amazonaws.com" }
        StringLike = {
          "kms:EncryptionContext:aws:s3:arn" = item.s3_bucket_key_enabled ? local.production_export_bucket_arn : "${local.production_export_bucket_arn}/${try(var.production_export_access.prefix, "")}*"
        }
      }
    }]
  }
}

resource "aws_iam_role_policy" "production_export_history_access" {
  count  = length(local.export_history_pairs) == 0 ? 0 : 1
  name   = "approved-historical-export-decrypt"
  role   = aws_iam_role.task["tool-executor"].id
  policy = jsonencode(local.export_history_policy)
  lifecycle {
    precondition {
      condition     = length(jsonencode(local.export_history_policy)) + length(aws_iam_role_policy.production_export_access[0].policy) <= 10240
      error_message = "The combined managed export inline policies exceed the IAM role policy size limit."
    }
  }
}
