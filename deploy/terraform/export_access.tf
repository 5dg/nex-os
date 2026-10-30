locals {
  production_export_bucket_arn = var.production_export_access == null ? "" : "arn:aws-us-gov:s3:::${var.production_export_access.bucket_name}"
  production_export_context = var.production_export_access == null ? "" : (
    var.production_export_access.s3_bucket_key_enabled ? local.production_export_bucket_arn : "${local.production_export_bucket_arn}/${var.production_export_access.prefix}*"
  )
}

# The executor's task role receives only the current versioning check,
# conditional prefix-scoped write and versioned-read actions. Bucket and key
# policies and other effective role grants must be independently reviewed.
resource "aws_iam_role_policy" "production_export_access" {
  count = var.production_export_access == null ? 0 : 1
  name  = "approved-versioned-export"
  role  = aws_iam_role.task["tool-executor"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "VerifyBucketVersioning", Effect = "Allow", Action = ["s3:GetBucketVersioning"], Resource = local.production_export_bucket_arn,
        Condition = { StringEquals = { "aws:ResourceAccount" = var.account_id } }
      },
      {
        Sid = "WriteApprovedPrefix", Effect = "Allow", Action = ["s3:PutObject"], Resource = "${local.production_export_bucket_arn}/${var.production_export_access.prefix}*",
        Condition = { StringEquals = {
          "aws:ResourceAccount"                            = var.account_id
          "s3:x-amz-server-side-encryption"                = "aws:kms"
          "s3:x-amz-server-side-encryption-aws-kms-key-id" = var.production_export_access.kms_key_arn
          "s3:if-none-match"                               = "*"
        } }
      },
      {
        Sid       = "ReadExactVersions", Effect = "Allow", Action = ["s3:GetObjectVersion"], Resource = "${local.production_export_bucket_arn}/${var.production_export_access.prefix}*",
        Condition = { StringEquals = { "aws:ResourceAccount" = var.account_id } }
      },
      {
        Sid = "ExportKeyViaS3", Effect = "Allow", Action = ["kms:GenerateDataKey", "kms:Decrypt"], Resource = var.production_export_access.kms_key_arn,
        Condition = {
          StringEquals = { "kms:ViaService" = "s3.${var.region}.amazonaws.com" }
          StringLike   = { "kms:EncryptionContext:aws:s3:arn" = local.production_export_context }
        }
      }
    ]
  })
}
