variable "production_export_access" {
  description = "Verified same-account S3 export destination and KMS context. Null grants no export access."
  type = object({
    bucket_name           = string
    prefix                = string
    kms_key_arn           = string
    s3_bucket_key_enabled = bool
  })
  default = null
  validation {
    condition = var.production_export_access == null ? true : (
      can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.production_export_access.bucket_name)) &&
      !strcontains(var.production_export_access.bucket_name, "..") &&
      !strcontains(var.production_export_access.bucket_name, ".-") &&
      !strcontains(var.production_export_access.bucket_name, "-.") &&
      !endswith(var.production_export_access.bucket_name, "--x-s3") &&
      !can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$", var.production_export_access.bucket_name)) &&
      length(var.production_export_access.prefix) <= 128 &&
      can(regex("^([A-Za-z0-9_-]+/)+$", var.production_export_access.prefix)) &&
      can(regex("^arn:aws-us-gov:kms:${var.region}:${var.account_id}:key/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|mrk-[0-9a-f]{32})$", var.production_export_access.kms_key_arn))
    )
    error_message = "Provide an ordinary S3 bucket, a slash-terminated safe prefix and an exact KMS key ARN in the approved GovCloud account and region."
  }
}
