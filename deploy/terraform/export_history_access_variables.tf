variable "production_export_history_access" {
  description = "Explicit historical KMS key/context pairs for versioned export reads. Empty adds no historical access."
  type = list(object({
    kms_key_arn           = string
    s3_bucket_key_enabled = bool
  }))
  default = []
  validation {
    condition = length(var.production_export_history_access) == 0 ? true : (
      var.production_export_access == null ? false : (
        length(var.production_export_history_access) <= 16 &&
        length(distinct([for item in var.production_export_history_access : jsonencode(item)])) == length(var.production_export_history_access) &&
        alltrue([for item in var.production_export_history_access : (
          can(regex("^arn:aws-us-gov:kms:${var.region}:${var.account_id}:key/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|mrk-[0-9a-f]{32})$", item.kms_key_arn)) &&
          !(item.kms_key_arn == var.production_export_access.kms_key_arn && item.s3_bucket_key_enabled == var.production_export_access.s3_bucket_key_enabled)
        )])
      )
    )
    error_message = "Historical decrypt access requires a current export route and distinct same-account/region key and context pairs not duplicating the current pair."
  }
}
