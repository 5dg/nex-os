variable "production_execution" {
  description = "Explicit reviewed execution-role and log configuration; null creates no execution resources."
  type = object({
    services           = set(string)
    logs_kms_key_arn   = string
    log_retention_days = number
  })
  default = null
  validation {
    condition = var.production_execution == null ? true : (
      length(var.production_execution.services) > 0 &&
      alltrue([for service in var.production_execution.services : contains(["control", "guard", "evidence", "model", "worker", "tool-executor", "workspace"], service)]) &&
      can(regex("^arn:aws-us-gov:kms:${var.region}:${var.account_id}:key/[A-Za-z0-9-]+$", var.production_execution.logs_kms_key_arn)) &&
      contains([30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.production_execution.log_retention_days)
    )
    error_message = "Specify supported services, a KMS key ARN in the approved GovCloud account and region, and a supported retention period of at least 30 days."
  }
}
