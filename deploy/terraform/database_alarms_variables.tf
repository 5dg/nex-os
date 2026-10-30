variable "production_database_alarms" {
  description = "Optional RDS capacity alarms; operators must explicitly select thresholds, notification state and destination."
  type = object({
    sns_topic_arn         = string
    actions_enabled       = bool
    period_seconds        = number
    evaluation_periods    = number
    datapoints_to_alarm   = number
    cpu_percent           = number
    free_storage_bytes    = number
    freeable_memory_bytes = number
  })
  default = null
  validation {
    condition = var.production_database_alarms == null ? true : (
      var.production_database != null &&
      can(regex("^arn:aws-us-gov:sns:${var.region}:${var.account_id}:[A-Za-z0-9_-]{1,256}$", var.production_database_alarms.sns_topic_arn)) &&
      var.production_database_alarms.actions_enabled != null &&
      contains([60, 300, 600], var.production_database_alarms.period_seconds) &&
      var.production_database_alarms.evaluation_periods >= 1 && var.production_database_alarms.evaluation_periods <= 10 &&
      floor(var.production_database_alarms.evaluation_periods) == var.production_database_alarms.evaluation_periods &&
      var.production_database_alarms.datapoints_to_alarm >= 1 &&
      var.production_database_alarms.datapoints_to_alarm <= var.production_database_alarms.evaluation_periods &&
      floor(var.production_database_alarms.datapoints_to_alarm) == var.production_database_alarms.datapoints_to_alarm &&
      var.production_database_alarms.cpu_percent > 0 && var.production_database_alarms.cpu_percent <= 100 &&
      var.production_database_alarms.free_storage_bytes > 0 &&
      floor(var.production_database_alarms.free_storage_bytes) == var.production_database_alarms.free_storage_bytes &&
      var.production_database_alarms.freeable_memory_bytes > 0 &&
      floor(var.production_database_alarms.freeable_memory_bytes) == var.production_database_alarms.freeable_memory_bytes
    )
    error_message = "Choose an existing database, an SNS topic in the approved account and region, explicit notification state, valid evaluation settings and positive capacity thresholds."
  }
}
