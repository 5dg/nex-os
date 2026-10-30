variable "production_service_alarms" {
  description = "Optional ECS service CPU and memory alarms. Null creates no alarms; the destination, thresholds and action state must be explicitly chosen."
  type = object({
    sns_topic_arn       = string
    actions_enabled     = bool
    period_seconds      = number
    evaluation_periods  = number
    datapoints_to_alarm = number
    services = map(object({
      cpu_percent    = number
      memory_percent = number
    }))
  })
  default = null
  validation {
    condition = var.production_service_alarms == null ? true : (
      can(regex("^arn:aws-us-gov:sns:${var.region}:${var.account_id}:[A-Za-z0-9_-]{1,256}$", var.production_service_alarms.sns_topic_arn)) &&
      var.production_service_alarms.actions_enabled != null &&
      length(var.production_service_alarms.services) > 0 &&
      (var.production_service_scaffolds == null ? false : alltrue([for name in keys(var.production_service_alarms.services) : contains(var.production_service_scaffolds.services, name)])) &&
      contains([60, 300, 600], var.production_service_alarms.period_seconds) &&
      var.production_service_alarms.evaluation_periods >= 1 && var.production_service_alarms.evaluation_periods <= 10 &&
      floor(var.production_service_alarms.evaluation_periods) == var.production_service_alarms.evaluation_periods &&
      var.production_service_alarms.datapoints_to_alarm >= 1 &&
      var.production_service_alarms.datapoints_to_alarm <= var.production_service_alarms.evaluation_periods &&
      floor(var.production_service_alarms.datapoints_to_alarm) == var.production_service_alarms.datapoints_to_alarm &&
      alltrue([for thresholds in values(var.production_service_alarms.services) :
        thresholds.cpu_percent > 0 && thresholds.cpu_percent <= 100 &&
        thresholds.memory_percent > 0 && thresholds.memory_percent <= 100
      ])
    )
    error_message = "Choose an SNS topic in the approved account and region, existing scaffold services, positive utilization thresholds at most 100, an allowed period, and valid evaluation/datapoint counts."
  }
}
