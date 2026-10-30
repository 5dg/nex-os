locals {
  database_capacity_alarms = var.production_database_alarms == null || var.production_database == null ? {} : {
    CPUUtilization = {
      threshold = var.production_database_alarms.cpu_percent
      statistic = "Average"
      operator  = "GreaterThanOrEqualToThreshold"
    }
    FreeStorageSpace = {
      threshold = var.production_database_alarms.free_storage_bytes
      statistic = "Minimum"
      operator  = "LessThanOrEqualToThreshold"
    }
    FreeableMemory = {
      threshold = var.production_database_alarms.freeable_memory_bytes
      statistic = "Minimum"
      operator  = "LessThanOrEqualToThreshold"
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "production_database_capacity" {
  for_each            = local.database_capacity_alarms
  alarm_name          = "${var.name}-database-${each.key}"
  alarm_description   = "RDS capacity signal; missing metrics breach. This is not a database or application readiness check."
  namespace           = "AWS/RDS"
  metric_name         = each.key
  statistic           = each.value.statistic
  comparison_operator = each.value.operator
  threshold           = each.value.threshold
  period              = var.production_database_alarms.period_seconds
  evaluation_periods  = var.production_database_alarms.evaluation_periods
  datapoints_to_alarm = var.production_database_alarms.datapoints_to_alarm
  treat_missing_data  = "breaching"
  actions_enabled     = var.production_database_alarms.actions_enabled
  alarm_actions       = [var.production_database_alarms.sns_topic_arn]
  ok_actions          = [var.production_database_alarms.sns_topic_arn]
  dimensions          = { DBInstanceIdentifier = aws_db_instance.production[0].identifier }
}
