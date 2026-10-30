locals {
  requested_service_alarms = var.production_service_alarms == null ? {} : var.production_service_alarms.services
  configured_service_alarms = {
    for service, thresholds in local.requested_service_alarms : service => thresholds
    if contains(keys(aws_ecs_service.production_scaffold), service)
  }
  service_utilization_alarms = merge([
    for service, thresholds in local.configured_service_alarms : {
      for metric, threshold in { CPUUtilization = thresholds.cpu_percent, MemoryUtilization = thresholds.memory_percent } :
      "${service}/${metric}" => { service = service, metric = metric, threshold = threshold }
    }
  ]...)
}

resource "aws_cloudwatch_metric_alarm" "production_service_utilization" {
  for_each            = local.service_utilization_alarms
  alarm_name          = "${var.name}-${each.value.service}-${each.value.metric}"
  alarm_description   = "ECS service utilization; missing metrics are treated as breaching. This does not establish readiness."
  namespace           = "AWS/ECS"
  metric_name         = each.value.metric
  statistic           = "Average"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = each.value.threshold
  period              = var.production_service_alarms.period_seconds
  evaluation_periods  = var.production_service_alarms.evaluation_periods
  datapoints_to_alarm = var.production_service_alarms.datapoints_to_alarm
  treat_missing_data  = "breaching"
  actions_enabled     = var.production_service_alarms.actions_enabled
  alarm_actions       = [var.production_service_alarms.sns_topic_arn]
  ok_actions          = [var.production_service_alarms.sns_topic_arn]
  dimensions = {
    ClusterName = aws_ecs_cluster.main.name
    ServiceName = aws_ecs_service.production_scaffold[each.value.service].name
  }
}
