mock_provider "aws" {
  mock_data "aws_caller_identity" { defaults = { account_id = "111122223333" } }
  mock_data "aws_partition" { defaults = { partition = "aws-us-gov" } }
  mock_data "aws_availability_zones" { defaults = { names = ["us-gov-west-1a", "us-gov-west-1b"] } }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012" }
  }
  mock_resource "aws_db_instance" {
    defaults = {
      master_user_secret = [{
        kms_key_id    = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
        secret_arn    = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:mock"
        secret_status = "active"
      }]
    }
  }
}

variables {
  account_id = "111122223333"
  model_arn  = "arn:aws-us-gov:bedrock:us-gov-west-1::foundation-model/synthetic-test-model-v1"
}

run "disabled_by_default" {
  command = plan
  assert {
    condition     = length(aws_cloudwatch_metric_alarm.production_database_capacity) == 0
    error_message = "Database alarms must be opt-in."
  }
}

run "explicit_capacity_alarms" {
  command   = apply
  state_key = "database_alarms"
  variables {
    production_database = { engine_version = "17.5", instance_class = "db.t4g.medium", allocated_storage_gib = 50, backup_retention_days = 7 }
    production_database_alarms = {
      sns_topic_arn   = "arn:aws-us-gov:sns:us-gov-west-1:111122223333:ops"
      actions_enabled = false, period_seconds = 60, evaluation_periods = 3, datapoints_to_alarm = 2
      cpu_percent     = 80, free_storage_bytes = 5368709120, freeable_memory_bytes = 536870912
    }
  }
  assert {
    condition = (
      length(aws_cloudwatch_metric_alarm.production_database_capacity) == 3 &&
      alltrue([for alarm in values(aws_cloudwatch_metric_alarm.production_database_capacity) :
        alarm.namespace == "AWS/RDS" && alarm.period == 60 && alarm.evaluation_periods == 3 &&
        alarm.datapoints_to_alarm == 2 && alarm.treat_missing_data == "breaching" && !alarm.actions_enabled &&
        toset(alarm.alarm_actions) == toset(["arn:aws-us-gov:sns:us-gov-west-1:111122223333:ops"]) &&
        toset(alarm.ok_actions) == toset(["arn:aws-us-gov:sns:us-gov-west-1:111122223333:ops"]) &&
        alarm.dimensions == tomap({ DBInstanceIdentifier = aws_db_instance.production[0].identifier })
      ]) &&
      aws_cloudwatch_metric_alarm.production_database_capacity["CPUUtilization"].threshold == 80 &&
      aws_cloudwatch_metric_alarm.production_database_capacity["CPUUtilization"].statistic == "Average" &&
      aws_cloudwatch_metric_alarm.production_database_capacity["CPUUtilization"].comparison_operator == "GreaterThanOrEqualToThreshold" &&
      aws_cloudwatch_metric_alarm.production_database_capacity["FreeStorageSpace"].threshold == 5368709120 &&
      aws_cloudwatch_metric_alarm.production_database_capacity["FreeStorageSpace"].statistic == "Minimum" &&
      aws_cloudwatch_metric_alarm.production_database_capacity["FreeStorageSpace"].comparison_operator == "LessThanOrEqualToThreshold" &&
      aws_cloudwatch_metric_alarm.production_database_capacity["FreeableMemory"].threshold == 536870912 &&
      aws_cloudwatch_metric_alarm.production_database_capacity["FreeableMemory"].statistic == "Minimum" &&
      aws_cloudwatch_metric_alarm.production_database_capacity["FreeableMemory"].comparison_operator == "LessThanOrEqualToThreshold"
    )
    error_message = "Alarms must match the configured database, operators, threshold units, and fail-closed notification settings."
  }
}

run "reject_missing_database" {
  command = plan
  variables {
    production_database_alarms = {
      sns_topic_arn   = "arn:aws-us-gov:sns:us-gov-west-1:111122223333:ops"
      actions_enabled = true, period_seconds = 60, evaluation_periods = 3, datapoints_to_alarm = 2
      cpu_percent     = 80, free_storage_bytes = 5368709120, freeable_memory_bytes = 536870912
    }
  }
  expect_failures = [var.production_database_alarms]
}

run "reject_foreign_destination" {
  command = plan
  variables {
    production_database = { engine_version = "17.5", instance_class = "db.t4g.medium", allocated_storage_gib = 50, backup_retention_days = 7 }
    production_database_alarms = {
      sns_topic_arn   = "arn:aws-us-gov:sns:us-gov-west-1:999999999999:ops"
      actions_enabled = true, period_seconds = 60, evaluation_periods = 3, datapoints_to_alarm = 2
      cpu_percent     = 80, free_storage_bytes = 5368709120, freeable_memory_bytes = 536870912
    }
  }
  expect_failures = [var.production_database_alarms]
}

run "reject_invalid_thresholds" {
  command = plan
  variables {
    production_database = { engine_version = "17.5", instance_class = "db.t4g.medium", allocated_storage_gib = 50, backup_retention_days = 7 }
    production_database_alarms = {
      sns_topic_arn   = "arn:aws-us-gov:sns:us-gov-west-1:111122223333:ops"
      actions_enabled = true, period_seconds = 60, evaluation_periods = 3, datapoints_to_alarm = 2
      cpu_percent     = 101, free_storage_bytes = 0, freeable_memory_bytes = -1
    }
  }
  expect_failures = [var.production_database_alarms]
}

run "reject_invalid_evaluation" {
  command = plan
  variables {
    production_database = { engine_version = "17.5", instance_class = "db.t4g.medium", allocated_storage_gib = 50, backup_retention_days = 7 }
    production_database_alarms = {
      sns_topic_arn   = "arn:aws-us-gov:sns:us-gov-west-1:111122223333:ops"
      actions_enabled = true, period_seconds = 60, evaluation_periods = 2, datapoints_to_alarm = 3
      cpu_percent     = 80, free_storage_bytes = 5368709120, freeable_memory_bytes = 536870912
    }
  }
  expect_failures = [var.production_database_alarms]
}

run "explicit_notification_enablement" {
  command = plan
  variables {
    production_database = { engine_version = "17.5", instance_class = "db.t4g.medium", allocated_storage_gib = 50, backup_retention_days = 7 }
    production_database_alarms = {
      sns_topic_arn   = "arn:aws-us-gov:sns:us-gov-west-1:111122223333:ops"
      actions_enabled = true, period_seconds = 300, evaluation_periods = 2, datapoints_to_alarm = 1
      cpu_percent     = 80, free_storage_bytes = 5368709120, freeable_memory_bytes = 536870912
    }
  }
  assert {
    condition = alltrue([for alarm in values(aws_cloudwatch_metric_alarm.production_database_capacity) :
      alarm.actions_enabled && alarm.period == 300 && alarm.evaluation_periods == 2 && alarm.datapoints_to_alarm == 1
    ])
    error_message = "Notification behavior must follow the operator's explicit choice."
  }
}

run "reject_implicit_action_state" {
  command = plan
  variables {
    production_database = { engine_version = "17.5", instance_class = "db.t4g.medium", allocated_storage_gib = 50, backup_retention_days = 7 }
    production_database_alarms = {
      sns_topic_arn   = "arn:aws-us-gov:sns:us-gov-west-1:111122223333:ops"
      actions_enabled = null, period_seconds = 60, evaluation_periods = 3, datapoints_to_alarm = 2
      cpu_percent     = 80, free_storage_bytes = 5368709120, freeable_memory_bytes = 536870912
    }
  }
  expect_failures = [var.production_database_alarms]
}
