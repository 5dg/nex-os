mock_provider "aws" {
  mock_data "aws_caller_identity" { defaults = { account_id = "111122223333" } }
  mock_data "aws_partition" { defaults = { partition = "aws-us-gov" } }
  mock_data "aws_availability_zones" { defaults = { names = ["us-gov-west-1a", "us-gov-west-1b"] } }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012" }
  }
  mock_resource "aws_ecr_repository" {
    defaults = {
      arn            = "arn:aws-us-gov:ecr:us-gov-west-1:111122223333:repository/mock"
      repository_url = "111122223333.dkr.ecr.us-gov-west-1.amazonaws.com/mock"
    }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws-us-gov:logs:us-gov-west-1:111122223333:log-group:mock" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws-us-gov:iam::111122223333:role/mock" }
  }
  mock_resource "aws_ecs_cluster" {
    defaults = { id = "arn:aws-us-gov:ecs:us-gov-west-1:111122223333:cluster/mock" }
  }
  mock_resource "aws_ecs_task_definition" {
    defaults = { arn = "arn:aws-us-gov:ecs:us-gov-west-1:111122223333:task-definition/mock:1" }
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
  production_execution = {
    services           = ["control"]
    logs_kms_key_arn   = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
    log_retention_days = 90
  }
  production_service_network = { services = ["control"], connections = {} }
  production_task_templates = {
    bootstrap_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    services = {
      control = {
        image_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        cpu          = 256, memory_mib = 512, uid = 65532, gid = 65532
        secrets = {
          db-url = {
            app_file_env = "DATABASE_URL_FILE"
            secret_arn   = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:nex-db-abcdef"
            kms_key_arn  = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
            base64       = false
          }
        }
      }
    }
  }
}

override_resource {
  target = aws_security_group.workloads
  values = { id = "sg-00000000000000001" }
}
override_resource {
  target = aws_security_group.production_service["control"]
  values = { id = "sg-00000000000000002" }
}
override_resource {
  target = aws_security_group.db_clients[0]
  values = { id = "sg-00000000000000003" }
}
override_resource {
  target = aws_subnet.private[0]
  values = { id = "subnet-00000000000000001" }
}
override_resource {
  target = aws_subnet.private[1]
  values = { id = "subnet-00000000000000002" }
}

run "alarms_disabled_by_default" {
  command = plan
  assert {
    condition     = length(aws_cloudwatch_metric_alarm.production_service_utilization) == 0
    error_message = "No service alarms should be created by default."
  }
}

run "explicit_service_utilization_alarms" {
  command   = apply
  state_key = "service_alarms"
  variables {
    production_service_scaffolds = { services = ["control"] }
    production_service_alarms = {
      sns_topic_arn       = "arn:aws-us-gov:sns:us-gov-west-1:111122223333:ops"
      actions_enabled     = false
      period_seconds      = 60
      evaluation_periods  = 3
      datapoints_to_alarm = 2
      services            = { control = { cpu_percent = 70, memory_percent = 80 } }
    }
  }
  assert {
    condition = (
      length(aws_cloudwatch_metric_alarm.production_service_utilization) == 2 &&
      alltrue([for alarm in values(aws_cloudwatch_metric_alarm.production_service_utilization) :
        alarm.namespace == "AWS/ECS" && alarm.statistic == "Average" &&
        alarm.comparison_operator == "GreaterThanOrEqualToThreshold" &&
        alarm.period == 60 && alarm.evaluation_periods == 3 && alarm.datapoints_to_alarm == 2 &&
        alarm.treat_missing_data == "breaching" && !alarm.actions_enabled &&
        toset(alarm.alarm_actions) == toset(["arn:aws-us-gov:sns:us-gov-west-1:111122223333:ops"]) &&
        toset(alarm.ok_actions) == toset(["arn:aws-us-gov:sns:us-gov-west-1:111122223333:ops"]) &&
        alarm.dimensions == tomap({ ClusterName = aws_ecs_cluster.main.name, ServiceName = aws_ecs_service.production_scaffold["control"].name })
      ]) &&
      aws_cloudwatch_metric_alarm.production_service_utilization["control/CPUUtilization"].threshold == 70 &&
      aws_cloudwatch_metric_alarm.production_service_utilization["control/MemoryUtilization"].threshold == 80 &&
      aws_ecs_service.production_scaffold["control"].desired_count == 0
    )
    error_message = "Alarms must reference the selected zero-count service, explicit thresholds and target, and fail closed on missing data."
  }
}

run "reject_cross_account_destination" {
  command = plan
  variables {
    production_service_scaffolds = { services = ["control"] }
    production_service_alarms = {
      sns_topic_arn   = "arn:aws-us-gov:sns:us-gov-west-1:999999999999:ops"
      actions_enabled = true, period_seconds = 60, evaluation_periods = 3, datapoints_to_alarm = 2
      services        = { control = { cpu_percent = 70, memory_percent = 80 } }
    }
  }
  expect_failures = [var.production_service_alarms]
}

run "reject_missing_service" {
  command = plan
  variables {
    production_service_alarms = {
      sns_topic_arn   = "arn:aws-us-gov:sns:us-gov-west-1:111122223333:ops"
      actions_enabled = true, period_seconds = 60, evaluation_periods = 3, datapoints_to_alarm = 2
      services        = { control = { cpu_percent = 70, memory_percent = 80 } }
    }
  }
  expect_failures = [var.production_service_alarms]
}

run "reject_invalid_thresholds" {
  command = plan
  variables {
    production_service_scaffolds = { services = ["control"] }
    production_service_alarms = {
      sns_topic_arn   = "arn:aws-us-gov:sns:us-gov-west-1:111122223333:ops"
      actions_enabled = true, period_seconds = 60, evaluation_periods = 3, datapoints_to_alarm = 2
      services        = { control = { cpu_percent = 101, memory_percent = 0 } }
    }
  }
  expect_failures = [var.production_service_alarms]
}

run "reject_invalid_evaluation" {
  command = plan
  variables {
    production_service_scaffolds = { services = ["control"] }
    production_service_alarms = {
      sns_topic_arn   = "arn:aws-us-gov:sns:us-gov-west-1:111122223333:ops"
      actions_enabled = true, period_seconds = 60, evaluation_periods = 2, datapoints_to_alarm = 3
      services        = { control = { cpu_percent = 70, memory_percent = 80 } }
    }
  }
  expect_failures = [var.production_service_alarms]
}

run "reject_null_action_choice" {
  command = plan
  variables {
    production_service_scaffolds = { services = ["control"] }
    production_service_alarms = {
      sns_topic_arn   = "arn:aws-us-gov:sns:us-gov-west-1:111122223333:ops"
      actions_enabled = null, period_seconds = 60, evaluation_periods = 3, datapoints_to_alarm = 2
      services        = { control = { cpu_percent = 70, memory_percent = 80 } }
    }
  }
  expect_failures = [var.production_service_alarms]
}

run "explicit_notification_enablement" {
  command = plan
  variables {
    production_service_scaffolds = { services = ["control"] }
    production_service_alarms = {
      sns_topic_arn       = "arn:aws-us-gov:sns:us-gov-west-1:111122223333:ops"
      actions_enabled     = true
      period_seconds      = 300
      evaluation_periods  = 2
      datapoints_to_alarm = 1
      services            = { control = { cpu_percent = 70, memory_percent = 100 } }
    }
  }
  assert {
    condition = alltrue([for alarm in values(aws_cloudwatch_metric_alarm.production_service_utilization) :
      alarm.actions_enabled && alarm.period == 300 && alarm.evaluation_periods == 2 && alarm.datapoints_to_alarm == 1
    ]) && aws_cloudwatch_metric_alarm.production_service_utilization["control/MemoryUtilization"].threshold == 100
    error_message = "Notifications and evaluation timing must follow the explicit operator choice."
  }
}
