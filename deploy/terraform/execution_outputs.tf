output "production_execution" {
  description = "Per-service ECS execution role ARNs and encrypted log group names; these resources do not deploy services."
  value = {
    for service in local.execution_services : service => {
      execution_role_arn = aws_iam_role.production_execution[service].arn
      log_group_name     = aws_cloudwatch_log_group.production_service[service].name
    }
  }
}
