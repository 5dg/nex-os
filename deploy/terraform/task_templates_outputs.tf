output "production_task_template_arns" {
  description = "Unactivated task definition revisions only; no ECS services are deployed."
  value       = { for service, task in aws_ecs_task_definition.production_template : service => task.arn }
}
