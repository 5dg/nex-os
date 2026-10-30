output "production_service_scaffold_arns" {
  description = "Fargate service scaffolds configured with desired count zero; live task state is not verified."
  value       = { for service, scaffold in aws_ecs_service.production_scaffold : service => scaffold.id }
}
