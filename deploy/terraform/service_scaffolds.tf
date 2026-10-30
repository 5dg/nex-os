locals {
  requested_service_scaffolds = var.production_service_scaffolds == null ? toset([]) : var.production_service_scaffolds.services
  # Invalid references are rejected by variable validation. Filter here so a
  # missing dependency does not cause unrelated invalid-index errors.
  configured_service_scaffolds = toset([
    for service in local.requested_service_scaffolds : service
    if contains(keys(local.configured_tasks), service) && contains(local.production_network_services, service)
  ])
}

# This creates a named service with zero tasks only. Increasing desired count,
# ingress, discovery and production traffic need a later reviewed integration.
resource "aws_ecs_service" "production_scaffold" {
  for_each                           = local.configured_service_scaffolds
  name                               = "${var.name}-${each.key}"
  cluster                            = aws_ecs_cluster.main.id
  task_definition                    = aws_ecs_task_definition.production_template[each.key].arn
  launch_type                        = "FARGATE"
  platform_version                   = "1.4.0"
  desired_count                      = 0
  enable_execute_command             = false
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  network_configuration {
    subnets          = aws_subnet.private[*].id
    assign_public_ip = false
    security_groups = concat(
      [aws_security_group.production_service[each.key].id, aws_security_group.workloads.id],
      contains(var.production_service_scaffolds.database_clients, each.key) && var.production_database != null ? [aws_security_group.db_clients[0].id] : []
    )
  }
}
