locals {
  requested_discovery_services = var.production_service_discovery == null ? toset([]) : var.production_service_discovery.services
  # Input validation reports mismatched scaffolds; filtering prevents invalid
  # lookups while Terraform renders the variable error.
  configured_discovery_services = toset([
    for service in local.requested_discovery_services : service
    if contains(local.configured_service_scaffolds, service)
  ])
}

resource "aws_service_discovery_private_dns_namespace" "production" {
  count       = var.production_service_discovery == null ? 0 : 1
  name        = var.production_service_discovery.namespace
  description = "Private service DNS for ${var.name}; service identity remains authenticated independently"
  vpc         = aws_vpc.main.id
}

resource "aws_service_discovery_service" "production" {
  for_each    = local.configured_discovery_services
  name        = each.key
  description = "Private ECS discovery for ${each.key}; does not establish application readiness"
  dns_config {
    namespace_id   = aws_service_discovery_private_dns_namespace.production[0].id
    routing_policy = "MULTIVALUE"
    dns_records {
      ttl  = var.production_service_discovery.ttl
      type = "A"
    }
  }
  # The provider marks this deprecated because AWS fixes it at one; setting
  # it explicitly also makes the configured value visible to mock tests.
  health_check_custom_config { failure_threshold = 1 }
}

output "production_service_discovery_names" {
  description = "Configured private DNS names; TLS identity, network reachability and application readiness need independent verification."
  value = tomap({
    for service in local.configured_discovery_services :
    service => "${service}.${var.production_service_discovery.namespace}"
  })
}
