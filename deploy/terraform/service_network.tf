# Service-to-service traffic is explicitly allowed by directed edge; attach a
# group's identity only to its matching service. Other access is separate.
locals {
  production_network_services = var.production_service_network == null ? toset([]) : var.production_service_network.services
  production_network_edges    = var.production_service_network == null ? tomap({}) : var.production_service_network.connections
}

resource "aws_security_group" "production_service" {
  for_each    = local.production_network_services
  name_prefix = "${var.name}-${each.key}-service-"
  description = "Private network identity for the ${each.key} service"
  vpc_id      = aws_vpc.main.id
}

resource "aws_vpc_security_group_egress_rule" "service_connection" {
  for_each                     = local.production_network_edges
  security_group_id            = aws_security_group.production_service[each.value.source].id
  referenced_security_group_id = aws_security_group.production_service[each.value.destination].id
  ip_protocol                  = "tcp"
  from_port                    = each.value.port
  to_port                      = each.value.port
  description                  = "Reviewed ${each.key} service connection"
}

resource "aws_vpc_security_group_ingress_rule" "service_connection" {
  for_each                     = local.production_network_edges
  security_group_id            = aws_security_group.production_service[each.value.destination].id
  referenced_security_group_id = aws_security_group.production_service[each.value.source].id
  ip_protocol                  = "tcp"
  from_port                    = each.value.port
  to_port                      = each.value.port
  description                  = "Reviewed ${each.key} service connection"
}
