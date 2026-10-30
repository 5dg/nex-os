output "production_service_security_groups" {
  description = "Per-service network identities; services must explicitly attach the correct group."
  value       = { for service, group in aws_security_group.production_service : service => group.id }
}
