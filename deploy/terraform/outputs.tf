output "vpc_id" { value = aws_vpc.main.id }
output "private_subnet_ids" { value = aws_subnet.private[*].id }
output "task_role_arns" { value = { for name, role in aws_iam_role.task : name => role.arn } }
output "ecr_repository_urls" { value = { for name, repo in aws_ecr_repository.application : name => repo.repository_url } }
output "document_bucket" { value = aws_s3_bucket.data.id }
output "production_database" {
  description = "Private endpoint and client security group; application credentials and database grants are provisioned separately."
  value = var.production_database == null ? null : {
    endpoint                 = aws_db_instance.production[0].address
    port                     = aws_db_instance.production[0].port
    database_name            = aws_db_instance.production[0].db_name
    client_security_group_id = aws_security_group.db_clients[0].id
    admin_secret_arn         = aws_db_instance.production[0].master_user_secret[0].secret_arn
  }
}
