output "vpc_id" { value = aws_vpc.main.id }
output "private_subnet_ids" { value = aws_subnet.private[*].id }
output "task_role_arns" { value = { for name, role in aws_iam_role.task : name => role.arn } }
output "ecr_repository_urls" { value = { for name, repo in aws_ecr_repository.application : name => repo.repository_url } }
output "document_bucket" { value = aws_s3_bucket.data.id }
