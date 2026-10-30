# These isolated execution identities prepare ECR pulls and logging only. They
# grant no task identity, application access or secret retrieval permissions.
locals {
  execution_services = var.production_execution == null ? toset([]) : var.production_execution.services
}

resource "aws_cloudwatch_log_group" "production_service" {
  for_each          = local.execution_services
  name              = "/ecs/${var.name}/${each.key}"
  retention_in_days = var.production_execution.log_retention_days
  kms_key_id        = var.production_execution.logs_kms_key_arn
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role" "production_execution" {
  for_each = local.execution_services
  name     = "${var.name}-${each.key}-exec"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole",
      Condition = { StringEquals = { "aws:SourceAccount" = var.account_id }, ArnLike = { "aws:SourceArn" = "arn:aws-us-gov:ecs:${var.region}:${var.account_id}:*" } }
    }]
  })
}

resource "aws_iam_role_policy" "production_execution" {
  for_each = local.execution_services
  name     = "image-pull-and-service-logs"
  role     = aws_iam_role.production_execution[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "EcrRegistryToken", Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = "*" },
      { Sid = "ServiceImagePull", Effect = "Allow", Action = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"], Resource = aws_ecr_repository.application[each.key].arn },
      { Sid = "ServiceLogWrite", Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${trimsuffix(aws_cloudwatch_log_group.production_service[each.key].arn, ":*")}:*" }
    ]
  })
}
