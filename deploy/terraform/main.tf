data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_availability_zones" "available" { state = "available" }

resource "aws_vpc" "main" {
  cidr_block           = "10.62.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  lifecycle {
    precondition {
      condition     = data.aws_partition.current.partition == "aws-us-gov" && data.aws_caller_identity.current.account_id == var.account_id
      error_message = "The authenticated identity must match the verified GovCloud account."
    }
  }
}

resource "aws_subnet" "private" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false
}

resource "aws_route_table" "private" { vpc_id = aws_vpc.main.id }
resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# No Internet gateway, NAT, default Internet route, or public service ingress.
resource "aws_security_group" "workloads" {
  name_prefix = "${var.name}-workloads-"
  description = "Workload traffic only to explicit service endpoints; no general Internet egress"
  vpc_id      = aws_vpc.main.id
}
resource "aws_security_group" "endpoints" {
  name_prefix = "${var.name}-endpoints-"
  description = "Private HTTPS endpoints"
  vpc_id      = aws_vpc.main.id
}
resource "aws_vpc_security_group_ingress_rule" "endpoint_https" {
  security_group_id            = aws_security_group.endpoints.id
  referenced_security_group_id = aws_security_group.workloads.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}
resource "aws_vpc_security_group_egress_rule" "endpoint_https" {
  security_group_id            = aws_security_group.workloads.id
  referenced_security_group_id = aws_security_group.endpoints.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}
resource "aws_vpc_endpoint" "interface" {
  for_each            = var.verified_interface_services
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
}
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  # ECR layer downloads require the regional AWS-managed S3 buckets too.
  # This is not a tenant isolation control; IAM and resource policies are still required.
}
resource "aws_vpc_security_group_egress_rule" "s3_https" {
  security_group_id = aws_security_group.workloads.id
  prefix_list_id    = aws_vpc_endpoint.s3.prefix_list_id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_kms_key" "data" {
  description             = "${var.name} data encryption; evidence signing and independent custody remain separate release work"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}
resource "aws_kms_alias" "data" {
  name          = "alias/${var.name}-data"
  target_key_id = aws_kms_key.data.key_id
}
resource "aws_s3_bucket" "data" {
  bucket        = "${var.name}-${var.account_id}-${var.region}-documents"
  force_destroy = false
}
resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
    bucket_key_enabled = true
  }
}
resource "aws_s3_bucket_policy" "tls" {
  bucket = aws_s3_bucket.data.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport", Effect = "Deny", Principal = "*", Action = "s3:*",
      Resource  = [aws_s3_bucket.data.arn, "${aws_s3_bucket.data.arn}/*"],
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_ecr_repository" "application" {
  for_each             = toset(["control", "workspace", "guard", "evidence", "model", "worker", "tool-executor"])
  name                 = "${var.name}/${each.key}"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.data.arn
  }
}
resource "aws_ecs_cluster" "main" {
  name = var.name
}
resource "aws_iam_role" "task" {
  for_each = toset(["control", "guard", "evidence", "model", "worker", "tool-executor"])
  name     = "${var.name}-${each.key}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole",
      Condition = { StringEquals = { "aws:SourceAccount" = var.account_id }, ArnLike = { "aws:SourceArn" = "arn:aws-us-gov:ecs:${var.region}:${var.account_id}:*" } }
    }]
  })
}
resource "aws_iam_role_policy" "model" {
  name = "approved-regional-model-only"
  role = aws_iam_role.task["model"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"], Resource = var.model_arn,
      Condition = { StringEquals = { "aws:RequestedRegion" = var.region } }
    }]
  })
}
# Worker/control/tool roles deliberately have no protected-resource policies yet.
# Add only the permissions required by the corresponding tested workload.
