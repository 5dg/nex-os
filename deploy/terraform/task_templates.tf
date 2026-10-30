locals {
  requested_tasks = var.production_task_templates == null ? {} : var.production_task_templates.services
  # A missing execution role is rejected by variable validation; filtering also
  # avoids indexing a nonexistent role while Terraform reports that error.
  configured_tasks = var.production_execution == null ? {} : {
    for name, task in local.requested_tasks : name => task if contains(var.production_execution.services, name)
  }
  task_entrypoints = {
    workspace       = ["node"]
    control         = ["/control"]
    guard           = ["/guard-kernel"]
    evidence        = ["/evidence"]
    model           = ["/model"]
    worker          = ["/worker"]
    "tool-executor" = ["/executor"]
  }
  task_commands = {
    workspace       = ["/app/server.js"]
    control         = ["serve"]
    guard           = ["serve"]
    evidence        = ["serve"]
    model           = ["serve"]
    worker          = ["serve"]
    "tool-executor" = ["serve"]
  }
  # Docker defaults, excluding CHOWN. Fargate allows individual capability
  # drops but does not allow adding CHOWN after dropping ALL. The bootstrap
  # independently rejects any effective/permitted capability beyond CHOWN.
  bootstrap_drop_capabilities = ["AUDIT_WRITE", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD", "NET_BIND_SERVICE", "NET_RAW", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT"]
  bootstrap_policies = {
    for service, task in local.configured_tasks : service => {
      Version = "2012-10-17"
      Statement = concat([
        { Sid = "BootstrapImagePull", Effect = "Allow", Action = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"], Resource = aws_ecr_repository.production_bootstrap[0].arn },
        { Sid = "ServiceSecrets", Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = distinct([for secret in values(task.secrets) : secret.secret_arn]) }
        ], [for pair in distinct([for secret in values(task.secrets) : jsonencode({ key = secret.kms_key_arn, secret = secret.secret_arn })]) : {
          Effect = "Allow", Action = ["kms:Decrypt"], Resource = jsondecode(pair).key,
          Condition = {
            StringEquals = {
              "kms:ViaService"                  = "secretsmanager.${var.region}.amazonaws.com"
              "kms:EncryptionContext:SecretARN" = jsondecode(pair).secret
            }
          }
        }
      ])
    }
  }
}

resource "aws_ecr_repository" "production_bootstrap" {
  count                = var.production_task_templates == null ? 0 : 1
  name                 = "${var.name}/secret-bootstrap"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.data.arn
  }
  lifecycle { prevent_destroy = true }
}

resource "aws_iam_role" "production_workspace_task" {
  count = contains(keys(local.configured_tasks), "workspace") ? 1 : 0
  name  = "${var.name}-workspace"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole",
      Condition = { StringEquals = { "aws:SourceAccount" = var.account_id }, ArnLike = { "aws:SourceArn" = "arn:aws-us-gov:ecs:${var.region}:${var.account_id}:*" } }
    }]
  })
}

# The execution role, not the application task role, retrieves injected
# secrets. This policy supplies only the extra bootstrap repo and exact
# per-service secret/key access. Key policies must separately permit use.
resource "aws_iam_role_policy" "production_task_bootstrap" {
  for_each = local.configured_tasks
  name     = "bootstrap-and-service-secrets"
  role     = aws_iam_role.production_execution[each.key].id
  policy   = jsonencode(local.bootstrap_policies[each.key])
  lifecycle {
    precondition {
      condition     = length(jsonencode(local.bootstrap_policies[each.key])) + length(aws_iam_role_policy.production_execution[each.key].policy) <= 10240
      error_message = "The combined managed inline execution policies exceed the IAM role policy size limit."
    }
  }
}

# These are inert task revisions only. No ECS service, network attachment,
# ingress, public address, or deployment is created by this resource.
resource "aws_ecs_task_definition" "production_template" {
  for_each                 = local.configured_tasks
  family                   = "${var.name}-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(each.value.cpu)
  memory                   = tostring(each.value.memory_mib)
  execution_role_arn       = aws_iam_role.production_execution[each.key].arn
  task_role_arn            = each.key == "workspace" ? aws_iam_role.production_workspace_task[0].arn : aws_iam_role.task[each.key].arn
  skip_destroy             = true

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  volume { name = "secret-files" }
  volume { name = "task-tmp" }

  container_definitions = jsonencode([
    {
      name                   = "secret-bootstrap"
      image                  = "${aws_ecr_repository.production_bootstrap[0].repository_url}@${var.production_task_templates.bootstrap_digest}"
      entryPoint             = ["/secret-bootstrap"]
      command                = ["run"]
      essential              = false
      user                   = "0:0"
      readonlyRootFilesystem = true
      startTimeout           = 60
      linuxParameters        = { capabilities = { drop = local.bootstrap_drop_capabilities } }
      environment = [{
        name = "NEX_SECRET_LAYOUT"
        value = jsonencode({
          uid = each.value.uid, gid = each.value.gid, tmp = true,
          files = [for i, filename in sort(keys(each.value.secrets)) : {
            name = filename, env = format("NEX_SECRET_VALUE_%02d", i), base64 = each.value.secrets[filename].base64
          }]
        })
      }]
      secrets = [for i, filename in sort(keys(each.value.secrets)) : {
        name = format("NEX_SECRET_VALUE_%02d", i), valueFrom = each.value.secrets[filename].secret_arn
      }]
      mountPoints = [
        { sourceVolume = "secret-files", containerPath = "/run/nex-secrets", readOnly = false },
        { sourceVolume = "task-tmp", containerPath = "/run/nex-tmp", readOnly = false }
      ]
      logConfiguration = { logDriver = "awslogs", options = { "awslogs-group" = aws_cloudwatch_log_group.production_service[each.key].name, "awslogs-region" = var.region, "awslogs-stream-prefix" = "secret-init" } }
    },
    merge({
      name                   = each.key
      image                  = "${aws_ecr_repository.application[each.key].repository_url}@${each.value.image_digest}"
      entryPoint             = local.task_entrypoints[each.key]
      command                = local.task_commands[each.key]
      essential              = true
      user                   = "${each.value.uid}:${each.value.gid}"
      readonlyRootFilesystem = true
      stopTimeout            = 75
      linuxParameters        = { capabilities = { drop = ["ALL"] } }
      dependsOn              = [{ containerName = "secret-bootstrap", condition = "SUCCESS" }]
      environment = concat(
        [{ name = "APP_ENV", value = "production" }, { name = "NEX_PROFILE", value = "production" }, { name = "TMPDIR", value = "/tmp" }],
        [for key in sort(keys(each.value.environment)) : { name = key, value = each.value.environment[key] }],
        [for filename in sort(keys(each.value.secrets)) : { name = each.value.secrets[filename].app_file_env, value = "/run/nex-secrets/${filename}" }]
      )
      mountPoints = [
        { sourceVolume = "secret-files", containerPath = "/run/nex-secrets", readOnly = true },
        { sourceVolume = "task-tmp", containerPath = "/tmp", readOnly = false }
      ]
      logConfiguration = { logDriver = "awslogs", options = { "awslogs-group" = aws_cloudwatch_log_group.production_service[each.key].name, "awslogs-region" = var.region, "awslogs-stream-prefix" = "app" } }
      }, each.value.listen_port == null ? {} : {
      portMappings = [{ containerPort = each.value.listen_port, hostPort = each.value.listen_port, protocol = "tcp" }]
    })
  ])
  depends_on = [aws_iam_role_policy.production_task_bootstrap]
}
