variable "production_task_templates" {
  description = "Explicit unactivated Fargate task revisions. All environment values must be non-secret; the secret map contains ARNs only."
  type = object({
    bootstrap_digest = string
    services = map(object({
      image_digest = string
      cpu          = number
      memory_mib   = number
      uid          = number
      gid          = number
      listen_port  = optional(number)
      environment  = optional(map(string), {})
      secrets = map(object({
        app_file_env = string
        secret_arn   = string
        kms_key_arn  = string
        base64       = bool
      }))
    }))
  })
  default = null
  validation {
    condition = var.production_task_templates == null ? true : (
      can(regex("^sha256:[a-f0-9]{64}$", var.production_task_templates.bootstrap_digest)) &&
      length(var.production_task_templates.services) > 0 && length(var.production_task_templates.services) <= 7 &&
      (var.production_execution == null ? false : alltrue([for service in keys(var.production_task_templates.services) : contains(var.production_execution.services, service)])) &&
      alltrue([for service, task in var.production_task_templates.services : (
        contains(["workspace", "control", "guard", "evidence", "model", "worker", "tool-executor"], service) &&
        can(regex("^sha256:[a-f0-9]{64}$", task.image_digest)) &&
        task.uid >= 1 && task.uid <= 2147483647 && floor(task.uid) == task.uid &&
        task.gid >= 1 && task.gid <= 2147483647 && floor(task.gid) == task.gid &&
        contains(lookup({
          "256"  = [512, 1024, 2048],
          "512"  = [1024, 2048, 3072, 4096],
          "1024" = [2048, 3072, 4096, 5120, 6144, 7168, 8192],
          "2048" = [for n in range(4, 17) : n * 1024],
          "4096" = [for n in range(8, 31) : n * 1024]
        }, tostring(task.cpu), []), task.memory_mib) &&
        (task.listen_port == null ? true : (task.listen_port >= 1024 && task.listen_port <= 65535 && floor(task.listen_port) == task.listen_port)) &&
        length(task.environment) <= 64 &&
        alltrue([for key, value in task.environment : (
          can(regex("^[A-Z][A-Z0-9_]{0,63}$", key)) &&
          !contains(["APP_ENV", "NEX_PROFILE", "TMPDIR", "NEX_SECRET_LAYOUT"], key) &&
          !startswith(key, "AWS_") && !startswith(key, "NEX_SECRET_") &&
          !contains(["PATH", "HOME", "NODE_ENV", "NODE_TLS_REJECT_UNAUTHORIZED", "LD_PRELOAD", "LD_LIBRARY_PATH", "NODE_OPTIONS", "NODE_PATH", "GODEBUG", "GOTRACEBACK", "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"], key) &&
          !endswith(key, "_FILE") &&
          !can(regex("(?i)(secret|password|token|private_key|access_key|database_url|_key$)", key)) &&
          length(value) <= 2048 && !can(regex("[\\r\\n]", value)) &&
          !can(regex("(?i)(-----BEGIN|://[^/]*:[^/@]+@)", value))
        )]) &&
        length(task.secrets) > 0 && length(task.secrets) <= 16 &&
        length(distinct([for item in values(task.secrets) : item.app_file_env])) == length(task.secrets) &&
        alltrue([for filename, item in task.secrets : (
          can(regex("^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$", filename)) &&
          contains(concat(["NEX_TLS_CA_FILE", "NEX_TLS_CERT_FILE", "NEX_TLS_KEY_FILE"], lookup({
            workspace       = ["OIDC_CLIENT_SECRET_FILE", "NEX_OIDC_ASSURANCE_POLICY_FILE", "NEX_SESSION_DB_URL_FILE", "NEX_SESSION_DB_CA_FILE", "NEX_SESSION_ENCRYPTION_KEY_FILE", "NEX_SESSION_PREVIOUS_ENCRYPTION_KEY_FILE"],
            control         = ["DATABASE_URL_FILE", "NEX_DB_CA_FILE", "NEX_HISTORY_CURSOR_KEY_FILE", "NEX_HISTORY_CURSOR_PREVIOUS_KEY_FILE", "GUARD_KEY_FILE", "MODEL_KEY_FILE", "EXPORT_KEY_FILE", "WORKER_KEY_FILE", "EVIDENCE_KEY_FILE", "EVIDENCE_PUBLIC_FILE"],
            guard           = ["DATABASE_URL_FILE", "NEX_DB_CA_FILE", "GUARD_KEY_FILE", "MODEL_GUARD_KEY_FILE", "EXPORT_GUARD_KEY_FILE", "EVIDENCE_KEY_FILE", "EVIDENCE_PUBLIC_FILE"],
            evidence        = ["EVIDENCE_KEY_FILE", "KERNEL_EVIDENCE_KEY_FILE", "SIGNING_SEED_FILE"],
            model           = ["MODEL_KEY_FILE", "MODEL_GUARD_KEY_FILE"],
            worker          = ["WORKER_KEY_FILE"],
            "tool-executor" = ["EXPORT_KEY_FILE", "EXPORT_GUARD_KEY_FILE"]
          }, service, [])), item.app_file_env) &&
          length(item.secret_arn) <= 180 &&
          can(regex("^arn:aws-us-gov:secretsmanager:${var.region}:${var.account_id}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$", item.secret_arn)) &&
          length(item.kms_key_arn) <= 160 &&
          can(regex("^arn:aws-us-gov:kms:${var.region}:${var.account_id}:key/[A-Za-z0-9-]+$", item.kms_key_arn))
        )])
      )])
    )
    error_message = "Task templates require selected execution roles, exact image digests, supported Fargate sizing, non-root IDs, non-secret environment metadata, and scoped same-account secret/key ARNs."
  }
}
