mock_provider "aws" {
  mock_data "aws_caller_identity" { defaults = { account_id = "111122223333" } }
  mock_data "aws_partition" { defaults = { partition = "aws-us-gov" } }
  mock_data "aws_availability_zones" { defaults = { names = ["us-gov-west-1a", "us-gov-west-1b"] } }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012" }
  }
  mock_resource "aws_ecr_repository" {
    defaults = {
      arn            = "arn:aws-us-gov:ecr:us-gov-west-1:111122223333:repository/mock"
      repository_url = "111122223333.dkr.ecr.us-gov-west-1.amazonaws.com/mock"
    }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws-us-gov:logs:us-gov-west-1:111122223333:log-group:mock" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws-us-gov:iam::111122223333:role/mock" }
  }
}
variables {
  account_id = "111122223333"
  model_arn  = "arn:aws-us-gov:bedrock:us-gov-west-1::foundation-model/synthetic-test-model-v1"
}

run "templates_disabled_by_default" {
  command = plan
  assert {
    condition     = length(aws_ecs_task_definition.production_template) == 0 && length(aws_ecr_repository.production_bootstrap) == 0
    error_message = "No task revisions or bootstrap registry should be created by default."
  }
}

run "isolated_task_template" {
  command   = apply
  state_key = "isolated_task_template"
  variables {
    production_execution = {
      services           = ["control"]
      logs_kms_key_arn   = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
      log_retention_days = 90
    }
    production_task_templates = {
      bootstrap_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      services = {
        control = {
          image_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          cpu          = 256
          memory_mib   = 512
          uid          = 65532
          gid          = 65532
          listen_port  = 8080
          environment  = { LISTEN_ADDR = ":8080" }
          secrets = {
            db-url = {
              app_file_env = "DATABASE_URL_FILE"
              secret_arn   = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:nex-db-abcdef"
              kms_key_arn  = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
              base64       = false
            }
            tls-key = {
              app_file_env = "NEX_TLS_KEY_FILE"
              secret_arn   = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:nex-tls-123456"
              kms_key_arn  = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/87654321-4321-4321-4321-210987654321"
              base64       = false
            }
          }
        }
      }
    }
  }
  assert {
    condition = (
      aws_ecs_task_definition.production_template["control"].network_mode == "awsvpc" &&
      toset(aws_ecs_task_definition.production_template["control"].requires_compatibilities) == toset(["FARGATE"]) &&
      aws_ecs_task_definition.production_template["control"].skip_destroy &&
      jsondecode(aws_ecs_task_definition.production_template["control"].container_definitions)[0].essential == false &&
      jsondecode(aws_ecs_task_definition.production_template["control"].container_definitions)[0].user == "0:0" &&
      jsondecode(aws_ecs_task_definition.production_template["control"].container_definitions)[0].entryPoint == ["/secret-bootstrap"] &&
      jsondecode(aws_ecs_task_definition.production_template["control"].container_definitions)[0].command == ["run"] &&
      !contains(jsondecode(aws_ecs_task_definition.production_template["control"].container_definitions)[0].linuxParameters.capabilities.drop, "CHOWN") &&
      !can(jsondecode(aws_ecs_task_definition.production_template["control"].container_definitions)[0].linuxParameters.capabilities.add) &&
      jsondecode(aws_ecs_task_definition.production_template["control"].container_definitions)[1].dependsOn[0].condition == "SUCCESS" &&
      jsondecode(aws_ecs_task_definition.production_template["control"].container_definitions)[1].user == "65532:65532" &&
      jsondecode(aws_ecs_task_definition.production_template["control"].container_definitions)[1].entryPoint == ["/control"] &&
      jsondecode(aws_ecs_task_definition.production_template["control"].container_definitions)[1].command == ["serve"] &&
      jsondecode(aws_ecs_task_definition.production_template["control"].container_definitions)[1].mountPoints[0].readOnly &&
      jsondecode(aws_ecs_task_definition.production_template["control"].container_definitions)[1].stopTimeout == 75
    )
    error_message = "The task must gate non-root, read-only application startup on the narrow bootstrap's success."
  }
  assert {
    condition = (
      jsondecode(aws_ecs_task_definition.production_template["control"].container_definitions)[0].secrets[0].valueFrom == var.production_task_templates.services.control.secrets.db-url.secret_arn &&
      !can(jsondecode(aws_ecs_task_definition.production_template["control"].container_definitions)[1].secrets) &&
      one([for e in jsondecode(aws_ecs_task_definition.production_template["control"].container_definitions)[1].environment : e.value if e.name == "DATABASE_URL_FILE"]) == "/run/nex-secrets/db-url" &&
      contains(jsondecode(aws_iam_role_policy.production_task_bootstrap["control"].policy).Statement[1].Resource, var.production_task_templates.services.control.secrets.db-url.secret_arn) &&
      length(jsondecode(aws_iam_role_policy.production_task_bootstrap["control"].policy).Statement) == 4 &&
      jsondecode(aws_iam_role_policy.production_task_bootstrap["control"].policy).Statement[2].Resource == var.production_task_templates.services.control.secrets.db-url.kms_key_arn &&
      jsondecode(aws_iam_role_policy.production_task_bootstrap["control"].policy).Statement[2].Condition.StringEquals["kms:EncryptionContext:SecretARN"] == var.production_task_templates.services.control.secrets.db-url.secret_arn &&
      jsondecode(aws_iam_role_policy.production_task_bootstrap["control"].policy).Statement[3].Resource == var.production_task_templates.services.control.secrets.tls-key.kms_key_arn &&
      jsondecode(aws_iam_role_policy.production_task_bootstrap["control"].policy).Statement[3].Condition.StringEquals["kms:EncryptionContext:SecretARN"] == var.production_task_templates.services.control.secrets.tls-key.secret_arn &&
      jsondecode(aws_iam_role_policy.production_task_bootstrap["control"].policy).Statement[2].Condition.StringEquals["kms:ViaService"] == "secretsmanager.us-gov-west-1.amazonaws.com"
    )
    error_message = "Secret delivery must use exact ARN-scoped execution permissions and files, never inject values into the application environment."
  }
}

run "workspace_explicit_command" {
  command   = apply
  state_key = "isolated_workspace_task"
  variables {
    production_execution = {
      services           = ["workspace"]
      logs_kms_key_arn   = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
      log_retention_days = 90
    }
    production_task_templates = {
      bootstrap_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      services = {
        workspace = {
          image_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          cpu          = 512, memory_mib = 1024, uid = 1000, gid = 1000
          secrets = {
            oidc = {
              app_file_env = "OIDC_CLIENT_SECRET_FILE"
              secret_arn   = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:nex-oidc-abcdef"
              kms_key_arn  = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
              base64       = false
            }
          }
        }
      }
    }
  }
  assert {
    condition = (
      jsondecode(aws_ecs_task_definition.production_template["workspace"].container_definitions)[1].entryPoint == ["node"] &&
      jsondecode(aws_ecs_task_definition.production_template["workspace"].container_definitions)[1].command == ["/app/server.js"] &&
      aws_iam_role.production_workspace_task[0].name != aws_iam_role.production_execution["workspace"].name
    )
    error_message = "Workspace must override inherited image CMD and use a separate task role."
  }
}

run "reject_invalid_task" {
  command = plan
  variables {
    production_execution = {
      services           = ["control"]
      logs_kms_key_arn   = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
      log_retention_days = 90
    }
    production_task_templates = {
      bootstrap_digest = "latest"
      services = {
        control = {
          image_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          cpu          = 256
          memory_mib   = 512
          uid          = 0
          gid          = 65532
          environment  = { DATABASE_URL = "postgres://name:password@example.invalid/database" }
          secrets = {
            db-url = {
              app_file_env = "DATABASE_URL_FILE"
              secret_arn   = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:nex-db-abcdef"
              kms_key_arn  = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
              base64       = false
            }
          }
        }
      }
    }
  }
  expect_failures = [var.production_task_templates]
}

run "reject_plaintext_environment" {
  command = plan
  variables {
    production_execution = {
      services           = ["control"]
      logs_kms_key_arn   = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
      log_retention_days = 90
    }
    production_task_templates = {
      bootstrap_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      services = {
        control = {
          image_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          cpu          = 256
          memory_mib   = 512
          uid          = 65532
          gid          = 65532
          environment  = { DATABASE_URL = "postgres://fake:fake@example.invalid/database" }
          secrets = {
            db-url = {
              app_file_env = "DATABASE_URL_FILE"
              secret_arn   = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:nex-db-abcdef"
              kms_key_arn  = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
              base64       = false
            }
          }
        }
      }
    }
  }
  expect_failures = [var.production_task_templates]
}

run "reject_foreign_secret" {
  command = plan
  variables {
    production_execution = {
      services           = ["control"]
      logs_kms_key_arn   = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
      log_retention_days = 90
    }
    production_task_templates = {
      bootstrap_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      services = {
        control = {
          image_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          cpu          = 256
          memory_mib   = 512
          uid          = 65532
          gid          = 65532
          environment  = {}
          secrets = {
            db-url = {
              app_file_env = "DATABASE_URL_FILE"
              secret_arn   = "arn:aws-us-gov:secretsmanager:us-gov-west-1:999988887777:secret:nex-db-abcdef"
              kms_key_arn  = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
              base64       = false
            }
          }
        }
      }
    }
  }
  expect_failures = [var.production_task_templates]
}

run "reject_unselected_execution_role" {
  command = plan
  variables {
    production_execution = {
      services           = ["workspace"]
      logs_kms_key_arn   = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
      log_retention_days = 90
    }
    production_task_templates = {
      bootstrap_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      services = {
        control = {
          image_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          cpu          = 256
          memory_mib   = 512
          uid          = 65532
          gid          = 65532
          environment  = {}
          secrets = {
            db-url = {
              app_file_env = "DATABASE_URL_FILE"
              secret_arn   = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:nex-db-abcdef"
              kms_key_arn  = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
              base64       = false
            }
          }
        }
      }
    }
  }
  expect_failures = [var.production_task_templates]
}

run "reject_unsupported_task_size" {
  command = plan
  variables {
    production_execution = {
      services           = ["control"]
      logs_kms_key_arn   = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
      log_retention_days = 90
    }
    production_task_templates = {
      bootstrap_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      services = {
        control = {
          image_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          cpu          = 256
          memory_mib   = 256
          uid          = 65532
          gid          = 65532
          environment  = {}
          secrets = {
            db-url = {
              app_file_env = "DATABASE_URL_FILE"
              secret_arn   = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:nex-db-abcdef"
              kms_key_arn  = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
              base64       = false
            }
          }
        }
      }
    }
  }
  expect_failures = [var.production_task_templates]
}

run "reject_runtime_injection" {
  command = plan
  variables {
    production_execution = {
      services           = ["control"]
      logs_kms_key_arn   = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
      log_retention_days = 90
    }
    production_task_templates = {
      bootstrap_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      services = {
        control = {
          image_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          cpu          = 256
          memory_mib   = 512
          uid          = 65532
          gid          = 65532
          environment  = { NODE_OPTIONS = "--require=/tmp/unapproved.js" }
          secrets = {
            db-url = {
              app_file_env = "DATABASE_URL_FILE"
              secret_arn   = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:nex-db-abcdef"
              kms_key_arn  = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
              base64       = false
            }
          }
        }
      }
    }
  }
  expect_failures = [var.production_task_templates]
}


run "reject_tls_verification_bypass" {
  command = plan
  variables {
    production_execution = {
      services           = ["control"]
      logs_kms_key_arn   = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
      log_retention_days = 90
    }
    production_task_templates = {
      bootstrap_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      services = {
        control = {
          image_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          cpu          = 256
          memory_mib   = 512
          uid          = 65532
          gid          = 65532
          environment  = { NODE_TLS_REJECT_UNAUTHORIZED = "0" }
          secrets = {
            db-url = {
              app_file_env = "DATABASE_URL_FILE"
              secret_arn   = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:nex-db-abcdef"
              kms_key_arn  = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
              base64       = false
            }
          }
        }
      }
    }
  }
  expect_failures = [var.production_task_templates]
}


run "reject_root_application_uid" {
  command = plan
  variables {
    production_execution = {
      services           = ["control"]
      logs_kms_key_arn   = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
      log_retention_days = 90
    }
    production_task_templates = {
      bootstrap_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      services = {
        control = {
          image_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          cpu          = 256
          memory_mib   = 512
          uid          = 0
          gid          = 65532
          environment  = { LISTEN_ADDR = ":8080" }
          secrets = {
            db-url = {
              app_file_env = "DATABASE_URL_FILE"
              secret_arn   = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:nex-db-abcdef"
              kms_key_arn  = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
              base64       = false
            }
          }
        }
      }
    }
  }
  expect_failures = [var.production_task_templates]
}


run "reject_unpinned_application_image" {
  command = plan
  variables {
    production_execution = {
      services           = ["control"]
      logs_kms_key_arn   = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
      log_retention_days = 90
    }
    production_task_templates = {
      bootstrap_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      services = {
        control = {
          image_digest = "latest"
          cpu          = 256
          memory_mib   = 512
          uid          = 65532
          gid          = 65532
          environment  = { LISTEN_ADDR = ":8080" }
          secrets = {
            db-url = {
              app_file_env = "DATABASE_URL_FILE"
              secret_arn   = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:nex-db-abcdef"
              kms_key_arn  = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
              base64       = false
            }
          }
        }
      }
    }
  }
  expect_failures = [var.production_task_templates]
}


run "reject_secret_path_escape" {
  command = plan
  variables {
    production_execution = {
      services           = ["control"]
      logs_kms_key_arn   = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
      log_retention_days = 90
    }
    production_task_templates = {
      bootstrap_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      services = {
        control = {
          image_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          cpu          = 256
          memory_mib   = 512
          uid          = 65532
          gid          = 65532
          environment  = { LISTEN_ADDR = ":8080" }
          secrets = {
            "../db-url" = {
              app_file_env = "DATABASE_URL_FILE"
              secret_arn   = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:nex-db-abcdef"
              kms_key_arn  = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
              base64       = false
            }
          }
        }
      }
    }
  }
  expect_failures = [var.production_task_templates]
}


run "reject_foreign_kms_key" {
  command = plan
  variables {
    production_execution = {
      services           = ["control"]
      logs_kms_key_arn   = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
      log_retention_days = 90
    }
    production_task_templates = {
      bootstrap_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      services = {
        control = {
          image_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          cpu          = 256
          memory_mib   = 512
          uid          = 65532
          gid          = 65532
          environment  = { LISTEN_ADDR = ":8080" }
          secrets = {
            db-url = {
              app_file_env = "DATABASE_URL_FILE"
              secret_arn   = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:nex-db-abcdef"
              kms_key_arn  = "arn:aws-us-gov:kms:us-gov-west-1:999988887777:key/12345678-1234-1234-1234-123456789012"
              base64       = false
            }
          }
        }
      }
    }
  }
  expect_failures = [var.production_task_templates]
}


run "reject_ambient_tls_trust_override" {
  command = plan
  variables {
    production_execution = {
      services           = ["control"]
      logs_kms_key_arn   = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
      log_retention_days = 90
    }
    production_task_templates = {
      bootstrap_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      services = {
        control = {
          image_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          cpu          = 256
          memory_mib   = 512
          uid          = 65532
          gid          = 65532
          environment  = { LISTEN_ADDR = ":8080" }
          secrets = {
            db-url = {
              app_file_env = "SSL_CERT_FILE"
              secret_arn   = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:nex-db-abcdef"
              kms_key_arn  = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
              base64       = false
            }
          }
        }
      }
    }
  }
  expect_failures = [var.production_task_templates]
}


run "reject_aws_config_file_override" {
  command = plan
  variables {
    production_execution = {
      services           = ["control"]
      logs_kms_key_arn   = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
      log_retention_days = 90
    }
    production_task_templates = {
      bootstrap_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      services = {
        control = {
          image_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          cpu          = 256
          memory_mib   = 512
          uid          = 65532
          gid          = 65532
          environment  = { LISTEN_ADDR = ":8080" }
          secrets = {
            db-url = {
              app_file_env = "AWS_CONFIG_FILE"
              secret_arn   = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:nex-db-abcdef"
              kms_key_arn  = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
              base64       = false
            }
          }
        }
      }
    }
  }
  expect_failures = [var.production_task_templates]
}


run "reject_aws_credentials_file_override" {
  command = plan
  variables {
    production_execution = {
      services           = ["control"]
      logs_kms_key_arn   = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
      log_retention_days = 90
    }
    production_task_templates = {
      bootstrap_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      services = {
        control = {
          image_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          cpu          = 256
          memory_mib   = 512
          uid          = 65532
          gid          = 65532
          environment  = { LISTEN_ADDR = ":8080" }
          secrets = {
            db-url = {
              app_file_env = "AWS_SHARED_CREDENTIALS_FILE"
              secret_arn   = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:nex-db-abcdef"
              kms_key_arn  = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
              base64       = false
            }
          }
        }
      }
    }
  }
  expect_failures = [var.production_task_templates]
}


run "reject_other_service_signing_key" {
  command = plan
  variables {
    production_execution = {
      services           = ["control"]
      logs_kms_key_arn   = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
      log_retention_days = 90
    }
    production_task_templates = {
      bootstrap_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      services = {
        control = {
          image_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          cpu          = 256
          memory_mib   = 512
          uid          = 65532
          gid          = 65532
          environment  = { LISTEN_ADDR = ":8080" }
          secrets = {
            db-url = {
              app_file_env = "SIGNING_SEED_FILE"
              secret_arn   = "arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:nex-db-abcdef"
              kms_key_arn  = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
              base64       = false
            }
          }
        }
      }
    }
  }
  expect_failures = [var.production_task_templates]
}

run "maximum_allowlisted_policy_fits" {
  command   = apply
  state_key = "oversized_policy"
  variables {
    production_execution = {
      services           = ["control"]
      logs_kms_key_arn   = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/12345678-1234-1234-1234-123456789012"
      log_retention_days = 90
    }
    production_task_templates = {
      bootstrap_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      services = {
        control = {
          image_digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          cpu          = 256, memory_mib = 512, uid = 65532, gid = 65532
          secrets = {
            for i, env in ["NEX_TLS_CA_FILE", "NEX_TLS_CERT_FILE", "NEX_TLS_KEY_FILE", "DATABASE_URL_FILE", "NEX_DB_CA_FILE", "NEX_HISTORY_CURSOR_KEY_FILE", "NEX_HISTORY_CURSOR_PREVIOUS_KEY_FILE", "GUARD_KEY_FILE", "MODEL_KEY_FILE", "EXPORT_KEY_FILE", "WORKER_KEY_FILE", "EVIDENCE_KEY_FILE", "EVIDENCE_PUBLIC_FILE"] :
            format("secret-%02d", i) => {
              app_file_env = env
              secret_arn   = format("arn:aws-us-gov:secretsmanager:us-gov-west-1:111122223333:secret:%s-%06d", join("", [for n in range(109) : "a"]), i)
              kms_key_arn  = format("arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/%s%02d", join("", [for n in range(108) : "b"]), i)
              base64       = false
            }
          }
        }
      }
    }
  }
  assert {
    condition = (
      length(aws_iam_role_policy.production_task_bootstrap["control"].policy) + length(aws_iam_role_policy.production_execution["control"].policy) <= 10240 &&
      length(aws_iam_role_policy.production_task_bootstrap["control"].policy) + length(aws_iam_role_policy.production_execution["control"].policy) > 9500 &&
      length(jsondecode(aws_iam_role_policy.production_task_bootstrap["control"].policy).Statement) == 15
    )
    error_message = "Maximum allowed control secrets must fit IAM limits and retain per-pair KMS statements."
  }
}
