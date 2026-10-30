# Opt-in database foundation. Attaching db_clients to an ECS task is a separate,
# reviewed service deployment decision; no existing workload gains DB access.
resource "aws_security_group" "db_clients" {
  count       = var.production_database == null ? 0 : 1
  name_prefix = "${var.name}-db-client-"
  description = "Attach only to workloads explicitly authorized for PostgreSQL"
  vpc_id      = aws_vpc.main.id
}

resource "aws_security_group" "database" {
  count       = var.production_database == null ? 0 : 1
  name_prefix = "${var.name}-database-"
  description = "Private PostgreSQL ingress from explicitly assigned clients"
  vpc_id      = aws_vpc.main.id
}

resource "aws_vpc_security_group_ingress_rule" "database_client" {
  count                        = var.production_database == null ? 0 : 1
  security_group_id            = aws_security_group.database[0].id
  referenced_security_group_id = aws_security_group.db_clients[0].id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

resource "aws_vpc_security_group_egress_rule" "database_client" {
  count                        = var.production_database == null ? 0 : 1
  security_group_id            = aws_security_group.db_clients[0].id
  referenced_security_group_id = aws_security_group.database[0].id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

resource "aws_db_subnet_group" "production" {
  count      = var.production_database == null ? 0 : 1
  name       = "${var.name}-database"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_db_parameter_group" "production" {
  count       = var.production_database == null ? 0 : 1
  name_prefix = "${var.name}-postgres17-"
  family      = "postgres17"
  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_db_instance" "production" {
  count                         = var.production_database == null ? 0 : 1
  identifier                    = "${var.name}-database"
  engine                        = "postgres"
  engine_version                = var.production_database.engine_version
  instance_class                = var.production_database.instance_class
  allocated_storage             = var.production_database.allocated_storage_gib
  storage_type                  = "gp3"
  storage_encrypted             = true
  kms_key_id                    = aws_kms_key.data.arn
  db_name                       = "nex"
  username                      = "nex_admin"
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.data.arn
  db_subnet_group_name          = aws_db_subnet_group.production[0].name
  parameter_group_name          = aws_db_parameter_group.production[0].name
  vpc_security_group_ids        = [aws_security_group.database[0].id]
  publicly_accessible           = false
  multi_az                      = true
  backup_retention_period       = var.production_database.backup_retention_days
  copy_tags_to_snapshot         = true
  deletion_protection           = true
  skip_final_snapshot           = false
  final_snapshot_identifier     = "${var.name}-database-final"
  apply_immediately             = false
  lifecycle {
    prevent_destroy = true
  }
}
