variable "production_service_scaffolds" {
  description = "Explicit zero-task Fargate service scaffolds. Application activation is not supported by this input."
  type = object({
    services         = set(string)
    database_clients = optional(set(string), [])
  })
  default = null
  validation {
    condition = var.production_service_scaffolds == null ? true : (
      length(var.production_service_scaffolds.services) > 0 &&
      (var.production_task_templates == null ? false : alltrue([for name in var.production_service_scaffolds.services : contains(keys(var.production_task_templates.services), name)])) &&
      (var.production_service_network == null ? false : alltrue([for name in var.production_service_scaffolds.services : contains(var.production_service_network.services, name)])) &&
      alltrue([for name in var.production_service_scaffolds.database_clients : contains(var.production_service_scaffolds.services, name) && contains(["control", "guard", "workspace"], name)]) &&
      (length(var.production_service_scaffolds.database_clients) == 0 || var.production_database != null)
    )
    error_message = "Select existing reviewed task and service-network identities; database clients must be selected control, guard or workspace services with an explicitly configured database."
  }
}
