variable "production_service_discovery" {
  description = "Optional private Cloud Map DNS namespace and explicit zero-count ECS services. Null creates no discovery resources."
  type = object({
    namespace = string
    ttl       = number
    services  = set(string)
  })
  default = null
  validation {
    condition = var.production_service_discovery == null ? true : (
      length(var.production_service_discovery.namespace) <= 253 &&
      length(split(".", var.production_service_discovery.namespace)) >= 2 &&
      alltrue([for label in split(".", var.production_service_discovery.namespace) :
        length(label) <= 63 && can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", label))
      ]) &&
      var.production_service_discovery.ttl >= 10 && var.production_service_discovery.ttl <= 300 &&
      floor(var.production_service_discovery.ttl) == var.production_service_discovery.ttl &&
      length(var.production_service_discovery.services) > 0 &&
      (var.production_service_scaffolds == null ? false : alltrue([
        for service in var.production_service_discovery.services : contains(var.production_service_scaffolds.services, service)
      ]))
    )
    error_message = "Choose a valid lowercase private DNS namespace, TTL of 10-300 seconds, and existing ECS scaffold services."
  }
}
