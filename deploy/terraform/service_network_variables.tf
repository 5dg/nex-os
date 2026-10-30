variable "production_service_network" {
  description = "Explicit service identities and reviewed directed TCP connections. Null creates no service network resources."
  type = object({
    services = set(string)
    connections = map(object({
      source      = string
      destination = string
      port        = number
    }))
  })
  default = null
  validation {
    condition = var.production_service_network == null ? true : (
      length(var.production_service_network.services) > 0 &&
      alltrue([for service in var.production_service_network.services : contains(["workspace", "control", "guard", "opa", "evidence", "model", "worker", "tool-executor"], service)]) &&
      length(distinct([for edge in values(var.production_service_network.connections) : "${edge.source}:${edge.destination}:${edge.port}"])) == length(var.production_service_network.connections) &&
      alltrue([for name, edge in var.production_service_network.connections : (
        can(regex("^[a-z][a-z0-9-]{0,39}$", name)) &&
        contains(var.production_service_network.services, edge.source) &&
        contains(var.production_service_network.services, edge.destination) &&
        edge.source != edge.destination &&
        edge.port >= 1 && edge.port <= 65535 && floor(edge.port) == edge.port
      )])
    )
    error_message = "Specify supported service names and directed connections between distinct selected services with named TCP ports from 1 to 65535."
  }
}
