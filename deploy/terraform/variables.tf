variable "region" {
  type    = string
  default = "us-gov-west-1"
  validation {
    condition     = contains(["us-gov-west-1", "us-gov-east-1"], var.region)
    error_message = "Only explicitly selected GovCloud regions are permitted."
  }
}

variable "account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "Provide the verified 12-digit GovCloud account ID."
  }
}

variable "name" {
  type    = string
  default = "nex-reference"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,24}$", var.name))
    error_message = "Use 3-25 lowercase characters, digits or hyphens."
  }
}

variable "model_arn" {
  description = "Exact verified regional foundation-model ARN; cross-region profiles are outside this initial foundation."
  type        = string
  validation {
    condition     = can(regex("^arn:aws-us-gov:bedrock:us-gov-(west|east)-1::foundation-model/[A-Za-z0-9.:-]+$", var.model_arn)) && startswith(var.model_arn, "arn:aws-us-gov:bedrock:${var.region}:")
    error_message = "Provide a specific foundation-model ARN in the selected GovCloud region."
  }
}

variable "verified_interface_services" {
  description = "Populate only after recording endpoint availability for this region. Empty means no interface endpoints have been validated."
  type        = set(string)
  default     = []
  validation {
    condition     = alltrue([for s in var.verified_interface_services : contains(["ecr.api", "ecr.dkr", "logs", "kms", "secretsmanager", "bedrock-runtime"], s)])
    error_message = "Only the initial approved service inventory is supported."
  }
}
