package nex.authz

import rego.v1

default decision := {"effect": "deny", "reason_code": "NOT_AUTHORIZED", "policy_version": "alpha-guard-v1"}

base if {
    input.actor.tenant_id == input.resource.tenant_id
    input.delegation_valid
    input.action in input.actor.permissions
    input.action in input.delegation_permissions
    input.actor.id in input.resource.reader_ids
}

decision := {"effect": "allow", "reason_code": "PERMITTED", "policy_version": "alpha-guard-v1"} if {
    base
    input.action == "document.read"
    input.resource.kind == "document"
    input.resource.classification in {"public", "internal", "confidential"}
}

decision := {"effect": "allow", "reason_code": "PERMITTED", "policy_version": "alpha-guard-v1"} if {
    base
    input.action == "model.invoke"
    input.resource.kind == "model"
    input.resource.classification == "public"
    input.data_classification == "public"
}

decision := {"effect": "allow", "reason_code": "PERMITTED", "policy_version": "alpha-guard-v1"} if {
    base
    input.action == "model.invoke"
    input.resource.kind == "model"
    input.data_classification in input.resource.approved_classifications
    input.data_classification != "restricted"
}

decision := {"effect": "allow", "reason_code": "PERMITTED", "policy_version": "alpha-guard-v1"} if {
    base
    input.action == "approval.decide"
    input.resource.kind == "document"
    input.resource.classification in {"public", "internal", "confidential"}
}

decision := {"effect": "require_approval", "reason_code": "APPROVAL_REQUIRED", "policy_version": "alpha-guard-v1"} if {
    base
    input.resource.kind == "document"
    input.action == "document.export"
}
