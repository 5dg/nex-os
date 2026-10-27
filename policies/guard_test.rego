package nex.authz_test

import rego.v1
import data.nex.authz.decision

sample := {"actor": {"id": "alice", "tenant_id": "a", "permissions": ["document.read", "document.export"]}, "resource": {"tenant_id": "a", "kind": "document", "classification": "internal", "reader_ids": ["alice"]}, "delegation_valid": true, "delegation_permissions": ["document.read", "document.export"], "action": "document.read"}

test_permit if {
    result := decision with input as sample
    result.effect == "allow"
}
test_cross_tenant if {
    result := decision with input as object.union(sample, {"resource": object.union(sample.resource, {"tenant_id": "b"})})
    result.effect == "deny"
}
test_unknown_action if {
    result := decision with input as object.union(sample, {"action": "shell.execute"})
    result.effect == "deny"
}
test_restricted if {
    result := decision with input as object.union(sample, {"resource": object.union(sample.resource, {"classification": "restricted"})})
    result.effect == "deny"
}
test_revocation if {
    result := decision with input as object.union(sample, {"delegation_valid": false})
    result.effect == "deny"
}
test_approval if {
    result := decision with input as object.union(sample, {"action": "document.export"})
    result.effect == "require_approval"
}
test_missing_acl if {
    result := decision with input as object.union(sample, {"resource": object.union(sample.resource, {"reader_ids": []})})
    result.effect == "deny"
}
