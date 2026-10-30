# Private ECS service discovery

`production_service_discovery` is null by default. To opt in, select an
operator-reviewed private namespace, DNS TTL of 10–300 seconds and existing
zero-task ECS scaffold names. The module creates one private Cloud Map namespace
associated with the existing VPC, a service for each selection and an ECS
registry attachment for the matching scaffold. It creates no task, ingress,
public DNS record, routing outside the VPC, certificate or workload identity.
The resulting addresses are `<service>.<namespace>`; clients must also have
the reviewed security group connections and correct application ports.

Check namespace overlap with existing private zones and corporate DNS before
planning. Creating the namespace also creates a Route 53 private hosted zone
and incurs Cloud Map and Route 53 charges. Review the actual AWS plan, DNS
resolver behavior, quota, regional support, task lifecycle, TTL and costs in
the approved environment. Changing a namespace or registry can replace resources
and interrupt lookups. Reconcile affected clients before applying changes.

Cloud Map records are routing hints, not service identity or authorization.
DNS can be cached or return stale addresses; clients must authenticate the
expected peer over TLS, use bounded timeouts, and handle re-resolution safely.
Cloud Map's ECS-managed health is not an authenticated readiness check or proof
of policy, database, evidence or production profile readiness. Verify
registration, deregistration, denial between unauthorized peers, TLS identity,
health checks and replacement behavior on the actual deployed platform before
enabling traffic. Mock Terraform tests only validate configuration structure.
The existing zero-task service restriction is unchanged.
