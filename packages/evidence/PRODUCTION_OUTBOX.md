# Candidate evidence outbox precursor

This package is unconnected to Guard and does not make candidate prompt release
available. A trusted Guard transaction must insert its authenticated candidate
context and the canonical event through `Enqueue` in the same authoritative
database transaction. The event binds the exact actor, tenant, job, document,
document version, delegation, operation, payload digest and candidate context
digest; an event ID cannot be reused for different bytes. No schema grants are
provisioned by the SQL file.

After commit, a separately authenticated dispatcher may call `Dispatch`. It
makes at most one append attempt per call, verifies the returned proof using an
independently trusted verifier, and durably records the exact proof. The existing
journal's event/proof format is unchanged. An identical retry after a lost append
response must return the original proof; conflicting bytes or a different proof
fail closed. A lost database commit response is unknown and must be resolved by
reading durable state, not by assuming success. `ReadyForRelease` returns no
prompt and requires current authenticated user/session/delegation authority and
proof verification; the caller must recheck authority at the actual release
boundary. Injected authorities, verifiers and appenders must honor deadlines.
The synthetic fixture exercises a subsequent read after a successful commit;
it does not inject a lost PostgreSQL commit response or prove failover recovery.

These checks do not make the SQL transaction atomic with the evidence service or
provide a distributed fence. Automatic retry of a possibly completed append is
safe only if the deployment proves that the journal cannot lose or fork an
acknowledged event, or stops admission and independently reconciles every
potentially lost append before retrying. The configured fence callback is only
an integration point; it does not itself establish nonrollback storage, cancel
an in-flight request, protect the signing key, or provide external evidence
anchoring. Those properties, an authenticated append transport, crypto policy,
role isolation, and an authoritative live session service require deployment
choices and independent verification. Existing local journal custody is not
distributed evidence durability.

The synthetic test role has access to all rows in its disposable outbox. This
precursor does not establish database-level tenant isolation; production must
provide and verify the chosen isolation and least-privilege grants separately.
