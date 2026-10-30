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

`PinnedOutboxProofVerifier` is an optional verifier for the existing Ed25519
evidence-v1 proof format. It copies an explicitly supplied public key, rejects
ambiguous proof fields and noncanonical event bytes, and checks the signature
and event binding. The caller must provision the correct independently trusted
key and handle key rotation. A valid signature does not prove journal continuity,
independent key custody, nonrollback storage, or the health of an external
anchor. This verifier is not wired into production and does not select a
deployment cryptographic or custody policy.

`VerifyAnchoredExtensionContext` checks that a complete signed journal
contains an exact previously retained checkpoint before accepting later
entries. It imposes caller-supplied limits on directory entries and bytes; it
requires a directory protected from untrusted concurrent writers. It does not
retain or advance the checkpoint and cannot detect loss or replacement of
entries after that checkpoint. Safe automatic recovery still requires an
independently durable, monotonic anchor and an effect-spanning fence.

`QualificationOutboxAppender` can send canonical kernel events to the existing
local evidence endpoint using the synthetic qualification profile's mTLS Guard
identity and a body-bound kernel capability. It pins the service role, forbids
redirects and plaintext, and returns ambiguous failures as unknown. The outbox
must still independently verify the returned proof. The existing endpoint uses
local single-writer custody and accepts neither production deployment identity
nor independently durable storage; the appender remains unwired and does not
make retries safe across journal rollback or failover.

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

## Reconciliation commit capture

The control service also inserts a distinct
`job.reconciliation.committed` event into `committed_reconciliation_outbox`
in the same database transaction as a successful reconciliation. The row is
separate from paginated audit history and contains canonical event bytes, a
database-checked SHA-256 digest, the protected operation's request digest and
a digest of the PostgreSQL JSON bytes read for its protected result. Its
existence in a committed database snapshot is not a signature or evidence of
an independently retained journal entry. Its timestamp is the capture time
inside the transaction, not an asserted database commit time.

There is no dispatcher or delivery receipt for these rows. They accumulate
undelivered, and retention limits, backlog monitoring, recovery and an
independent anchor are not implemented. The qualification control role can
insert outbox rows; a future dispatcher must not trust their content solely
because the row exists or its hash matches. It must independently verify the
authenticated writer, exact event scope, protected operation and result,
transaction state, and anchor continuity before signing. A database restore
or untrusted writer can invalidate assumptions based on a local row. Safe
delivery also requires a real effect-spanning fence and reconciliation of
uncertain appends. The capture does not authorize release or export and does
not establish production readiness.
