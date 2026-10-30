# Requirements for phased receipt custody

The phased receipt API is an unconnected prototype. Its nonce and database
checks do not establish authenticated receiver ownership, prevent stale replicas
from dispatching, or make failover and restore safe. The existing receipt table
is readable by its receiver role; another replica sharing that role can observe
the nonce. A nonce is therefore not a receiver identity or a fencing capability.
No production path may use either the phased or legacy unphased API until the
dependencies below are implemented and independently verified.

Trusted custody must bind each exact tenant, operation, request digest, receiver
domain, authenticated receiver workload, independently authenticated receiver
instance and claim generation to an authoritative fence generation. Instance
identity must be derived from verified workload credentials, never a request
field. The claim must be issued and checked by an independently trusted
authority; a role that reads receipt rows must not be able to mint, replace,
transfer, or impersonate claims. Bindings must be immutable for the lifetime of
an attempt, and expiry or revocation must be checked against current authority.
The target deployment must select and protect the signing, key custody and
workload identity mechanisms; the test Ed25519 keys and mock authorities in this
repository do not make that selection.

The receipt claim, its owner and authoritative fence generation need an atomic
admission protocol with durable ordering. A failover or restore must either
preserve every acknowledged marker and authority generation (proven RPO zero)
or stop admission until potentially lost and in-flight effects have been
independently reconciled. An epoch read or boolean callback before dispatch does
not close the race with a later failover, revoke an in-flight external request,
or fence a previously authorized stale process. A provider or independently
controlled admission boundary must enforce the relevant fence across the effect;
the deployment must demonstrate this behavior rather than infer it from a DB
transaction, process-local lock, shared filesystem, or an unverified timestamp.

Dispatch preflight, fenced effect dispatch, authenticated receiver handoff and
completed user-result read require distinct current-authority decisions. The
handoff permits the original authorized receiver to obtain its committed result
only to complete Guard; it is not a user-result read. The latter requires both a
completed Guard operation and a completed matching receipt. Unknown, denied,
stale, revoked, missing or mismatched authority fails closed; an uncertain
effect is never automatically retried. Existing single-callback receipt APIs
cannot express this separation and must not become alternate production paths.

The prototype's conservative status matrix is:

| Purpose | Guard operation | Receipt | Additional requirement |
| --- | --- | --- | --- |
| Dispatch preflight | pending | absent or attested not-started | Current authority and proven recovery continuity; no effect yet |
| Effect dispatch | started | started | Exact authenticated active claimant, one-shot Guard grant and effective fence |
| Receiver handoff | started | completed | The same authenticated active claimant; handoff only to complete Guard |
| Completed-result read | completed | completed | Separately authenticated current user/result authority |
| Reconciliation | No default | No default | Separate privileged policy, read-only investigation and audited decisions; never an effect retry |

The status matrix is necessary but not sufficient: the present prototype cannot
prove the additional claimant, authority and fencing requirements. All other
combinations, including denied or unrecognized Guard states and started or
unknown receipts for user-result reads, deny access.

When the completed receipt was committed but handoff failed or its reply was
lost, the current API returns unknown and cannot automatically complete Guard.
Recovery requires a separately authorized, audited reconciliation procedure:
authenticate the operator or recovery workload independently, bind its authority
to the exact tenant/operation/digest and destination, establish the current
nonrollback fence, verify the provider outcome and immutable receipt/evidence,
and decide whether a Guard completion is permitted. Reconciliation is not a
dispatch grant, does not automatically release a user result, and never retries
an uncertain effect. The authority, provider evidence, failure/expiry handling,
and approval policy for this procedure remain to be selected and verified.
