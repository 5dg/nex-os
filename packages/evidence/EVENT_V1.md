# Existing evidence v1 event binding

This specifies the existing Go journal encoding. It adds no event, proof, wire,
signature-domain or historical-file version. Test cryptography and a matching
proof do not establish independent production custody.

The evidence endpoint authenticates the producer and sets `producer` to
`control` or `kernel`. The Rust writer uses the kernel endpoint. An append reply
must bind the exact submitted event after this producer assignment, not merely
repeat its event ID under a valid signing key.

## Head bytes

The head is lowercase hexadecimal SHA-256 of compact UTF-8 JSON with this outer
field order:

```json
{"event":{...},"previous":"..."}
```

The event field order follows the Go `Event` struct, including fields whose
values are empty:

1. `resource_id` (string)
2. `delegation_id` (string)
3. `timestamp_us` (signed 64-bit integer)
4. `producer` (the authenticated endpoint's producer)
5. `event_id` (string)
6. `tenant_id` (string)
7. `actor_id` (string)
8. `job_id` (string, omitted when empty)
9. `action` (string)
10. `detail` (JSON, including `null`)

`detail` is decoded using Go `json.Decoder.UseNumber` and re-encoded using
`encoding/json`. Object keys are sorted recursively by their decoded UTF-8
strings; arrays preserve order. Valid number tokens preserve their original
spelling, including exponent notation. Whitespace and object-key source order
do not survive this normalization.

Go's default string encoding applies to fields, object keys and nested values:
normal JSON escapes, lowercase `\u00xx` control escapes, HTML escapes for `<`,
`>` and `&`, and escapes for U+2028 and U+2029. Other valid Unicode is UTF-8.
Literal backslash escape text remains distinct from the Unicode it names.

The Rust writer computes this head from its **already serialized outbound
request body**, retaining the number-token spelling that the Go signer receives.
An additive `serde_json` RawValue parser may retain those tokens; changing global
number precision or reformatting existing manifest values is out of scope.
The compatibility helper rejects malformed or unsupported input. It does not
extend the accepted producer request schema or make arbitrary non-UTF-8 input
valid.

## Proof verification

The existing signed message remains:

```text
nex-evidence-v1:<sequence>:<head>:<event_id>:<producer>
```

The append client reads the existing proof's `previous` value, recomputes the
head above and checks the exact event ID, authenticated producer and pinned
Ed25519 signature before committing the protected database operation. A valid
signature over another event's head is insufficient. Failures roll back the
candidate grant; existing receipt reconciliation still governs uncertain effects.

The previous value is part of the event-head hash. This per-event check does not
independently establish that the signer persisted a journal, that a sequence is
the latest global head, or that a compromised signer cannot sign an exact request.
External checkpoint/custody requirements remain separate.

## Compatibility evidence

Independent Go-produced vectors must cover genesis and linked heads, empty and
nonempty job IDs, nested objects and arrays, nulls, Unicode/HTML/control escaping,
large integers and numeric-token spellings. Both languages must verify the same
canonical bytes, heads and existing-format signatures. Signed negative fixtures
retain the expected event ID/producer while changing event content or linkage.
Old journal entries, proofs and migrations are never rewritten to satisfy a test.
