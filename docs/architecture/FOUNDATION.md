# Architecture status

The initial Go-only foundation has evolved into the local Go/Rust alpha described in [GO_RUST_BOUNDARY.md](GO_RUST_BOUNDARY.md). That document is authoritative for current ownership and failure semantics.

The fixed workflow is document review followed by one approval-protected export. Agents do not execute arbitrary customer code. PostgreSQL holds durable job/lease state; controlled synthetic documents and named destinations are ingested by the development fixture command. Runtime roles cannot change those security facts.

OIDC JWT signature/issuer/audience/expiry validation is functional, using an explicit development issuer in this environment. Browser persona selection is a synthetic test facility, not customer sign-in. Customer IdP/session/MFA configuration is deferred with cloud setup.

Model invocation is behind an explicit provider boundary. The development generator is deterministic. The Bedrock SDK implementation preserves an exact approved route and performs no fallback, but has not been invoked against AWS. Current local storage and transport must be replaced/configured for the approved deployment before processing real CUI.
