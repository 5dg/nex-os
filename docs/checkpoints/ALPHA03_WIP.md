# Alpha 0.3 work-in-progress checkpoint

This branch publishes the local Alpha 0.2 baseline and the first Alpha 0.3 implementation slice for review. It is not a finished or qualified release.

The accepted interface is `docs/architecture/ALPHA03_TRUST_CONTRACT.md`. Work in this checkpoint includes shared Go TLS/profile primitives, v3 contracts, strict API-token validation, synthetic OIDC/PKI fixtures, receiver/signing updates, Rust qualification work, and initial deployment tooling. Integration, qualification Compose wiring, adversarial tests and final release evidence are in progress. Component checks do not establish an end-to-end pass.

The historical Alpha 0.2 validation remains in `docs/VALIDATION.md`. Its results do not certify the changes on this work-in-progress branch. Live GovCloud/Bedrock, production cryptography, customer identity, CUI use and formal assessments remain unavailable/deferred. The native Go advisory feed, unresolved OS advisories and an actual hosted CI result are separate release gates.

Runtime keys, credentials, test PKI, receipts, journal data, local evidence, build artifacts and dependency caches are intentionally excluded from Git. All synthetic credentials in authored tests/configuration are fixtures only.
