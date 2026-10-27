# Alpha 0.3 work-in-progress checkpoint

This local checkpoint contains the Alpha 0.2 baseline and the first Alpha 0.3 implementation slice for review. Remote publication is established only by a successful push. It is not a finished or qualified release.

The accepted interface is `docs/architecture/ALPHA03_TRUST_CONTRACT.md`. Work in this checkpoint includes shared Go TLS/profile primitives, v3 contracts, strict API-token validation, synthetic OIDC/PKI fixtures, receiver/signing updates, Rust qualification work, and initial deployment tooling. Integration, qualification Compose wiring, adversarial tests and final release evidence are in progress. Component checks do not establish an end-to-end pass.

The historical Alpha 0.2 validation remains in `docs/VALIDATION.md`. Its results do not certify the changes on this work-in-progress branch. Live GovCloud/Bedrock, production cryptography, customer identity, CUI use and formal assessments remain unavailable/deferred. The native Go advisory feed, unresolved OS advisories and an actual hosted CI result are separate release gates.

Runtime keys, credentials, test PKI, receipts, journal data, local evidence, build artifacts and dependency caches are intentionally excluded from Git. All synthetic credentials in authored tests/configuration are fixtures only.

The next local checkpoint adds the qualification runtime wiring, browser session flow, v3 authority handling and isolated deployment configuration. Component compilation/tests have passed; the first complete TLS qualification deployment is still pending integration. The normal push of initial local commit `7c9e3468b37f34592eb65976f5e508b907d1c741` was rejected with HTTP403 because the configured GitHub identity lacked repository write access. No credentials are changed to work around that result; publication is retried only at meaningful checkpoints or after an access update.
