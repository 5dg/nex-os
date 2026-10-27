# Alpha 0.3 work-in-progress checkpoint

This local checkpoint contains the Alpha 0.2 baseline and the first Alpha 0.3 implementation slice for review. Remote publication is established only by a successful push. It is not a finished or qualified release.

The accepted interface is `docs/architecture/ALPHA03_TRUST_CONTRACT.md`. Work in this checkpoint includes shared Go TLS/profile primitives, v3 contracts, strict API-token validation, synthetic OIDC/PKI fixtures, receiver/signing updates, Rust qualification work, and initial deployment tooling. Integration, qualification Compose wiring, adversarial tests and final release evidence are in progress. Component checks do not establish an end-to-end pass.

The historical Alpha 0.2 validation remains in `docs/VALIDATION.md`. Its results do not certify the changes on this work-in-progress branch. Live GovCloud/Bedrock, production cryptography, customer identity, CUI use and formal assessments remain unavailable/deferred. The native Go advisory feed, unresolved OS advisories and an actual hosted CI result are separate release gates.

Runtime keys, credentials, test PKI, receipts, journal data, local evidence, build artifacts and dependency caches are intentionally excluded from Git. All synthetic credentials in authored tests/configuration are fixtures only.

The local implementation now includes qualification runtime wiring, browser session flow, v3 authority handling, isolated deployment configuration and receiver-readiness proofs. The first isolated core stack completed TLS PostgreSQL bootstrap, migrations and seed, and returned HTTP200 from control readiness using a workspace mTLS certificate. The browser workflow and final current-source candidate remain pending integration. PostgreSQL bootstrap required a private HBA copy readable by its runtime user; an interrupted init was recovered by creating only the missing expected database, preserving the existing cluster. This Docker daemon suppresses published bindings on internal-only networks; fixed loopback TCP relays preserve those networks and end-to-end TLS without adding an external bridge.

Whole-repository Go race tests passed for checkpoint3. Prior component checks passed for Rust and the workspace, including a real delayed intermediate-certificate expiry test. These checks do not establish the full workflow or a qualified release.

Normal pushes of initial local commit `7c9e3468b37f34592eb65976f5e508b907d1c741` and checkpoint2 `274635d904f561d062a3bcbb16cdc93c15867eab` were rejected with HTTP403 because the configured GitHub identity lacked repository write access. No credentials are changed to work around that result; publication is retried only at meaningful checkpoints or after an access update.
