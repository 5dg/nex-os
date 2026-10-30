# Synthetic result-access integration fixture

This fixture is unqualified test code. It uses a fixed, public Ed25519 test key
and a mutable in-process session mock. It cannot provide production identity,
session revocation, cryptographic policy, failover or effect-fencing evidence.

The runtime coordinator must create a fresh empty database and a distinct,
unprivileged login on an owned synthetic TLS PostgreSQL cluster. Both names must
begin `nex_result_fixture_`. Use verified TLS URLs with `sslmode=verify-full`
and an explicit `sslrootcert`; set `NEX_DB_CA_FILE` to the same trusted test CA.
Never use customer or existing application state. The fixture is destructive
to its own disposable database: it applies migrations, grants the restricted
login, inserts synthetic data, and revokes/changes synthetic session records.

With `NEX_RESULT_TEST_DISPOSABLE=yes`, set a new absolute directory directly
under `/workspace` named `nex-result-pki-*` as `NEX_RESULT_TEST_PKI_DIR`, then
run `go run ./services/guard-kernel/tests/synthetic_prepare.go pki`. It refuses
an existing directory and generates a fresh synthetic CA and workload keys.
Start an isolated OPA service with that PKI's `opa` identity and the repository
Guard policy; supply its authenticated HTTPS URL in `NEX_RESULT_TEST_OPA_URL`.
The coordinator must retain its own resource receipts and stop only its stack.
If the runner inherits a proxy, preserve its settings and append the private
`opa` and `postgres` names to its existing `NO_PROXY` and `no_proxy` lists.
Guard's HTTP client otherwise may send the private OPA request to the proxy.

Set `NEX_RESULT_TEST_ADMIN_DSN` and `NEX_RESULT_TEST_GUARD_DSN` to the separate
admin and restricted login URLs and run `go run ./services/guard-kernel/tests/synthetic_prepare.go database`.
The preparer refuses nonempty databases and nonrestricted or owning Guard
logins. It installs synthetic authority state and a vector-derived v3 operation;
the fixture manifest is inserted by the synthetic administrator and does not
establish a trusted production Guard manifest-issuance path.

Set `NEX_TLS_CA_FILE`, `NEX_TLS_CERT_FILE`, and `NEX_TLS_KEY_FILE` to the new
PKI's CA and `guard/tls.crt`, `guard/tls.key`. Set
`NEX_RESULT_TEST_OPERATION=operation-v3-123` and
`NEX_RESULT_TEST_DIGEST=6a6d7815d06aecae50ee34b5be18cc89637209f665a16f72d0e245d44af12109`.
Choose `NEX_RESULT_TEST_SESSION_MODE` explicitly as `original_session_only` or
`current_session_same_actor`; run each mode against its own freshly prepared DB.
Run only the ignored test named `synthetic_guard_mtls_result_access_and_revocation`.
The test uses actual Guard mTLS, the selected synthetic policy service, and
verified PostgreSQL; it verifies fixture-signed assertions and synthetic session
changes. A passing result does not select a customer session policy or enable a
production profile.

Every run requires independently reviewed and frozen source, dependencies,
credentials, resource budget and isolated orchestration. Record the actual
test execution and outcome; do not treat a skipped test as a pass.
