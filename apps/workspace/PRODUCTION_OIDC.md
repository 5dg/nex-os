# OIDC assurance precursor

The workspace production profile remains closed. The optional assurance policy
is currently testable only in `synthetic-qualification`; it does not implement
a production identity provider, real MFA or a production trust transport. The
existing synthetic issuer does not issue MFA claims, so an enabled MFA policy
rejects its ordinary login until a separate reviewed assurance fixture is used.

`NEX_OIDC_ASSURANCE_POLICY_FILE` may point to a 0400/0600 regular file owned by
the workspace service UID, without a symlink or special bits. The JSON document
must contain exactly these fields:

- `issuer`, `clientId`, `audience`, `requiredAccessScope`, and
  `authorizationScopes` (including `openid` and the required access scope).
- `workspaceOrigin` and its exact `/auth/callback` `redirectURI`.
- Exact approved `authorizationEndpoint`, `tokenEndpoint` and `jwksURI`.
- `allowedAcr` and `requiredAmr` arrays and `maxAuthAgeSeconds` (1–86400).

Values must use HTTPS without credentials, query strings or fragments. Unknown
policy fields, duplicate scope/assurance values and mismatched workspace issuer,
client, audience, scope or callback fail closed. Discovery must advertise code
flow, S256 PKCE, RS256 and `client_secret_basic`, and its issuer/endpoints must
exactly match the policy. The current synthetic transport also requires all
three endpoints to share the configured issuer origin and fixture workload
identity. A split-origin provider needs independently reviewed network and TLS
transport before it can be used.

ACR/AMR names alone do not establish MFA. The deployment owner must approve the
chosen provider's documented assurance semantics and required authentication
freshness. Signed ID-token claims and assurance are checked after cryptographic
ID-token/nonce verification and before control resolves the current actor. The
actor is then bound after control independently validates the access token;
issuer and subject must agree. Existing sessions without the required assurance
are denied; assurance is rechecked on protected session and workflow requests.
Logout still requires a valid session, canonical host, origin and CSRF
token, and can revoke a session after assurance expires.

Policy contents are snapshotted at process startup. Replacing file contents does
not reload the running process; changing or removing the configured path at
runtime fails closed. Coordinate deployment across every replica when changing
or tightening policy, drain old replicas and verify the effective policy before
claiming enforcement. Existing sessions may require reauthentication.

Real IdP endpoint trust, access-token profile and issuer/JWKS behavior, customer
MFA semantics, signed session provenance and live identity tests remain required
before production admission. Never use this precursor as a claim of customer
identity or production readiness.
