# Isolated native browser fixture

This directory is separate test tooling. It does not change production workspace
dependencies. E alone builds/runs the image from the captured source with the
ephemeral public build CA. The digest-pinned Node 24.19.0 Bookworm base installs
exact Chromium 156.0.8078.47-1~deb12u1 and NSS 2:3.87.1-1+deb12u4 through ordinary
signed HTTPS APT. Playwright Core 1.64.1 uses the frozen local lockfile. Transitive
OS package versions are recorded, not claimed fully pinned or reproducible.

Build from the repository root with this Dockerfile. The fixture defaults to the
existing `node` user (UID 1000, OS home `/home/node`). Runtime requires a fresh
private tmpfs mounted there, a suitable shared-memory budget, a writable private
`/results` directory, the public qualification root certificate read-only at
`/trust/ca.crt`, and the captured D-owned driver read-only at
`/driver/qualification-browser.mjs`. No application service keys, host NSS
directories, host home directory or persistent browser profiles are mounted.

Set `APP_ENV=development` and `NEX_PROFILE=synthetic-qualification`. Attach only to
the appropriate isolated frontend/issuer networks, using certificate-matching
aliases `workspace.nex.test` and `issuer.nex.test`. Driver arguments include
`--base-url=https://workspace.nex.test:9443`, a reachable wrong-CA URL served by a
separate private TLS fixture, and `--output=/results/browser-results.json`. The
driver connects to fixed loopback CDP port 9222. No host port exposes CDP.

The entry imports only the public CA into the fresh native NSS store before
Chromium starts. It rejects TLS-ignore options by construction: the browser flags
are fixed. The native OS sandbox is enabled by default. Only after E records an
actual kernel/user-namespace failure and the lead approves the exception may E
set `NEX_BROWSER_FIXTURE_NO_SANDBOX=1` for this isolated test container. That
exception is recorded in evidence and never disables certificate verification.

Build and runtime evidence record browser/package versions and actual executable
hashes. Chrome logs, session cookies and NSS/profile contents stay on container
tmpfs and are not exported. Driver outputs contain bounded assertion status and
tool identities, with no HAR, trace, callback URLs, credentials or session handles.
E records the actual fixture image ID, package inventory and measured resource
cost separately from the six application/runtime release images.
