# Isolated synthetic qualification

Use synthetic data only. This profile rejects production configuration and live model SDK construction. Test PKI, fixture identity and ordinary TLS libraries do not establish approved CUI handling, MFA or FIPS qualification.

## Build and start

Use the pinned tools installed by `scripts/bootstrap.sh` and `scripts/bootstrap-rust.sh`.

```sh
./scripts/qualification.sh build-host  # host diagnostic candidate, explicitly not attested
# Or: ./scripts/qualification.sh build  # pinned container builder path
./scripts/qualification.sh init
./scripts/qualification.sh up
./scripts/qualification.sh ready
```

The project is `nex-qualification`, with private `.local/qualification` state and a separate PostgreSQL volume. Existing `nex-local` data is retained. `NEX_TOOLS_DIR` selects the tool root; `NEX_QUAL_STATE_DIR` must name the intended private state. Never delete a volume or secret to repeat startup. Initialization preserves existing state and refuses unknown directories. If initdb finished before its temporary server failed, startup creates only the missing expected `nex` database; it preserves the cluster. PostgreSQL copies its leaf key, certificate and HBA into a private runtime directory with PostgreSQL ownership.

All backend links are internal Docker networks. On the tested daemon, Docker recorded published bindings but omitted their actual listeners for internal-only networks. `qualification-relay.py` therefore exposes exactly the declared local test ports using raw byte relays bound to `127.0.0.1`: PostgreSQL 55432, Guard 55051, control 18080, OPA 18181, workspace 9443 and issuer 9444. It inspects closed project/service/network identities and forwards to current container IPs. TLS remains end to end; no validation is disabled and no external bridge is added. Startup refreshes relay destinations after recreation. Relay PID ownership is checked before stopping; unrelated listeners are never killed. `scripts/qualification.sh down` stops these relays and containers, retaining volumes and private state.

## Execute acceptance in order

The complete ordered entry point is `./scripts/verify-qualification.sh` after startup. It runs the commands below, coordinates both lifecycle harnesses, and leaves the isolated restore project active with source writers stopped. It refuses an existing restore state; it is not a reset command. The wrapper's constituent checks are also runnable individually as described below.

Keep one stack coordinator. Run the normal workflow before tests that mutate shared authority. Set `NEX_QUAL_STATE_DIR` to the absolute qualification path and use the pinned Go tool and its configured `GOPATH`/`GOCACHE`.

```sh
go test -race -tags=integration -count=1 -timeout=4m ./tests/qualification -run '^TestQualificationSystem($|APITokenBoundary$)'
go test -race -tags=integration -count=1 ./tests/qualification -run '^TestQualificationSystemPostgresTLSAndRoles$'
go test -race -tags=integration -count=1 -timeout=5m ./tests/qualification -run '^TestQualificationSystemKernel'
./scripts/qualification-receiver-check.sh
```

The kernel mutation suite temporarily changes shared route/catalogue/admission/source records and restores each case. Do not run workflows concurrently. The receiver probe uses an ephemeral container in the control network namespace, makes readiness requests only, and compares execution rows, receipt files and signed journal bytes before and after.

## Certificate rotation and restore

Use the independent `TestQualificationCustodyTransition` harness with explicit `NEX_QUAL_TRANSITION=rotation` or `restore`, an absolute state directory and a new private empty `NEX_QUAL_TRANSITION_SIGNAL_DIR`. For restore also set the distinct absolute `NEX_QUAL_RESTORE_STATE_DIR`. The harness keeps the old browser cookie in memory and writes only a public checkpoint and phase markers.

Wait for `before.ready`. For rotation run `scripts/qualification.sh rotate-pki`; it stops peers, preserves old PKI generations and all application/signing state, mints a new generation, force-recreates PostgreSQL and every peer to remount secrets, and refreshes relays. For restore run `scripts/qualification-restore.sh`; it rejects any prior restore state/container/volume, stops every source writer, dumps PostgreSQL, copies private custody and PKI, stops the remaining source services, and restores into the empty distinct `nex-qualification-restore` volume. It never uses `--clean`. Minimal runtime roles are reapplied by the ordinary seed path. Source state and volume remain retained, with source writers stopped.

After readiness succeeds, write `transition.applied` into the signal directory. The harness must write `after.verified`. It checks old-session rejection before token expiry, fresh login, historical receipt bytes, independent journal signatures/prefixes, a real completed export job and its signed database timeline. A timeout or failed assertion is a failed check, not a successful transition. Never run source and restored writers concurrently against copied custody. To return to the source, stop the restore project and its relays first; then start only the source project.

## Evidence and limits

```sh
NEX_RELEASE_PROFILE=synthetic-qualification python3 scripts/release-audit.py "$PWD/.local/qualification-release-evidence"
```

This scans actual qualification image identities, preserves all raw findings and incomplete scanner results, emits full image inventories/CycloneDX SBOMs and keeps source inventory separate from image OS packages. Nonzero is expected while any gate is unresolved; never weaken filters or erase earlier findings. Hosted CI and successful GitHub publication are separate checks. Host compiler ABI records and a passing workflow do not establish pinned-builder reproducibility or production attestation.

Browser sessions are bounded, in-memory and specific to one Node process; restart logs users out. Idle lifetime is five minutes, hard lifetime fifteen minutes, both capped by access/ID-token expiry. Background polling does not extend idle life. Logout removes only the application session; it does not revoke global IdP SSO or cancel already accepted delegated jobs. API calls always recheck access-token authority and current database permissions. Cached JWKs and short JWT lifetimes do not provide immediate issuer-account revocation. ID tokens are not accepted as API credentials. Test identity and credentials must never be used for customer deployments.
