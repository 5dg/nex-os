#!/usr/bin/env bash
# Single coordinator for the isolated synthetic TLS/OIDC qualification project.
set -euo pipefail
cd "$(dirname "$0")/.."
task_tools="${NEX_TOOLS_DIR:-/workspace/.tools}"
export CARGO_HOME="${CARGO_HOME:-$task_tools/cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$task_tools/rustup}"
export PATH="$task_tools/go/bin:$task_tools/bin:$CARGO_HOME/bin:$PATH"
export GOPATH="${GOPATH:-$task_tools/gopath}" GOCACHE="${GOCACHE:-/tmp/nex-go-cache}" GOTOOLCHAIN=local
export NEX_QUAL_PROJECT="${NEX_QUAL_PROJECT:-nex-qualification}"
case "$NEX_QUAL_PROJECT" in
 nex-qualification) task_default_state="$PWD/.local/qualification" ;;
 nex-qualification-restore) task_default_state="$PWD/.local/qualification-restore" ;;
 *) echo 'Only the primary and isolated restore qualification projects are allowed.' >&2;exit 2 ;;
esac
export NEX_QUAL_STATE_DIR="${NEX_QUAL_STATE_DIR:-$task_default_state}"
export NEX_UID="$(id -u)" NEX_GID="$(id -g)"
compose() {
 env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock compose --project-name "$NEX_QUAL_PROJECT" -f deploy/qualification/compose.yaml "$@"
}
initialize() {
 python3 scripts/qualification-init.py --state "$NEX_QUAL_STATE_DIR"
 bin/evidence public-key "$NEX_QUAL_STATE_DIR/secrets/signing-seed" "$NEX_QUAL_STATE_DIR/evidence-public"
}
ready() {
 task_pki="$NEX_QUAL_STATE_DIR/current-pki"
 curl --noproxy control -fsS --cacert "$task_pki/ca.crt" --cert "$task_pki/workspace-client/tls.crt" --key "$task_pki/workspace-client/tls.key" \
  --resolve control:18080:127.0.0.1 https://control:18080/readyz >/dev/null
 curl --noproxy workspace.nex.test -fsS --cacert "$task_pki/ca.crt" \
  --resolve workspace.nex.test:9443:127.0.0.1 https://workspace.nex.test:9443/api/status >/dev/null
}
case "${1:-}" in
 build) ./scripts/qualification-build.sh container ;;
 build-host) ./scripts/qualification-build.sh host ;;
 init) initialize ;;
 up|start)
  initialize
  task_recreate=()
  if [[ "${NEX_QUAL_RECREATE:-0}" == 1 ]]; then task_recreate=(--force-recreate); fi
  compose up -d --pull never --wait "${task_recreate[@]}" postgres
  # initdb may have completed before a temporary-server startup failure. Finish
  # only the missing expected database; never recreate/reset an existing cluster.
  task_database_exists="$(compose exec -T postgres psql -U nex -d postgres -X -t -A -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_database WHERE datname='nex'")"
  if [[ "$task_database_exists" == 0 ]]; then compose exec -T postgres psql -U nex -d postgres -X -v ON_ERROR_STOP=1 -c 'CREATE DATABASE nex'; fi
  compose run --rm migrate
  compose run --rm seed
  compose up -d --no-build --pull never "${task_recreate[@]}" issuer opa-edge opa evidence guard model executor control worker workspace workspace-edge
  python3 scripts/qualification-relay.py start --state "$NEX_QUAL_STATE_DIR"
  for attempt in {1..60}; do
   if ready; then echo 'Synthetic qualification stack ready; no production/CUI authorization.';exit 0;fi
   sleep 1
  done
  compose logs --tail=20 control guard workspace workspace-edge opa-edge
  exit 1
  ;;
 rotate-pki)
  # All data is retained. Generate an additional trust generation, then restart
  # every peer so immutable trust snapshots change together. Existing sessions
  # are intentionally invalidated by process restart.
  python3 scripts/qualification-relay.py stop --state "$NEX_QUAL_STATE_DIR"
  compose stop worker control workspace-edge workspace model executor guard evidence opa opa-edge issuer postgres
  python3 scripts/qualification-init.py --state "$NEX_QUAL_STATE_DIR" --rotate-pki
  export NEX_QUAL_RECREATE=1
  exec "$0" up
  ;;
 ready) ready ;;
 down)
  python3 scripts/qualification-relay.py stop --state "$NEX_QUAL_STATE_DIR"
  compose down ;; # Never remove the qualification volume or historical keys.
 logs) compose logs --tail=80 ;;
 *) echo 'Usage: scripts/qualification.sh build|build-host|init|up|ready|rotate-pki|logs|down' >&2;exit 2;;
esac
