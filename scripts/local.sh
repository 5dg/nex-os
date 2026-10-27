#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Only target the managed/local daemon. Preserve registry credentials and proxy defaults.
compose() {
  env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
    docker --host=unix:///var/run/docker.sock compose --project-name nex-local -f deploy/local/compose.yaml "$@"
}
export NEX_BUILD_CA="${NEX_BUILD_CA:-/etc/ssl/certs/ca-certificates.crt}"
export BUILDX_CONFIG="${BUILDX_CONFIG:-/tmp/nex-buildx}"
mkdir -p "$BUILDX_CONFIG"
export NEX_UID="$(id -u)" NEX_GID="$(id -g)"
case "${1:-}" in
  up|start)
    python3 scripts/local-secrets.py
    if [[ "$1" == up ]]; then ./scripts/build-local.sh; bin/evidence public-key .local/signing-seed .local/evidence-public; compose build; fi
    compose up -d --wait postgres
    compose run --rm migrate
    compose run --rm seed
    compose up -d --no-build --pull never issuer opa guard control model executor evidence worker workspace
    for attempt in {1..60}; do
      if curl --noproxy 127.0.0.1 -fsS http://127.0.0.1:8080/readyz >/dev/null && \
         curl --noproxy 127.0.0.1 -fsS http://127.0.0.1:3000/api/status >/dev/null; then
        echo 'Local synthetic-data stack ready.'; exit 0
      fi
      sleep 1
    done
    compose logs --tail=30 control workspace opa
    exit 1
    ;;
  down) compose down ;; # Named database volume is intentionally preserved.
  logs) compose logs --tail=80 ;;
  migrate|seed) compose run --rm "$1" ;;
  *) echo 'Usage: scripts/local.sh up|start|down|logs|migrate|seed' >&2; exit 2 ;;
esac
