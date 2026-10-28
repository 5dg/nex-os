#!/usr/bin/env bash
# Build an explicit host diagnostic candidate or the immutable-builder candidate.
# Neither mode overrides the unresolved source/CI/advisory/assessment release gates.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
cd "$(dirname "$0")/.."
task_mode="${1:-container}"
case "$task_mode" in container|host) ;; *) echo 'Usage: qualification-build.sh [container|host]' >&2; exit 2;; esac
if [[ "$task_mode" == container ]]; then
 task_candidate="${2:-${NEX_QUAL_CANDIDATE_MANIFEST:-}}"
 [[ "$task_candidate" == /* && -f "$task_candidate" ]] || { echo 'Canonical build requires an absolute captured candidate.json path.' >&2;exit 2; }
 python3 scripts/candidate.py verify --candidate "$task_candidate"
 task_snapshot="$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve().parent / "source")' "$task_candidate")"
 exec python3 "$task_snapshot/scripts/canonical-build.py" --candidate "$task_candidate" --build "${3:-one}"
fi
task_tools="${NEX_TOOLS_DIR:-/workspace/.tools}"
export CARGO_HOME="${CARGO_HOME:-$task_tools/cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$task_tools/rustup}"
export PATH="$task_tools/go/bin:$task_tools/bin:$CARGO_HOME/bin:$PATH"
export GOPATH="${GOPATH:-$task_tools/gopath}" GOCACHE="${GOCACHE:-/tmp/nex-go-cache}" GOTOOLCHAIN=local
export BUILDX_CONFIG="${BUILDX_CONFIG:-/tmp/nex-buildx}"
mkdir -p "$BUILDX_CONFIG" bin .local/qualification-build-evidence
# Host diagnostics remain explicit; canonical tools are exported by pinned compilers.
go build -mod=readonly -trimpath -ldflags='-s -w' -o bin/qualification-pki ./tests/qualification/cmd/pki
build_image() {
 env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock build --secret "id=proxy_ca,src=${NEX_BUILD_CA:-/etc/ssl/certs/ca-certificates.crt}" \
  --label "org.nex.qualification.candidate-mode=$task_mode" --label "org.nex.qualification.builder=${3:-$task_mode}" -f "$1" -t "$2" .
}
build_image deploy/qualification/Dockerfile.postgres nex-postgres:qualification container
if [[ "$task_mode" == host ]]; then
 NEX_BUILD_QUALIFICATION_FIXTURES=1 ./scripts/build-local.sh
 build_image deploy/local/Dockerfile.control.local nex-control:qualification
 build_image deploy/local/Dockerfile.guard nex-guard:qualification
 build_image deploy/qualification/Dockerfile.fixtures.local nex-qualification-fixtures:local
else
 build_image deploy/local/Dockerfile.control nex-control:qualification
 build_image deploy/qualification/Dockerfile.guard nex-guard:qualification
 build_image deploy/qualification/Dockerfile.fixtures nex-qualification-fixtures:local
fi
build_image deploy/local/Dockerfile.workspace nex-workspace:qualification container
printf '%s\n' "$task_mode" > .local/qualification-build-evidence/builder-mode
