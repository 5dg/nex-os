#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export NEX_TEST_DATABASE_URL="${NEX_TEST_DATABASE_URL:-postgres://nex:nex-local-synthetic-only@127.0.0.1:5432/nex?sslmode=disable}"
export NEX_TEST_OPA_URL="${NEX_TEST_OPA_URL:-http://127.0.0.1:8181}"
./scripts/check-contracts.sh
go vet ./...
go test -race ./...
go test -race -tags=integration -count=1 -v ./tests/integration ./services/control/api
NEX_TEST_GUARD_BINARY="$PWD/bin/guard-kernel" go test -race -tags=integration -count=1 -v ./services/control/guard
env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock run --rm -v "$PWD/policies:/policies:ro" \
  openpolicyagent/opa@sha256:02d31f4e34dcae04d87b542796aa0d089e42039fe6bbc5601587be44fb218963 test /policies -v
node scripts/workspace-smoke.mjs
node scripts/workspace-workflow-smoke.mjs
python3 scripts/check-local-roles.py
python3 scripts/check-worker-boundary.py

python3 scripts/workflow-smoke.py
python3 scripts/recovery-smoke.py
python3 scripts/verify-restore.py
