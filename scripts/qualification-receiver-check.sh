#!/usr/bin/env bash
# Read-only receiver proofs in the existing control network namespace.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
task_project="${NEX_QUAL_PROJECT:-nex-qualification}"
case "$task_project" in nex-qualification) task_default_state="$PWD/.local/qualification" ;; nex-qualification-restore) task_default_state="$PWD/.local/qualification-restore" ;; *) exit 2;; esac
task_state="${NEX_QUAL_STATE_DIR:-$task_default_state}"
task_tools="${NEX_TOOLS_DIR:-/workspace/.tools}"
task_output="${NEX_QUAL_EVIDENCE_DIR:-$PWD/.local/qualification-release-evidence}"
[[ "$task_state" == /* && "$task_output" == /* ]] || { echo 'Absolute state/evidence paths required.' >&2;exit 2; }
mkdir -p bin "$task_output"
GOPATH="${GOPATH:-$task_tools/gopath}" GOCACHE="${GOCACHE:-/tmp/nex-go-cache}" CGO_ENABLED=0 \
 "$task_tools/go/bin/go" build -mod=readonly -trimpath -o bin/qualification-receiver-readiness ./tests/qualification/cmd/receiver-readiness
docker_local() {
 env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH docker --host=unix:///var/run/docker.sock "$@"
}
snapshot() {
 docker_local exec "$task_project-postgres-1" psql -U nex -d nex -X -At -v ON_ERROR_STOP=1 \
  -c 'SELECT row_to_json(t) FROM execution_operations t ORDER BY id' | sha256sum | cut -d' ' -f1
 python3 - "$task_state" <<'PY'
import pathlib,hashlib,json,sys
root=pathlib.Path(sys.argv[1]);out={}
for name in ('model-receipts','export-receipts','evidence'):
 for p in sorted((root/name).rglob('*')):
  if p.is_file():out[str(p.relative_to(root))]=hashlib.sha256(p.read_bytes()).hexdigest()
print(json.dumps(out,sort_keys=True))
PY
}
snapshot > "$task_output/receiver-before.txt"
docker_local run --rm --network "container:$task_project-control-1" --read-only --cap-drop ALL \
 --security-opt no-new-privileges:true --user "$(id -u):$(id -g)" --entrypoint /readiness-probe \
 --mount "type=bind,src=$PWD/bin/qualification-receiver-readiness,dst=/readiness-probe,readonly" \
 --mount "type=bind,src=$task_state/current-pki/ca.crt,dst=/ca.crt,readonly" \
 --mount "type=bind,src=$task_state/current-pki/control/tls.crt,dst=/tls.crt,readonly" \
 --mount "type=bind,src=$task_state/current-pki/control/tls.key,dst=/tls.key,readonly" \
 --mount "type=bind,src=$task_state/secrets/model-key,dst=/model-key,readonly" \
 --mount "type=bind,src=$task_state/secrets/export-key,dst=/export-key,readonly" \
 -e NEX_PROFILE=synthetic-qualification -e APP_ENV=development \
 -e NEX_TLS_CA_FILE=/ca.crt -e NEX_TLS_CERT_FILE=/tls.crt -e NEX_TLS_KEY_FILE=/tls.key \
 -e MODEL_URL=https://model:8082 -e EXPORT_URL=https://executor:8083 \
 -e MODEL_KEY_FILE=/model-key -e EXPORT_KEY_FILE=/export-key -e NO_PROXY='*' \
 nex-control:qualification > "$task_output/receiver-readiness.json"
snapshot > "$task_output/receiver-after.txt"
cmp "$task_output/receiver-before.txt" "$task_output/receiver-after.txt"
printf '%s\n' 'Actual receiver readiness proofs passed; execution rows, receipt files and signed journal bytes unchanged.'
