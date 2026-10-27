#!/usr/bin/env bash
set -euo pipefail
# Optional cloud tooling, obtained from AWS's digest-pinned official CLI image.
# This installs no credentials and performs no AWS login.
task_tools="${NEX_TOOLS_DIR:-/workspace/.tools}"
task_image='amazon/aws-cli@sha256:6014c77975a4ae237395924cc821333f20bf87c91964a45dd4ed5f3b13b424f5'
docker_local() {
  env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
    docker --host=unix:///var/run/docker.sock "$@"
}
mkdir -p "$task_tools"
if [[ -e "$task_tools/aws" ]]; then "$task_tools/aws" --version; exit 0; fi
[[ ! -e "$task_tools/aws-cli" ]] || { echo 'Existing AWS CLI files found; inspect before installation.' >&2; exit 2; }
docker_local pull "$task_image"
task_container="$(docker_local create "$task_image" --version)"
trap 'docker_local rm "$task_container" >/dev/null' EXIT
docker_local cp "$task_container:/usr/local/aws-cli" "$task_tools/aws-cli"
python3 - "$task_tools" <<'PY'
import pathlib,sys
root=pathlib.Path(sys.argv[1]).resolve()
files=[p for p in (root/'aws-cli/v2').glob('*/dist/aws') if p.is_file()]
if len(files)!=1:raise SystemExit('Unexpected AWS CLI image layout')
(root/'aws').symlink_to(files[0])
PY
"$task_tools/aws" --version
