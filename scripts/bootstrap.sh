#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "$(uname -s)/$(uname -m)" == "Linux/x86_64" ]] || { echo 'Use the versions in .tool-versions on this platform.' >&2; exit 2; }
task_tools="${NEX_TOOLS_DIR:-/workspace/.tools}"
mkdir -p "$task_tools"
task_dir="$(mktemp -d)"; trap 'rm -rf "$task_dir"' EXIT
if [[ ! -x "$task_tools/go/bin/go" ]] || [[ "$("$task_tools/go/bin/go" version)" != *go1.27.3* ]]; then
  curl -fsSL https://go.dev/dl/go1.27.3.linux-amd64.tar.gz -o "$task_dir/go.tar.gz"
  echo '65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40  '"$task_dir/go.tar.gz" | sha256sum -c -
  # Refuse to overwrite an unknown tool installation.
  [[ ! -e "$task_tools/go" ]] || { echo 'Existing Go version differs; select a new NEX_TOOLS_DIR.' >&2; exit 2; }
  tar -xzf "$task_dir/go.tar.gz" -C "$task_tools"
fi
if [[ ! -x "$task_tools/terraform" ]]; then
  curl -fsSL https://releases.hashicorp.com/terraform/1.17.0/terraform_1.17.0_linux_amd64.zip -o "$task_dir/terraform.zip"
  echo 'c168cab7c637a8769fdb90089ddd19de701bc6ff8aca64dc2e2185fe46f59f67  '"$task_dir/terraform.zip" | sha256sum -c -
  python3 - "$task_dir/terraform.zip" "$task_tools" <<'PY'
import sys,zipfile
with zipfile.ZipFile(sys.argv[1]) as z:z.extract('terraform',sys.argv[2])
PY
  chmod +x "$task_tools/terraform"
fi
[[ "$("$task_tools/terraform" version -json | python3 -c 'import json,sys;print(json.load(sys.stdin)["terraform_version"])')" == "1.17.0" ]] || { echo 'Terraform version mismatch.' >&2; exit 2; }
[[ "$(node --version)" == "v24.19.0" ]] || { echo 'Node 24.19.0 required.' >&2; exit 2; }
export PATH="$task_tools/go/bin:$task_tools:$PATH"
export GOPATH="${GOPATH:-$task_tools/gopath}"
export GOCACHE="${GOCACHE:-/tmp/nex-go-cache}"
go mod download
npm --prefix apps/workspace --cache "${NEX_NPM_CACHE:-/tmp/nex-npm-cache}" ci --ignore-scripts
echo 'Dependencies installed. Add NEX_TOOLS_DIR/go/bin and NEX_TOOLS_DIR to PATH, then run make dev.'
