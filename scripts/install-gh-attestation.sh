#!/usr/bin/env bash
# Install only the verified public CLI binary; never log in or change Git auth.
set -euo pipefail
task_tools="${NEX_TOOLS_DIR:-/workspace/.tools}"
task_version=2.103.3
task_checksum=4c806978ffce1cec70853302a56d70ac6da4f19bae7adca4e1a8ab00633dd91d
[[ "$(uname -s)/$(uname -m)" == Linux/x86_64 ]] || { echo 'Pinned attestation CLI supports Linux amd64.' >&2;exit 2; }
task_temp="$(mktemp -d /tmp/nex-gh-attestation.XXXXXX)"
trap 'rm -rf "$task_temp"' EXIT
curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
 "https://github.com/cli/cli/releases/download/v$task_version/gh_${task_version}_linux_amd64.tar.gz" -o "$task_temp/gh.tar.gz"
printf '%s  %s\n' "$task_checksum" "$task_temp/gh.tar.gz" | sha256sum --check --strict
tar -xzf "$task_temp/gh.tar.gz" -C "$task_temp" "gh_${task_version}_linux_amd64/bin/gh"
task_binary="$task_temp/gh_${task_version}_linux_amd64/bin/gh"
mkdir -p "$task_tools/bin"
task_target="$task_tools/bin/gh-attestation"
if [[ -e "$task_target" ]]; then
 cmp "$task_binary" "$task_target"
else
 install -m0555 "$task_binary" "$task_target"
fi
"$task_target" --version | head -1
python3 - "$task_target" "$task_version" "$task_checksum" <<'PY'
import hashlib,json,pathlib,sys
binary=pathlib.Path(sys.argv[1])
record={'schema_version':1,'version':sys.argv[2],'archive_sha256':sys.argv[3],'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'source':'https://github.com/cli/cli/releases'}
(binary.parent/'gh-attestation.json').write_text(json.dumps(record,indent=2)+'\n')
PY
