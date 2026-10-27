#!/usr/bin/env bash
set -euo pipefail
task_tools="${NEX_TOOLS_DIR:-/workspace/.tools}"
export CARGO_HOME="$task_tools/cargo" RUSTUP_HOME="$task_tools/rustup"
if [[ ! -x "$CARGO_HOME/bin/rustup" ]]; then
  task_installer="$(mktemp)";trap 'rm -f "$task_installer"' EXIT
  curl -fsSL https://sh.rustup.rs -o "$task_installer"
  echo '9502b514362a21096210d498f143b8cdacda365d3dfcf45e8f5541e089ccafc0  '"$task_installer" | sha256sum -c -
  sh "$task_installer" -y --no-modify-path --profile minimal --default-toolchain 1.99.1
fi
"$CARGO_HOME/bin/rustup" toolchain install 1.99.1 --profile minimal --component rustfmt
echo 'Rust installed. Activate CARGO_HOME/bin and preserve CARGO_HOME/RUSTUP_HOME for commands.'
