#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Compile once on the host, then package thin images. The managed VFS Docker
# driver otherwise duplicates large compiler layers for every development build.
mkdir -p bin
task_tools="${NEX_TOOLS_DIR:-/workspace/.tools}"
export CARGO_HOME="${CARGO_HOME:-$task_tools/cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$task_tools/rustup}"
export PATH="$task_tools/go/bin:$task_tools/bin:$CARGO_HOME/bin:$PATH"
export GOPATH="${GOPATH:-$task_tools/gopath}" GOCACHE="${GOCACHE:-/tmp/nex-go-cache}"
export GOTOOLCHAIN=local
task_go_version="$(awk '$1 == "golang" {print $2}' .tool-versions)"
task_rust_version="$(awk '$1 == "rust" {print $2}' .tool-versions)"
[[ "$(go version | awk '{print $3}')" == "go$task_go_version" ]] || { echo 'Pinned Go toolchain required.' >&2; exit 2; }
[[ "$(rustc --version | awk '{print $2}')" == "$task_rust_version" ]] || { echo 'Pinned Rust toolchain required.' >&2; exit 2; }
export CGO_ENABLED=0
task_build_record="$(mktemp /tmp/nex-build-inputs.XXXXXX)"
trap 'rm -f "$task_build_record"' EXIT
python3 scripts/build-record.py begin "$task_build_record"
for task_binary in control dev-issuer; do
  go build -mod=readonly -trimpath -ldflags='-s -w' -o "bin/$task_binary" "./services/control/cmd/$task_binary"
done
go build -mod=readonly -trimpath -ldflags='-s -w' -o bin/model ./services/model/cmd/model
go build -mod=readonly -trimpath -ldflags='-s -w' -o bin/executor ./services/tool-executor/cmd/executor
go build -mod=readonly -trimpath -ldflags='-s -w' -o bin/worker ./services/worker
go build -mod=readonly -trimpath -ldflags='-s -w' -o bin/evidence ./services/evidence
if [[ "${NEX_BUILD_QUALIFICATION_FIXTURES:-0}" == 1 ]]; then
  for task_fixture in qualification-edge qualification-policy-edge; do
    go build -mod=readonly -trimpath -ldflags='-s -w' -o "bin/$task_fixture" "./scripts/$task_fixture"
  done
  go build -mod=readonly -trimpath -ldflags='-s -w' -o bin/qualification-pki ./tests/qualification/cmd/pki
  go build -mod=readonly -trimpath -ldflags='-s -w' -o bin/qualification-issuer ./tests/qualification/cmd/oidc-issuer
fi
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/nex-rust-target}"
cargo build --locked --manifest-path services/guard-kernel/Cargo.toml -j "${CARGO_BUILD_JOBS:-2}"
cp "$CARGO_TARGET_DIR/debug/nex-guard-kernel" bin/guard-kernel.next
strip bin/guard-kernel.next
mv bin/guard-kernel.next bin/guard-kernel
python3 scripts/build-record.py finish "$task_build_record"
