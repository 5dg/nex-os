#!/usr/bin/env bash
# Check generated Go bindings and shared semantic digests. Rust generates its
# bindings from the same source during its locked build; no generated Rust file
# is kept in the repository.
set -euo pipefail
cd "$(dirname "$0")/.."
task_tools="${NEX_TOOLS_DIR:-/workspace/.tools}"
export CARGO_HOME="${CARGO_HOME:-$task_tools/cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$task_tools/rustup}"
export PATH="$task_tools/go/bin:$task_tools/bin:$CARGO_HOME/bin:$PATH"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/nex-rust-target}"
export GOPATH="${GOPATH:-$task_tools/gopath}"
export GOCACHE="${GOCACHE:-/tmp/nex-go-cache}"
if [[ "${1:-}" == --install-tools ]]; then
  mkdir -p "$task_tools/bin"
  GOBIN="$task_tools/bin" go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
  GOBIN="$task_tools/bin" go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
  cargo fetch --locked --manifest-path services/guard-kernel/Cargo.toml
elif [[ $# -ne 0 ]]; then
  echo 'Usage: scripts/check-contracts.sh [--install-tools]' >&2; exit 2
fi
[[ "$(protoc-gen-go --version)" == 'protoc-gen-go v1.36.12' ]] || { echo 'Pinned protoc-gen-go required; use --install-tools.' >&2; exit 2; }
[[ "$(protoc-gen-go-grpc --version)" == 'protoc-gen-go-grpc 1.6.2' ]] || { echo 'Pinned protoc-gen-go-grpc required; use --install-tools.' >&2; exit 2; }
[[ "$(uname -s)/$(uname -m)" == Linux/x86_64 ]] || { echo 'Select the matching locked vendored protoc for this platform.' >&2; exit 2; }
task_protoc="$(python3 - <<'PY'
import os,pathlib,sys
paths=list(pathlib.Path(os.environ['CARGO_HOME']).glob('registry/src/*/protoc-bin-vendored-linux-x86_64-3.3.0/bin/protoc'))
if len(paths)!=1:sys.exit('Locked protoc unavailable; use --install-tools.')
print(paths[0])
PY
)"
[[ "$("$task_protoc" --version)" == 'libprotoc 36.2' ]] || { echo 'Locked protoc version mismatch.' >&2; exit 2; }
task_generated="$(mktemp -d)"; trap 'rm -rf "$task_generated"' EXIT
"$task_protoc" -I packages/contracts/proto \
  --go_out="$task_generated" --go_opt=module=github.com/5dg/nex-os \
  --go-grpc_out="$task_generated" --go-grpc_opt=module=github.com/5dg/nex-os \
  packages/contracts/proto/nex/guard/v1/guard.proto
diff -ru packages/contracts/gen "$task_generated/packages/contracts/gen"
go test -mod=readonly ./packages/contracts
cargo fmt --check --manifest-path services/guard-kernel/Cargo.toml
cargo test --locked --manifest-path services/guard-kernel/Cargo.toml --lib -- --list | \
  python3 -c 'import sys; lines=sys.stdin.read().splitlines(); expected="execution::tests::semantic_payload_digest_matches_cross_language_vectors: test"; assert expected in lines, "Required Rust conformance test missing"; print(expected)'
cargo test --locked --manifest-path services/guard-kernel/Cargo.toml
printf '%s\n' 'Go bindings reproduce exactly; Go/Rust contract tests passed.'
