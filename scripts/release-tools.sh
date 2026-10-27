#!/usr/bin/env bash
# Install scanners independently from application dependency locks. Run explicitly;
# verification scripts never silently install or update their own scanners.
set -euo pipefail
cd "$(dirname "$0")/.."
task_tools="${NEX_TOOLS_DIR:-/workspace/.tools}"
export CARGO_HOME="${CARGO_HOME:-$task_tools/cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$task_tools/rustup}"
export PATH="$task_tools/go/bin:$task_tools/bin:$CARGO_HOME/bin:$PATH"
export GOPATH="${GOPATH:-$task_tools/gopath}" GOCACHE="${GOCACHE:-/tmp/nex-go-cache}"
mkdir -p "$task_tools/bin"
GOBIN="$task_tools/bin" go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}" cargo install cargo-audit --version 0.22.2 --locked
[[ "$(uname -s)/$(uname -m)" == Linux/x86_64 ]] || { echo 'Select the verified Trivy build for this platform.' >&2; exit 2; }
task_scanner_archive="$(mktemp)";trap 'rm -f "$task_scanner_archive"' EXIT
curl -fsSL https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-64bit.tar.gz -o "$task_scanner_archive"
echo 'c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0  '"$task_scanner_archive" | sha256sum -c -
tar -xzf "$task_scanner_archive" -C "$task_tools/bin" trivy
printf '%s\n' 'Pinned govulncheck, cargo-audit and Trivy scanners installed.'
