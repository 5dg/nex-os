#!/usr/bin/env bash
# E-owned execution only. Run from a reviewed capture; preserve every failed run.
set -euo pipefail
umask 077
export PYTHONDONTWRITEBYTECODE=1
task_tools="${NEX_TOOLS_DIR:-/workspace/.tools}"
export NEX_TOOLS_DIR="$task_tools" CARGO_HOME="${CARGO_HOME:-$task_tools/cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$task_tools/rustup}"
export PATH="$task_tools/go/bin:$task_tools/bin:$CARGO_HOME/bin:$task_tools:$PATH"
export GOPATH="${GOPATH:-$task_tools/gopath}" GOCACHE="${GOCACHE:-/tmp/nex-go-cache}" GOTOOLCHAIN=local
[[ $# == 2 && "$1" == /* && "$2" == */20 ]] || { echo 'Usage: candidate-pipeline.sh /absolute/candidate.json inspected-RFC1918/20' >&2; exit 2; }
export NEX_QUAL_CANDIDATE_MANIFEST="$1"
task_base="$(dirname "$1")"
cd "$task_base/source"
python3 scripts/candidate.py verify --candidate "$1"
[[ ! -e "$task_base/pipeline.log" ]] || { echo 'Retain the prior pipeline; capture a new candidate.' >&2; exit 2; }
exec 3>&1 4>&2
exec > >(tee "$task_base/pipeline.log") 2>&1
task_tee=$!
task_failed=0
task_log_open=1
task_sealed=0
close_log() {
 if [[ "$task_log_open" == 1 ]]; then
  exec 1>&3 2>&4
  task_log_open=0
  wait "$task_tee" || true
 fi
}
retain_on_exit() {
 local task_exit=$?
 trap - EXIT
 close_log
 if [[ "$task_sealed" != 1 ]]; then
  python3 scripts/candidate-evidence.py seal --candidate "$NEX_QUAL_CANDIDATE_MANIFEST" || true
  if [[ ! -e "$task_base/candidate-bundle.tar.gz" ]]; then
   python3 scripts/candidate-evidence.py bundle --candidate "$NEX_QUAL_CANDIDATE_MANIFEST" --output "$task_base/candidate-bundle.tar.gz" || task_exit=1
  fi
 fi
 exit "$task_exit"
}
trap retain_on_exit EXIT
note() { python3 scripts/candidate-evidence.py note --candidate "$1" --name "$2" --status blocked --reason "$3" || true; }
check() {
 local task_name="$1"; shift
 python3 scripts/candidate-evidence.py run --candidate "$NEX_QUAL_CANDIDATE_MANIFEST" --name "$task_name" --timeout 1800 -- "$@" || task_failed=1
}
mkdir -p "$task_base/evidence"
python3 - "$task_base/evidence/verification-tools.json" <<'PY'
import hashlib,json,pathlib,shutil,subprocess,sys
tools={}
for name,args,required in [('go',['version'],'go1.27.3'),('rustc',['--version'],'rustc 1.99.1'),('node',['--version'],'v24.19.0'),('npm',['--version'],None),('govulncheck',['-version'],'v1.1.4'),('cargo-audit',['--version'],'0.22.2'),('trivy',['--version'],'0.76.1')]:
    path=shutil.which(name)
    if not path: raise SystemExit('Pinned verification prerequisite missing: '+name)
    result=subprocess.run([path,*args],capture_output=True,text=True,timeout=30)
    version=(result.stdout+result.stderr).strip()
    if result.returncode or (required and required not in version): raise SystemExit('Verification prerequisite version mismatch: '+name)
    actual=pathlib.Path(path).resolve()
    with actual.open('rb') as stream: digest=hashlib.file_digest(stream,'sha256').hexdigest()
    tools[name]={'path':str(actual),'sha256':digest,'version':version}
pathlib.Path(sys.argv[1]).write_text(json.dumps({'schema_version':1,'scope':'host verification tools, separate from canonical compiler identities','tools':tools},sort_keys=True,indent=2)+'\n')
PY
# Compiler output trees are fresh and distinct; failed builds are never resumed.
task_plan_one=(); task_plan_two=()
for task_phase in ONE TWO; do
 task_plan_name="NEX_CANONICAL_RESOURCE_PLAN_$task_phase"
 task_plan_path="${!task_plan_name:-}"
 if [[ -n "$task_plan_path" ]]; then
  [[ "$task_plan_path" == /* && -f "$task_plan_path" ]] || { echo 'Absolute reviewed resource plan required.' >&2; exit 2; }
  if [[ "$task_phase" == ONE ]]; then task_plan_one=(--resource-plan "$task_plan_path"); else task_plan_two=(--resource-plan "$task_plan_path"); fi
 fi
done
if python3 scripts/canonical-build.py --candidate "$1" --build one "${task_plan_one[@]}" &&
   python3 scripts/canonical-build.py --candidate "$1" --build two "${task_plan_two[@]}"; then
 python3 scripts/candidate-evidence.py compare --candidate "$1" || task_failed=1
 python3 scripts/ipam-preflight.py --block "$2" --output "$task_base/ipam-preflight.json"
 python3 scripts/candidate.py ipam --candidate "$1" --block "$2"
 source scripts/qualification-context.sh
 if [[ -z "${NEX_BROWSER_FIXTURE_IMAGE:-}" ]]; then
  # Supplemental test tooling is separate from the six runtime images. Normal
  # signed APT/TLS and the exact frontend are retained; no browser TLS bypass.
  env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
   docker --host=unix:///var/run/docker.sock build --no-cache \
   --build-arg BUILDKIT_SYNTAX=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e \
   --secret "id=proxy_ca,src=${NEX_BUILD_CA:-/etc/ssl/certs/ca-certificates.crt}" \
   --iidfile "$task_base/browser-image-id" -f apps/workspace/tests/browser/Dockerfile .
  export NEX_BROWSER_FIXTURE_IMAGE="$(cat "$task_base/browser-image-id")"
 fi
 if ./scripts/qualification.sh up; then
  # A fresh private fixture exports its temporary endpoints only into the child.
  check native-fixtures bash scripts/qualification-native-fixtures.sh --candidate "$1" -- bash scripts/candidate-native-suite.sh
  # This ordered runner includes DOM/revocation/polling before PKI/restore.
  check qualification ./scripts/verify-qualification.sh
 else
  note "$1" qualification 'Candidate stack did not become ready; retain build/stack diagnostics.'
  task_failed=1
 fi
 export NEX_RELEASE_PROFILE=synthetic-qualification
 check vulnerability-scans python3 scripts/release-audit.py "$task_base/evidence/scans"
else
 note "$1" qualification 'Canonical build did not complete; no tested-image claim.'
 task_failed=1
fi
# These remote facts arrive in a separate completed-run receipt. They cannot be
# proved by a local shell exit or embedded circularly in the unfinished subject.
for task_gate in hosted-ci durable-retention provenance-attestation; do
 note "$1" "$task_gate" 'Pending completed hosted run and independent retained-artifact verification.'
done
# Close the live log before hashing it into a sealed bundle.
close_log
# Pending future remote facts keep the release record blocked but are not a
# fabricated CI failure. Actual local failures already set task_failed above.
python3 scripts/candidate-evidence.py seal --candidate "$1" || true
python3 scripts/candidate-evidence.py bundle --candidate "$1" --output "$task_base/candidate-bundle.tar.gz"
task_sealed=1
exit "$task_failed"
