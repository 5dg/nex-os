#!/usr/bin/env bash
# I alone schedules this destructive-to-availability, state-preserving check.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
source scripts/qualification-context.sh
[[ "$NEX_QUAL_PROJECT" == "$NEX_QUAL_PRIMARY_PROJECT" ]] || { echo 'Packaged lifecycle requires the primary stack.' >&2; exit 2; }
if [[ -n "${NEX_QUAL_CANDIDATE_MANIFEST:-}" ]]; then
 python3 scripts/candidate.py verify-images --candidate "$NEX_QUAL_CANDIDATE_MANIFEST" --build "${NEX_QUAL_BUILD:-one}"
 export NEX_LIFECYCLE_SCOPE=canonical-candidate
else
 [[ "${NEX_LIFECYCLE_DIAGNOSTIC:-}" == 1 ]] || { echo 'A candidate or explicit diagnostic mode is required.' >&2; exit 2; }
 export NEX_LIFECYCLE_SCOPE=diagnostic-current-images
fi
export NEX_LIFECYCLE_OUTPUT="${NEX_LIFECYCLE_OUTPUT:-${NEX_QUAL_EVIDENCE_DIR:-$NEX_QUAL_STATE_DIR}/packaged-lifecycle}"
[[ "$NEX_LIFECYCLE_OUTPUT" == /* && ! -e "$NEX_LIFECYCLE_OUTPUT" ]] || { echo 'New absolute lifecycle output directory required; preserve earlier attempts.' >&2; exit 2; }
mkdir -m 700 "$NEX_LIFECYCLE_OUTPUT"
export NEX_LIFECYCLE_COORDINATED=1
task_tools="${NEX_TOOLS_DIR:-/workspace/.tools}"
export GOPATH="${GOPATH:-$task_tools/gopath}" GOCACHE="${GOCACHE:-/tmp/nex-go-cache}" GOTOOLCHAIN=local
"$task_tools/go/bin/go" test -mod=readonly -race -tags=integration -count=1 -timeout=600s \
 ./tests/qualification -run '^TestQualificationPackagedLifecycle$' -v
./scripts/qualification.sh ready
