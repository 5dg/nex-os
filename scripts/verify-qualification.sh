#!/usr/bin/env bash
# Ordered, one-shot acceptance. Starts with primary ready; ends on isolated restore.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
task_tools="${NEX_TOOLS_DIR:-/workspace/.tools}"
export GOPATH="${GOPATH:-$task_tools/gopath}" GOCACHE="${GOCACHE:-/tmp/nex-go-cache}"
source scripts/qualification-context.sh
[[ "$NEX_QUAL_PROJECT" == "$NEX_QUAL_PRIMARY_PROJECT" ]] || { echo 'Start ordered verification on its primary project.' >&2;exit 2; }
task_go="$task_tools/go/bin/go"
task_output="${NEX_QUAL_EVIDENCE_DIR:-$PWD/.local/qualification-release-evidence}"
[[ "$task_output" == /* && "$NEX_QUAL_STATE_DIR" == /* && "$NEX_QUAL_RESTORE_STATE_DIR" == /* ]] || exit 2
[[ ! -e "$NEX_QUAL_RESTORE_STATE_DIR" ]] || { echo 'One-shot verification refuses an existing restore state; preserve and inspect it.' >&2;exit 1; }
mkdir -p "$task_output"
task_harness=''
finish_harness() {
 if [[ -n "$task_harness" ]] && kill -0 "$task_harness" 2>/dev/null; then wait "$task_harness" || true;fi
}
trap finish_harness EXIT
./scripts/qualification.sh ready
"$task_go" test -race -tags=integration -count=1 -timeout=4m ./tests/qualification -run '^TestQualificationSystem($|APITokenBoundary$)' > "$task_output/browser-api.log" 2>&1
"$task_go" test -race -tags=integration -count=1 ./tests/qualification -run '^TestQualificationSystemPostgresTLSAndRoles$' > "$task_output/postgres.log" 2>&1
"$task_go" test -race -tags=integration -count=1 -timeout=5m ./tests/qualification -run '^TestQualificationSystemKernel' > "$task_output/kernel-mutations.log" 2>&1
./scripts/qualification-receiver-check.sh > "$task_output/receivers.log" 2>&1
# DOM identity, revocation and bounded polling belong to the original live
# source stack. Rotation/restore invalidate its sessions and run only afterward.
if [[ -n "${NEX_QUAL_CANDIDATE_MANIFEST:-}" ]]; then
 python3 scripts/candidate-evidence.py run --candidate "$NEX_QUAL_CANDIDATE_MANIFEST" \
  --build "${NEX_QUAL_BUILD:-one}" --name dom-browser --timeout 600 -- ./scripts/qualification-browser.sh
fi
for task_mode in rotation restore; do
 task_signals="$(mktemp -d "$NEX_QUAL_STATE_DIR/acceptance-$task_mode.XXXXXX")"
 NEX_QUAL_TRANSITION="$task_mode" NEX_QUAL_TRANSITION_SIGNAL_DIR="$task_signals" \
  "$task_go" test -race -tags=integration -count=1 -timeout=4m ./tests/qualification -run '^TestQualificationCustodyTransition$' > "$task_output/$task_mode-harness.log" 2>&1 &
 task_harness=$!
 task_marker_ready=0
 for task_attempt in {1..120}; do
  if [[ -f "$task_signals/before.ready" ]]; then task_marker_ready=1;break;fi
  if ! kill -0 "$task_harness" 2>/dev/null; then wait "$task_harness";exit 1;fi
  sleep 0.25
 done
 [[ "$task_marker_ready" == 1 ]] || { echo 'Transition harness did not become ready; inspect retained log.' >&2;exit 1; }
 if [[ "$task_mode" == rotation ]]; then
  ./scripts/qualification.sh rotate-pki > "$task_output/rotation-stack.log" 2>&1
 else
  ./scripts/qualification-restore.sh > "$task_output/restore-stack.log" 2>&1
 fi
 touch "$task_signals/transition.applied"
 wait "$task_harness"
 task_harness=''
 [[ -f "$task_signals/after.verified" ]]
done
printf '%s\n' 'Ordered synthetic qualification passed. Restore project is active; original state/volume retained with source writers stopped.'
