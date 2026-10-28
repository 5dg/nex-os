#!/usr/bin/env bash
# Native tests of the exported candidate binary or captured Go source, as noted
# by each case; none substitutes for packaged container-runtime qualification.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/qualification-context.sh
[[ -n "${NEX_QUAL_CANDIDATE_MANIFEST:-}" && -n "${NEX_TEST_DATABASE_URL:-}" ]] || { echo 'Candidate and private disposable-schema database endpoint required.' >&2; exit 2; }
python3 - "$NEX_QUAL_TOOL_DIR/build-inputs.json" "$PWD" <<'PY'
import pathlib,sys
sys.path.insert(0,'scripts')
from source_record import verify_artifacts
verify_artifacts(pathlib.Path(sys.argv[1]),pathlib.Path(sys.argv[2]),('guard-kernel',),require_canonical=True)
PY
export NEX_TEST_GUARD_BINARY="$NEX_QUAL_TOOL_DIR/guard-kernel"
task_go="${NEX_TOOLS_DIR:-/workspace/.tools}/go/bin/go"
case "${1:-}" in
 proof-parity)
  "$task_go" test -mod=readonly -tags=integration ./services/control/guard -run '^TestRustRejectsValidSignatureForDifferentEvidenceContent$' -count=1 -race -v
  "$task_go" test -mod=readonly ./tests/qualification -run '^TestEvidenceV1GoldenVectorsPreserveExistingGoProofs$' -count=1 -race -v
  ;;
 shutdown)
  "$task_go" test -mod=readonly -tags=integration ./services/control/guard -run '^Test(QualificationRustSIGTERMClosesAdmissionAndDrainsRPC|RustSIGTERMDrainsActualGrantAndRestartDoesNotRepeat|QualificationRustAdmissionSaturationCancellationAndRecovery)$' -count=1 -race -v
  "$task_go" test -mod=readonly ./packages/trust -run '^TestHTTPShutdownRetainsHandlersUntilDrained$' -count=1 -race -v
  # Original caller authority at commit and the post-dispatch unknown outcome
  # use disposable Go-source integration fixtures, not a container API claim.
  "$task_go" test -mod=readonly -tags=integration ./services/control/api -run '^TestQualified(OriginalWorkspaceExpiryBeforeJobCommit|OriginalWorkerExpiryBeforeLeaseCommit|WorkspaceCancellationBeforeJobCommit|WorkerCancellationBeforeLeaseCommit|OriginalWorkspaceExpiryAfterCommittedApprovalReturnsUnknown)$' -count=1 -race -v
  ;;
 history-pagination)
  [[ -n "${NEX_TEST_OPA_URL:-}" ]] || { echo 'Private native policy endpoint required for history pagination.' >&2; exit 2; }
  # Captured Go-source HTTP/DB/OPA/signer fixtures, not the packaged Control API.
  # The candidate evidence runner rejects zero-test or skipped-test output.
  "$task_go" test -mod=readonly -tags=integration -race -count=1 -timeout=3m ./services/control/api -run '^TestHistoryPaginationIntegration$' -v
  ;;
 *) echo 'Usage: qualification-native-check.sh proof-parity|shutdown|history-pagination' >&2; exit 2;;
esac
