#!/usr/bin/env bash
# Child of the private native fixture wrapper; never serializes its endpoints.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/qualification-context.sh
task_failed=0
for task_gate in proof-parity shutdown; do
 python3 scripts/candidate-evidence.py run --candidate "$NEX_QUAL_CANDIDATE_MANIFEST" \
  --name "$task_gate" --timeout 900 -- bash scripts/qualification-native-check.sh "$task_gate" || task_failed=1
done
exit "$task_failed"
