# Sourced from the repository root. Contains artifact paths/public identities only.
export PYTHONDONTWRITEBYTECODE=1
if [[ -n "${NEX_QUAL_CANDIDATE_MANIFEST:-}" ]]; then
 task_context_args=(--candidate "$NEX_QUAL_CANDIDATE_MANIFEST" --build "${NEX_QUAL_BUILD:-one}")
 if [[ "${NEX_QUAL_PROJECT:-}" == *-restore ]]; then task_context_args+=(--restore);fi
 task_context="$(python3 scripts/candidate.py env "${task_context_args[@]}")" || return 1
 while IFS='=' read -r task_context_key task_context_value; do
  [[ "$task_context_key" =~ ^NEX_[A-Z0-9_]+$ ]] || return 1
  export "$task_context_key=$task_context_value"
 done <<< "$task_context"
fi
export NEX_QUAL_PROJECT="${NEX_QUAL_PROJECT:-nex-qualification}"
case "$NEX_QUAL_PROJECT" in
 nex-qualification|nex-qualification-restore)
  task_primary_project=nex-qualification
  task_restore_project=nex-qualification-restore
  task_default_primary="$PWD/.local/qualification"
  task_default_restore="$PWD/.local/qualification-restore"
  ;;
 *)
  [[ "$NEX_QUAL_PROJECT" =~ ^nex-alpha04-([0-9a-f]{12})(-restore)?$ ]] || { echo 'Invalid qualification project namespace.' >&2;return 1; }
  [[ "${NEX_QUAL_RUN_ID:-}" == "${BASH_REMATCH[1]}" && -n "${NEX_QUAL_CANDIDATE_MANIFEST:-}" ]] || { echo 'A manifest-bound Alpha04 run ID is required.' >&2;return 1; }
  task_primary_project="nex-alpha04-$NEX_QUAL_RUN_ID"
  task_restore_project="$task_primary_project-restore"
  task_default_primary="$PWD/.local/alpha04/$NEX_QUAL_RUN_ID/state"
  task_default_restore="$PWD/.local/alpha04/$NEX_QUAL_RUN_ID/restore-state"
  ;;
esac
export NEX_QUAL_PRIMARY_PROJECT="$task_primary_project" NEX_QUAL_RESTORE_PROJECT="$task_restore_project"
if [[ "$NEX_QUAL_PROJECT" == "$task_primary_project" ]]; then
 export NEX_QUAL_STATE_DIR="${NEX_QUAL_STATE_DIR:-$task_default_primary}"
 export NEX_QUAL_PRIMARY_STATE_DIR="$NEX_QUAL_STATE_DIR"
 task_network_file="${NEX_QUAL_PRIMARY_NETWORK_FILE:-}"
else
 export NEX_QUAL_STATE_DIR="${NEX_QUAL_STATE_DIR:-$task_default_restore}"
 export NEX_QUAL_PRIMARY_STATE_DIR="${NEX_QUAL_PRIMARY_STATE_DIR:-$task_default_primary}"
 task_network_file="${NEX_QUAL_RESTORE_NETWORK_FILE:-}"
fi
export NEX_QUAL_RESTORE_STATE_DIR="${NEX_QUAL_RESTORE_STATE_DIR:-$task_default_restore}"
export NEX_QUAL_TOOL_DIR="${NEX_QUAL_TOOL_DIR:-$PWD/bin}"
[[ "$NEX_QUAL_STATE_DIR" == /* && "$NEX_QUAL_RESTORE_STATE_DIR" == /* && "$NEX_QUAL_TOOL_DIR" == /* ]] || { echo 'Absolute qualification paths required.' >&2;return 1; }
task_network_args=()
if [[ -n "$task_network_file" ]]; then
 [[ "$task_network_file" == /* && -f "$task_network_file" ]] || { echo 'IPAM override file unavailable.' >&2;return 1; }
 task_network_args=(-f "$task_network_file")
fi
