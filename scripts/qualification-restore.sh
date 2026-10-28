#!/usr/bin/env bash
# Quiescent synthetic restore into a new project/volume; original custody retained.
# The caller must serialize this transition with all workflow/mutation tests.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
task_source="${NEX_QUAL_STATE_DIR:-$PWD/.local/qualification}"
task_restore="${NEX_QUAL_RESTORE_STATE_DIR:-$PWD/.local/qualification-restore}"
task_backup="$PWD/.local/qualification-backups/$(date -u +%Y%m%dT%H%M%SZ)-$$"
export NEX_UID="$(id -u)" NEX_GID="$(id -g)"
docker_local() {
 env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH docker --host=unix:///var/run/docker.sock "$@"
}
compose_source() {
 NEX_QUAL_STATE_DIR="$task_source" docker_local compose --project-name nex-qualification -f deploy/qualification/compose.yaml "$@"
}
compose_restore() {
 NEX_QUAL_STATE_DIR="$task_restore" docker_local compose --project-name nex-qualification-restore -f deploy/qualification/compose.yaml "$@"
}
python3 - "$task_source" "$task_restore" <<'PY'
import pathlib,sys
if not all(pathlib.Path(p).is_absolute() for p in sys.argv[1:]):
 raise SystemExit('Source and restore state paths must be absolute')
source,restore=map(lambda p:pathlib.Path(p).resolve(),sys.argv[1:])
if source==restore or source in restore.parents or restore in source.parents:
 raise SystemExit('Source and restore state must be separate directories')
if (source/'synthetic-qualification.state').read_text()!='synthetic-qualification\n':
 raise SystemExit('An existing synthetic source state is required')
if restore.exists():raise SystemExit('Restore state must be new; preserve any prior restore')
PY
if docker_local volume inspect nex-qualification-restore_postgres-data >/dev/null 2>&1; then
 echo 'Restore volume already exists; refusing to overwrite it.' >&2;exit 1
fi
if [[ -n "$(docker_local ps -aq --filter label=com.docker.compose.project=nex-qualification-restore)" ]]; then
 echo 'Restore containers already exist; refusing ambiguous custody.' >&2;exit 1
fi
mkdir -p "$task_backup"
NEX_QUAL_PROJECT=nex-qualification python3 scripts/qualification-relay.py stop --state "$task_source"
# Stop every application/evidence writer before taking either snapshot. PostgreSQL
# remains up only to produce the consistent dump; no source writer is restarted.
compose_source stop worker control workspace-edge workspace model executor guard evidence
task_running="$(docker_local ps --filter label=com.docker.compose.project=nex-qualification --format '{{.Label "com.docker.compose.service"}}')"
while IFS= read -r task_service; do
 case "$task_service" in postgres|issuer|opa|opa-edge|'') ;; *) echo 'Source application writer still running; refusing snapshot.' >&2;exit 1;; esac
done <<< "$task_running"
compose_source exec -T postgres pg_dump -U nex -d nex -Fc > "$task_backup/database.dump"
python3 - "$task_source" "$task_restore" "$task_backup" <<'PY'
import pathlib,shutil,json,hashlib,sys
source,restore,backup=map(pathlib.Path,sys.argv[1:])
restore.mkdir(mode=0o700,parents=True)
names=('secrets','pki','current-pki','model-receipts','export-receipts','evidence','evidence-public','synthetic-qualification.state')
for name in names:
 src,dst=source/name,restore/name
 if src.is_symlink(): dst.symlink_to(src.readlink())
 elif src.is_dir(): shutil.copytree(src,dst,symlinks=True)
 else: shutil.copy2(src,dst)
digests={}
for directory in ('model-receipts','export-receipts','evidence'):
 for path in sorted((source/directory).rglob('*')):
  if path.is_file():digests[str(path.relative_to(source))]=hashlib.sha256(path.read_bytes()).hexdigest()
record={'source_project':'nex-qualification','restore_project':'nex-qualification-restore','quiescent':True,
 'database_dump_sha256':hashlib.sha256((backup/'database.dump').read_bytes()).hexdigest(),
 'custody_sha256':digests,'source_state_retained':True,'production_backup_claim':False}
(backup/'checkpoint.json').write_text(json.dumps(record,indent=2)+'\n')
PY
compose_source stop postgres issuer opa opa-edge
compose_restore up -d --wait postgres
# A newly initialized fixture volume must have no application tables. Never
# restore over an existing schema or use --clean against retained data.
task_tables="$(compose_restore exec -T postgres psql -U nex -d nex -X -At -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_tables WHERE schemaname='public'")"
[[ "$task_tables" == 0 ]] || { echo 'Restore database is not empty.' >&2;exit 1; }
compose_restore exec -T postgres pg_restore -U nex -d nex --exit-on-error --no-owner --no-privileges < "$task_backup/database.dump"
# Seed reapplies the minimal current runtime grants/passwords, not dump ownership.
NEX_QUAL_PROJECT=nex-qualification-restore NEX_QUAL_STATE_DIR="$task_restore" ./scripts/qualification.sh up
printf '%s\n' 'Isolated synthetic restore ready. Original project/state/volume retained with all source writers stopped.'
printf 'Private backup evidence: %s\n' "$task_backup"
