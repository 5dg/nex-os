#!/usr/bin/env bash
# E-only runtime coordinator for native synthetic browser qualification.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
source scripts/qualification-context.sh
[[ $# == 0 && -n "${NEX_QUAL_CANDIDATE_MANIFEST:-}" && "$NEX_QUAL_PROJECT" == "$NEX_QUAL_PRIMARY_PROJECT" ]] || {
 echo 'A source-bound primary candidate is required for browser qualification.' >&2;exit 2;
}
[[ "${NEX_BROWSER_FIXTURE_IMAGE:-}" =~ ^sha256:[0-9a-f]{64}$ ]] || {
 echo 'An immutable browser fixture image is required.' >&2;exit 2;
}
case "${NEX_BROWSER_FIXTURE_NO_SANDBOX:-0}" in 0|1) ;; *) exit 2;; esac
python3 - "$NEX_QUAL_CANDIDATE_MANIFEST" "$PWD" <<'PY'
import pathlib,sys
sys.path.insert(0,'scripts')
from candidate import load
_,_,source=load(pathlib.Path(sys.argv[1]))
if source.resolve()!=pathlib.Path(sys.argv[2]).resolve():
 raise SystemExit('Run the browser coordinator from the captured source, not a different checkout.')
PY
python3 scripts/candidate.py verify-images --candidate "$NEX_QUAL_CANDIDATE_MANIFEST" --build "$NEX_QUAL_BUILD"
task_project="$NEX_QUAL_PROJECT"
task_state="$NEX_QUAL_STATE_DIR"
task_output="$NEX_QUAL_EVIDENCE_DIR/browser"
task_private="$task_state/browser-private"
task_front="$task_project"_browser-front
task_issuer="$task_project"_browser-issuer
task_wrong="$task_project-browser-wrong-ca"
task_browser="$task_project-browser"
task_restore_needed=0
task_browser_created=0
task_wrong_created=0
[[ -f "$task_state/synthetic-qualification.state" && "$(cat "$task_state/synthetic-qualification.state")" == synthetic-qualification ]]
mkdir "$task_output" "$task_private"
mkdir "$task_output/dom" "$task_output/revocation"
docker_local() {
 env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock "$@"
}
# timeout wraps the CLI, never an unbounded database statement or host sleep.
sql() {
 timeout 10s env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock exec -i "$task_project-postgres-1" \
  psql -U nex -d nex -X -At -v ON_ERROR_STOP=1 -c "SET statement_timeout='5s'; SET lock_timeout='3s'; $1"
}
restore_authority() {
 if [[ "$task_restore_needed" == 1 ]]; then
  sql "BEGIN; $(cat "$task_private/restore.sql") COMMIT;" > /dev/null || return 1
  task_restore_needed=0
 fi
}
cleanup() {
 local task_exit=$?
 trap - EXIT INT TERM
 if [[ "$task_browser_created" == 1 ]]; then docker_local rm -f "$task_browser" >/dev/null 2>&1 || task_exit=1;fi
 if [[ "$task_wrong_created" == 1 ]]; then docker_local rm -f "$task_wrong" >/dev/null 2>&1 || task_exit=1;fi
 if ! restore_authority; then echo 'Synthetic authority restoration failed; preserve state and stop qualification.' >&2;task_exit=1;fi
 exit "$task_exit"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Reject accidental access to the Control/backend networks. These two links are
# dedicated Compose/IPAM declarations; the coordinator never creates networks.
docker_local network inspect "$task_front" "$task_issuer" | python3 -c '
import json,sys
project=sys.argv[1]
for network in json.load(sys.stdin):
 suffix=network["Name"].removeprefix(project+"_")
 service={"browser-front":"workspace","browser-issuer":"issuer"}.get(suffix)
 expected=project+"-"+str(service)+"-1"
 names={c["Name"] for c in network.get("Containers",{}).values()}
 if not service or not network.get("Internal") or network.get("Labels",{}).get("com.docker.compose.project")!=project or names!={expected}:
  raise SystemExit("Dedicated internal frontend/issuer network membership required")
' "$task_project"
# Verify the actual executable helper and frozen dependency declarations in the
# supplied image against captured source; no source or host node_modules mount.
docker_local run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
 --entrypoint node "$NEX_BROWSER_FIXTURE_IMAGE" --input-type=module -e \
 'import{readFileSync}from"node:fs";import{createHash}from"node:crypto";for(const n of["entry.mjs","package.json","package-lock.json"])console.log(n+" "+createHash("sha256").update(readFileSync("/fixture/"+n)).digest("hex"));' \
 > "$task_private/image-inputs.txt"
python3 - "$task_private/image-inputs.txt" "$task_output/fixture-inputs.json" "$NEX_BROWSER_FIXTURE_IMAGE" <<'PY'
import hashlib,json,pathlib,sys
base=pathlib.Path('apps/workspace/tests/browser')
actual=dict(line.split() for line in pathlib.Path(sys.argv[1]).read_text().splitlines())
expected={name:hashlib.sha256((base/name).read_bytes()).hexdigest() for name in ('entry.mjs','package.json','package-lock.json')}
if actual!=expected:raise SystemExit('Browser image helper/dependency inputs differ from captured source')
inputs={name:hashlib.sha256((base/name).read_bytes()).hexdigest() for name in ('Dockerfile','entry.mjs','package.json','package-lock.json','README.md')}
pathlib.Path(sys.argv[2]).write_text(json.dumps({'schema_version':1,'image_id':sys.argv[3],'captured_inputs':inputs,'scope':'separate synthetic test tooling; image inputs checked, no reproducibility claim'},indent=2)+'\n')
PY
cat > "$task_private/wrong-ca.json" <<'JSON'
{"valid_for_seconds":600,"entries":[{"name":"untrusted","dns_names":["untrusted.nex.test"],"uris":["spiffe://nex.local/service/browser-untrusted-fixture"],"client_auth":false,"server_auth":true}]}
JSON
"$NEX_QUAL_TOOL_DIR/qualification-pki" --config "$task_private/wrong-ca.json" --directory "$task_private/wrong-pki"
! cmp -s "$task_private/wrong-pki/ca.crt" "$task_state/current-pki/ca.crt"
# The wrong-root server holds only its independently generated leaf, never any
# application certificate, root private key, or browser session material.
docker_local create --name "$task_wrong" --network "$task_front" --network-alias untrusted.nex.test \
 --read-only --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges:true \
 --mount "type=bind,src=$task_private/wrong-pki/untrusted/tls.crt,dst=/wrong.crt,readonly" \
 --mount "type=bind,src=$task_private/wrong-pki/untrusted/tls.key,dst=/wrong.key,readonly" \
 --entrypoint node "$NEX_BROWSER_FIXTURE_IMAGE" --input-type=module -e \
 'import https from"node:https";import{readFileSync}from"node:fs";https.createServer({cert:readFileSync("/wrong.crt"),key:readFileSync("/wrong.key"),minVersion:"TLSv1.3"},(_,r)=>{r.writeHead(200,{"Content-Type":"text/plain"});r.end("synthetic wrong-root fixture\n");}).listen(9445,"0.0.0.0");' > /dev/null
task_wrong_created=1
docker_local start "$task_wrong" >/dev/null
# Prove the listener is serving a successful, hostname-valid HTTPS response with
# its independent root before asking Chromium to reject that untrusted root.
for ((task_attempt=0;task_attempt<50;task_attempt++)); do
 if docker_local exec -i "$task_wrong" node --input-type=module -e \
  'import https from"node:https";let ca="";for await(const c of process.stdin)ca+=c;await new Promise((resolve,reject)=>{const r=https.get({hostname:"127.0.0.1",port:9445,servername:"untrusted.nex.test",ca,minVersion:"TLSv1.3",timeout:1000},s=>{s.resume();s.statusCode===200?resolve():reject();});r.on("timeout",()=>r.destroy());r.on("error",reject);}).catch(()=>process.exit(1));' \
  < "$task_private/wrong-pki/ca.crt" 2>/dev/null;then break;fi
 [[ "$task_attempt" -lt 49 ]] || { echo 'Wrong-root HTTPS fixture did not become ready.' >&2;exit 1; }
 sleep .1
done

start_browser() {
 local task_driver="$1" task_results="$2"
 task_browser_results="$task_results"
 local task_mounted_results="$task_private/${task_driver%.mjs}-results"
 mkdir "$task_mounted_results"
 # The browser writes only this separate in-progress directory. The final
 # evidence directory is never mounted, so cross-UID docker cp cannot collide
 # with browser-owned mode0600 originals already present at its destination.
 chmod 0770 "$task_mounted_results"
 shift 2
 docker_local create --name "$task_browser" --network "$task_front" --read-only --init --group-add "$(id -g)" \
  --cap-drop ALL --security-opt no-new-privileges:true --shm-size=256m \
  --tmpfs /home/node:rw,nosuid,nodev,size=256m,uid=1000,gid=1000,mode=0700 \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m,mode=1777 \
  --mount "type=bind,src=$task_state/current-pki/ca.crt,dst=/trust/ca.crt,readonly" \
  --mount "type=bind,src=$PWD/tests/qualification/browser/$task_driver,dst=/driver/qualification-browser.mjs,readonly" \
  --mount "type=bind,src=$task_mounted_results,dst=/results" \
  -e APP_ENV=development -e NEX_PROFILE=synthetic-qualification \
  -e "NEX_BROWSER_FIXTURE_NO_SANDBOX=${NEX_BROWSER_FIXTURE_NO_SANDBOX:-0}" \
  "$NEX_BROWSER_FIXTURE_IMAGE" "$@" > /dev/null
 task_browser_created=1
 docker_local network connect "$task_issuer" "$task_browser"
 docker_local start "$task_browser" >/dev/null
}
finish_browser() {
 local task_code
 task_code="$(timeout 150s env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock wait "$task_browser")"
 # Logs are deliberately bounded fixture status codes, never Chromium logs.
 docker_local logs "$task_browser"
 # docker cp maps extracted files to the invoking host user by default. This
 # supports CI coordinators with a different UID without weakening file modes.
 docker_local cp "$task_browser:/results/." "$task_browser_results/"
 [[ "$task_code" == 0 ]] || { echo 'Native browser qualification failed; retain evidence and private tmpfs until cleanup.' >&2;return 1; }
 docker_local rm "$task_browser" >/dev/null
 task_browser_created=0
}
start_browser qualification-browser.mjs "$task_output/dom" \
 --base-url=https://workspace.nex.test:9443 --wrong-ca-url=https://untrusted.nex.test:9445 \
 --output=/results/browser-results.json --measure-polling=true
finish_browser

# A genuinely idle, owned synthetic state is required. Legitimate policy/read
# journal entries may grow; zero-effect checks cover all jobs/operations/receipts.
[[ "$(sql "SELECT count(*) FROM jobs WHERE state IN ('queued','running','approval_required')" | tail -n 1)" == 0 ]]
[[ "$(sql "SELECT count(*) FROM users u JOIN delegations d ON d.user_id=u.id AND d.tenant_id=u.tenant_id WHERE u.id='alice' AND u.tenant_id='tenant-a' AND u.subject='alice' AND u.issuer='https://issuer.nex.test:9444' AND d.id='delegation-alice' AND d.revoked_at IS NULL AND d.expires_at>clock_timestamp() AND u.permissions @> ARRAY['document.read','document.export','model.invoke']" | tail -n 1)" == 1 ]]
sql "SELECT format('UPDATE users SET permissions=%L::text[] WHERE id=''alice'' AND tenant_id=''tenant-a''; UPDATE delegations SET revoked_at=%L::timestamptz WHERE id=''delegation-alice'' AND tenant_id=''tenant-a'';',u.permissions::text,d.revoked_at::text) FROM users u JOIN delegations d ON d.user_id=u.id AND d.tenant_id=u.tenant_id WHERE u.id='alice' AND u.tenant_id='tenant-a' AND d.id='delegation-alice'" \
 | tail -n 1 > "$task_private/restore.sql"
[[ -s "$task_private/restore.sql" ]]
authority_hash() {
 sql "SELECT json_build_object('permissions',u.permissions,'revoked_at',d.revoked_at) FROM users u JOIN delegations d ON d.user_id=u.id AND d.tenant_id=u.tenant_id WHERE u.id='alice' AND u.tenant_id='tenant-a' AND d.id='delegation-alice'" | tail -n 1 | sha256sum | cut -d' ' -f1
}
authority_hash > "$task_private/authority-before.sha256"
snapshot_effects() {
 local task_prefix="$1"
 sql "SELECT json_build_object('jobs',COALESCE((SELECT json_agg(row_to_json(j) ORDER BY id) FROM jobs j),'[]'::json),'operations',COALESCE((SELECT json_agg(row_to_json(o) ORDER BY id) FROM execution_operations o),'[]'::json))" \
 | tail -n 1 | python3 -c '
import hashlib,json,sys
x=json.load(sys.stdin);out={}
for kind,rows in x.items():
 out[kind+"_count"]=len(rows);out[kind+"_sha256"]=hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(",",":")).encode()).hexdigest()
print(json.dumps(out,sort_keys=True))
' > "$task_prefix-db.json"
 python3 - "$task_state" "$task_prefix-receipts.json" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]);out={}
for name in ('model-receipts','export-receipts'):
 files={}
 for p in sorted((root/name).rglob('*')):
  if p.name.startswith('.readiness-'):continue
  if p.is_symlink():raise SystemExit('Receipt symlink is not a fixture artifact')
  if p.is_file():files[str(p.relative_to(root/name))]=hashlib.sha256(p.read_bytes()).hexdigest()
 out[name]={'count':len(files),'files_sha256':files}
pathlib.Path(sys.argv[2]).write_text(json.dumps(out,sort_keys=True)+'\n')
PY
}
wait_marker() {
 local task_kind="$1" task_step="$2"
 for ((task_attempt=0;task_attempt<1200;task_attempt++)); do
  if docker_local exec --user 1000 "$task_browser" node --input-type=module -e \
   'import{lstatSync,readFileSync}from"node:fs";try{const p="/results/"+process.argv[1]+"-"+process.argv[2]+".json";const s=lstatSync(p);if(!s.isFile()||s.isSymbolicLink()||s.size>1024)process.exit(2);const x=JSON.parse(readFileSync(p,"utf8"));process.exit(x.stage===process.argv[1]&&x[process.argv[2]]===true?0:2);}catch{process.exit(1);}' \
   "$task_kind" "$task_step" 2>/dev/null;then return;fi
  if [[ "$(docker_local inspect --format '{{.State.Running}}' "$task_browser")" != true ]]; then
   # The last denied marker can race a successful driver exit. Copy only that
   # bounded public marker from the stopped container; no browser profile mount.
   docker_local cp "$task_browser:/results/$task_kind-$task_step.json" "$task_private/stopped-$task_kind-$task_step.json" >/dev/null 2>&1 || return 1
   python3 - "$task_private/stopped-$task_kind-$task_step.json" "$task_kind" "$task_step" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1])
if p.is_symlink() or not p.is_file() or p.stat().st_size>1024:raise SystemExit('Invalid marker')
x=json.loads(p.read_text())
if x.get('stage')!=sys.argv[2] or x.get(sys.argv[3]) is not True:raise SystemExit('Marker mismatch')
PY
   return
  fi
  sleep .1
 done
 echo 'Browser revocation marker timed out.' >&2;return 1
}
start_browser revocation-browser.mjs "$task_output/revocation" \
 --base-url=https://workspace.nex.test:9443 --directory=/results
for task_kind in permission delegation; do
 wait_marker "$task_kind" ready
 task_ack_started="$(python3 -c 'import time;print(time.monotonic_ns())')"
 [[ "$(sql "SELECT count(*) FROM jobs WHERE state IN ('queued','running','approval_required')" | tail -n 1)" == 0 ]]
 if [[ "$task_kind" == delegation ]]; then restore_authority;fi
 snapshot_effects "$task_output/revocation/$task_kind-before"
 task_restore_needed=1
 if [[ "$task_kind" == permission ]]; then
  sql "BEGIN; UPDATE users SET permissions=array_remove(permissions,'document.read') WHERE id='alice' AND tenant_id='tenant-a'; COMMIT;" >/dev/null
 else
  sql "BEGIN; UPDATE delegations SET revoked_at=clock_timestamp() WHERE id='delegation-alice' AND tenant_id='tenant-a'; COMMIT;" >/dev/null
 fi
 # The acknowledgement is emitted strictly after PostgreSQL confirms COMMIT.
 docker_local exec --user 1000 "$task_browser" node --input-type=module -e \
  'import{writeFileSync,renameSync}from"node:fs";const p="/results/"+process.argv[1]+"-committed.json";writeFileSync(p+".tmp",JSON.stringify({stage:process.argv[1],committed:true})+"\n",{mode:0o600,flag:"wx"});renameSync(p+".tmp",p);' "$task_kind"
 python3 - "$task_ack_started" "$task_kind" "$task_output/revocation/$task_kind-ack-timing.json" <<'PY'
import json,pathlib,sys,time
pathlib.Path(sys.argv[3]).write_text(json.dumps({'stage':sys.argv[2],'observed_ready_to_ack_ms':(time.monotonic_ns()-int(sys.argv[1]))/1000000,'driver_ack_budget_ms':20000})+'\n')
PY
 wait_marker "$task_kind" denied
 snapshot_effects "$task_output/revocation/$task_kind-after"
 cmp "$task_output/revocation/$task_kind-before-db.json" "$task_output/revocation/$task_kind-after-db.json"
 cmp "$task_output/revocation/$task_kind-before-receipts.json" "$task_output/revocation/$task_kind-after-receipts.json"
done
finish_browser
restore_authority
authority_hash > "$task_private/authority-after.sha256"
cmp "$task_private/authority-before.sha256" "$task_private/authority-after.sha256"
python3 - "$task_output" <<'PY'
import json,pathlib,sys
root=pathlib.Path(sys.argv[1])
for run in ('dom','revocation'):
 if json.loads((root/run/'browser-results.json').read_text()).get('status')!='passed':raise SystemExit('Incomplete browser assertion result')
report={'schema_version':1,'status':'passed','scope':'source-bound synthetic browser qualification only','same_session_permission_and_delegation_revocation':True,'job_operation_and_receipt_snapshots_unchanged_after_each_denial':True,'exact_prior_authority_restored':True}
(root/'coordinator-results.json').write_text(json.dumps(report,indent=2)+'\n')
PY
echo 'Native browser TLS/DOM, same-session revocation and polling measurements completed.'
