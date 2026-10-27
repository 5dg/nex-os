#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v aws >/dev/null || { echo 'BLOCKED: AWS CLI v2 is required.' >&2; exit 2; }
: "${NEX_GOV_REGION:?Set the explicitly approved GovCloud region}"
: "${NEX_BEDROCK_MODEL_ID:?Set the exact approved regional foundation-model ID}"
case "$NEX_GOV_REGION" in us-gov-west-1|us-gov-east-1) ;; *) echo 'DENIED: GovCloud region required.' >&2; exit 2;; esac
[[ "$NEX_BEDROCK_MODEL_ID" =~ ^[A-Za-z0-9.:-]+$ ]] || { echo 'DENIED: exact model ID required; profiles and arbitrary ARNs are outside this preflight.' >&2; exit 2; }
export AWS_PAGER=""
task_report="${NEX_PREFLIGHT_REPORT:-.local/govcloud-preflight.json}"
mkdir -p "$(dirname "$task_report")"
task_dir="$(mktemp -d)"; trap 'rm -rf "$task_dir"' EXIT
# Use the configured SDK/CLI identity; do not replace credentials or initiate login.
aws sts get-caller-identity --region "$NEX_GOV_REGION" --output json > "$task_dir/identity.json"
python3 - "$task_dir/identity.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]))
if not x['Arn'].startswith('arn:aws-us-gov:'):raise SystemExit('DENIED: identity is outside aws-us-gov')
PY
aws bedrock get-foundation-model --region "$NEX_GOV_REGION" --model-identifier "$NEX_BEDROCK_MODEL_ID" --output json > "$task_dir/model.json"
aws ec2 describe-vpc-endpoint-services --region "$NEX_GOV_REGION" --output json > "$task_dir/endpoints.json"
python3 - "$task_dir" "$task_report" <<'PY'
import json,os,sys,datetime
directory,report=sys.argv[1:]
identity=json.load(open(directory+'/identity.json'))
model=json.load(open(directory+'/model.json'))
endpoints=json.load(open(directory+'/endpoints.json'))
result={'observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'partition':'aws-us-gov','region':os.environ['NEX_GOV_REGION'],'account_id':identity['Account'],'model_details':model,'endpoint_services':endpoints.get('ServiceNames',[]),'live_invocation':'UNRUN','authorization_scope_review':'UNVERIFIED','quotas':'UNVERIFIED','ready':False}
with open(report,'w') as f:json.dump(result,f,indent=2)
print('Inventory saved. Model invocation, entitlements, quotas, residency and authorization-scope review still required.')
PY
