#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v aws >/dev/null || { echo 'BLOCKED: AWS CLI v2 is required.' >&2; exit 2; }
: "${NEX_GOV_REGION:?Set the explicitly approved GovCloud region}"
: "${NEX_APPROVED_ACCOUNT_ID:?Set the explicitly approved AWS account ID}"
: "${NEX_BEDROCK_MODEL_ID:?Set the exact approved regional foundation-model ID}"
case "$NEX_GOV_REGION" in us-gov-west-1|us-gov-east-1) ;; *) echo 'DENIED: GovCloud region required.' >&2; exit 2;; esac
[[ "$NEX_APPROVED_ACCOUNT_ID" =~ ^[0-9]{12}$ ]] || { echo 'DENIED: approved account ID must be 12 digits.' >&2; exit 2; }
[[ "$NEX_BEDROCK_MODEL_ID" =~ ^[A-Za-z0-9.:-]+$ ]] || { echo 'DENIED: exact model ID required; profiles and arbitrary ARNs are outside this preflight.' >&2; exit 2; }
export AWS_PAGER=""
task_report="${NEX_PREFLIGHT_REPORT:-.local/govcloud-preflight.json}"
mkdir -p "$(dirname "$task_report")"
if [[ -e "$task_report" || -L "$task_report" ]]; then
  echo 'DENIED: preflight report already exists; select a fresh report path.' >&2
  exit 2
fi
task_dir="$(mktemp -d)"; trap 'rm -rf "$task_dir"' EXIT
# Use the configured SDK/CLI identity; do not replace credentials or initiate login.
aws sts get-caller-identity --region "$NEX_GOV_REGION" --output json > "$task_dir/identity.json"
python3 - "$task_dir/identity.json" "$NEX_APPROVED_ACCOUNT_ID" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]))
account = sys.argv[2]
arn = x.get('Arn', '').split(':', 5)
if (x.get('Account') != account or len(arn) != 6 or
    arn[0] != 'arn' or arn[1] != 'aws-us-gov' or arn[4] != account):
    raise SystemExit('DENIED: caller identity does not match the approved GovCloud account')
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
fd = os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as f:json.dump(result,f,indent=2)
print('Inventory saved. Model invocation, entitlements, quotas, residency and authorization-scope review still required.')
PY
