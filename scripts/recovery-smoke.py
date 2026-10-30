#!/usr/bin/env python3
"""Check owner-scoped recovery against a real local synthetic workflow.

Only this script's newly created job is faulted to simulate a lost completion
acknowledgement. Its manifest, result, receipts and signed history are retained.
"""
import hashlib,json,os,pathlib,re,subprocess,time,urllib.error,urllib.parse,urllib.request,uuid
root=pathlib.Path(__file__).resolve().parent.parent
base='http://127.0.0.1:8080'
def token(subject):
    request=urllib.request.Request('http://127.0.0.1:8081/token',data=urllib.parse.urlencode({'subject':subject}).encode(),method='POST')
    with urllib.request.urlopen(request,timeout=10) as response:return json.load(response)['access_token']
def call(subject,method,path,body=None,expected=200):
    request=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),method=method,headers={'Authorization':'Bearer '+token(subject),'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(request,timeout=10) as response:status=response.status;result=json.load(response)
    except urllib.error.HTTPError as response:status=response.code;result=json.load(response)
    assert status==expected,(method,path,status,expected,result)
    return result
environment=os.environ.copy()
for name in ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH']:environment.pop(name,None)
command=['docker','--host=unix:///var/run/docker.sock','exec','-i','nex-local-postgres-1','psql','-U','nex','-d','nex','-X','-t','-A','-v','ON_ERROR_STOP=1']
def sql(statement):
    result=subprocess.run(command,input=statement,text=True,capture_output=True,env=environment,check=True)
    return result.stdout.strip()
created=call('alice','POST','/v1/jobs',{'delegation_id':'delegation-alice','document_id':'review-alice','question':'Summarize the synthetic access review requirements.','idempotency_key':str(uuid.uuid4())},202)
job=created['id'];assert re.fullmatch(r'[A-Za-z0-9_-]{8,100}',job)
for _ in range(80):
    review=call('alice','GET','/v1/jobs/'+job)
    assert review['state']!='failed',review
    if review['state']=='completed':break
    time.sleep(.25)
else:raise AssertionError('Review did not complete')
operation=sql("SELECT operation_id FROM jobs WHERE id='"+job+"';");assert re.fullmatch(r'[A-Za-z0-9_-]{8,100}',operation)
receipt=root/'.local/model-receipts'/(operation+'.state')
original_receipt=hashlib.sha256(receipt.read_bytes()).hexdigest()
original_manifest=sql("SELECT md5(to_jsonb(m)::text) FROM execution_manifests m WHERE operation_id='"+operation+"';")
original_completion_events=sql("SELECT count(*) FROM audit_events WHERE job_id='"+job+"' AND action='model.completed';")
assert original_completion_events=='1'
# Simulate control losing the receiver acknowledgement after Rust completion.
# Protected result/manifest/receipt rows are unchanged.
sql("UPDATE jobs SET state='failed',error_code='model_OUTCOME_UNAVAILABLE_OR_UNKNOWN' WHERE id='"+job+"' AND state='completed' AND phase='review';")
call('bob','POST','/v1/jobs/'+job+'/reconcile',expected=403)
call('bob','POST','/v1/jobs/'+job+'/retry',expected=403)
call('alice','POST','/v1/jobs/'+job+'/retry',expected=409)
call('alice','POST','/v1/jobs/'+job+'/reconcile',{'state':'completed','result':'forged'},400)
recovered=call('alice','POST','/v1/jobs/'+job+'/reconcile')
assert recovered['state']=='completed',recovered
current=call('alice','GET','/v1/jobs/'+job)
assert current['answer']==review['answer'] and current['state']=='completed' and not current.get('error_code')
assert hashlib.sha256(receipt.read_bytes()).hexdigest()==original_receipt,'Recovery rewrote the receiver receipt'
assert sql("SELECT md5(to_jsonb(m)::text) FROM execution_manifests m WHERE operation_id='"+operation+"';")==original_manifest,'Recovery rewrote the manifest'
assert sql("SELECT count(*) FROM audit_events WHERE job_id='"+job+"' AND action='model.completed';")==original_completion_events,'Recovery repeated completion/effects'
call('alice','POST','/v1/jobs/'+job+'/reconcile',expected=409)
events=call('alice','GET','/v1/jobs/'+job+'/events')
assert all(event['integrity_verified'] for event in events),'Invalid recovery evidence'
assert any(event['action']=='job.reconciliation_attempt' for event in events)
print('Recovery workflow passed: owner/current authority, cross-tenant rejection, no client-supplied outcome, unknown retry denial, durable-result reconciliation and unchanged manifest/receipt/completion count.')
