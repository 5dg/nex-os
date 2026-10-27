#!/usr/bin/env python3
"""Exercise the local synthetic workflow; never output tokens or secret values."""
import json,time,uuid,urllib.request,urllib.error,urllib.parse
base='http://127.0.0.1:8080'
def token(subject):
    request=urllib.request.Request('http://127.0.0.1:8081/token',data=urllib.parse.urlencode({'subject':subject}).encode(),method='POST')
    with urllib.request.urlopen(request) as response:return json.load(response)['access_token']
def call(subject,method,path,body=None,expected=200):
    data=None if body is None else json.dumps(body).encode()
    request=urllib.request.Request(base+path,data=data,method=method,headers={'Authorization':'Bearer '+token(subject),'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(request,timeout=10) as response:status=response.status;result=json.load(response)
    except urllib.error.HTTPError as response:status=response.code;result=json.load(response)
    if status!=expected:raise AssertionError((method,path,status,expected,result))
    return result
def wait(job):
    for _ in range(60):
        result=call('alice','GET','/v1/jobs/'+job)
        if result['state'] in ['completed','failed','cancelled']:
            assert result['state']=='completed',result
            return result
        time.sleep(.25)
    raise AssertionError('Job did not complete')
documents=call('alice','GET','/v1/documents');assert any(x['id']=='review-alice' for x in documents)
request={'delegation_id':'delegation-alice','document_id':'review-alice','question':'What access review and export controls apply?','idempotency_key':str(uuid.uuid4())}
job=call('alice','POST','/v1/jobs',request,202)
assert call('alice','POST','/v1/jobs',request)['id']==job['id']
review=wait(job['id']);assert review['provider']=='development' and 'review-alice@v1' in review['citation']
call('bob','GET','/v1/jobs/'+job['id'],expected=403)
approval=call('alice','POST','/v1/jobs/'+job['id']+'/export',{'destination_id':'local-evidence'},201)
call('alice','POST','/v1/approvals/'+approval['id']+'/decision',{'approve':True,'request_digest':approval['request_digest']},403)
pending=call('carol','GET','/v1/approvals');assert any(x['id']==approval['id'] for x in pending)
call('carol','POST','/v1/approvals/'+approval['id']+'/decision',{'approve':True,'request_digest':'modified'},403)
call('carol','POST','/v1/approvals/'+approval['id']+'/decision',{'approve':True,'request_digest':approval['request_digest']})
exported=wait(job['id']);assert exported['export_id']
call('carol','POST','/v1/approvals/'+approval['id']+'/decision',{'approve':True,'request_digest':approval['request_digest']},403)
events=call('alice','GET','/v1/jobs/'+job['id']+'/events')
assert any(x['action']=='approval.decided' for x in events)
assert any(x['action']=='export.authorized' and x['detail'].get('outcome')=='authorization_candidate_pending_commit' for x in events)
assert any(x['action']=='export.completed' and x['detail'].get('provenance',{}).get('result',{}).get('artifact_id')==exported['export_id'] for x in events)
assert all(x['integrity_verified'] for x in events)
print('Synthetic workflow passed: durable review, idempotent creation, cross-tenant denial, independent approval, modified/replayed approval denial, controlled export and Rust authorization evidence.')
