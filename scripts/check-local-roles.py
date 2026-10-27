#!/usr/bin/env python3
"""Check permissions without reading or printing service credentials."""
import subprocess,os
environment=os.environ.copy()
for name in ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH']:environment.pop(name,None)
command=['docker','--host=unix:///var/run/docker.sock','exec','-i','nex-local-postgres-1','psql','-U','nex','-d','nex','-X','-t','-A','-v','ON_ERROR_STOP=1']
def query(sql):
    result=subprocess.run(command,input=sql,text=True,capture_output=True,env=environment)
    if result.returncode:raise AssertionError(result.stderr)
    return result.stdout.strip().splitlines()
control=query("SET ROLE nex_control; SELECT has_column_privilege(current_user,'approvals','approved_at','UPDATE'),has_column_privilege(current_user,'approvals','consumed_at','UPDATE');")
assert control[-1]=='f|f',control
kernel=query("SET ROLE nex_guard; SELECT has_column_privilege(current_user,'approvals','approved_at','UPDATE'),has_column_privilege(current_user,'approvals','consumed_at','UPDATE');")
assert kernel[-1]=='t|t',kernel
denied=subprocess.run(command,input="BEGIN; SET LOCAL ROLE nex_control; UPDATE approvals SET approved_at=now() WHERE false; ROLLBACK;",text=True,capture_output=True,env=environment)
assert denied.returncode!=0 and 'permission denied' in denied.stderr, 'Go runtime role could approve directly'
print('Database ownership passed: Go cannot approve/consume approvals; Rust has the required column permissions.')

# Test the installed roles, including column-level grants retained by PostgreSQL
# across table-level REVOKE. WHERE false avoids modifying any retained rows.
for statement in [
    "UPDATE jobs SET answer='forged' WHERE false",
    "UPDATE jobs SET owner_id='forged' WHERE false",
    "UPDATE jobs SET document_version='forged' WHERE false",
    "UPDATE jobs SET question='forged' WHERE false",
    "UPDATE jobs SET provider='forged' WHERE false",
    "UPDATE jobs SET export_id='forged' WHERE false",
    "UPDATE jobs SET review_operation_id=NULL WHERE false",
    "INSERT INTO jobs(id,answer) SELECT 'forged','forged' WHERE false",
    "INSERT INTO execution_operations(id,tenant_id,job_id,kind,request_digest) SELECT 'forged','forged','forged','export','forged' WHERE false",
    "UPDATE execution_operations SET request_digest='forged' WHERE false",
    "UPDATE execution_operations SET status='completed' WHERE false",
    "UPDATE execution_operations SET result='{}' WHERE false",
    "INSERT INTO execution_manifests(operation_id,version,payload,payload_digest,context_digest,expires_at) SELECT 'forged',2,'{}','forged','forged',now() WHERE false",
    "UPDATE execution_manifests SET payload='{}' WHERE false",
]:
    result=subprocess.run(command,input="BEGIN; SET LOCAL ROLE nex_control; "+statement+"; ROLLBACK;",text=True,capture_output=True,env=environment)
    assert result.returncode!=0 and 'permission denied' in result.stderr, 'Go runtime role may rewrite protected execution context: '+statement
kernel_immutable=subprocess.run(command,input="BEGIN; SET LOCAL ROLE nex_guard; UPDATE execution_manifests SET payload='{}' WHERE false; ROLLBACK;",text=True,capture_output=True,env=environment)
assert kernel_immutable.returncode!=0 and 'permission denied' in kernel_immutable.stderr, 'Kernel role may mutate a sealed manifest'
print('Manifest/result ownership passed: actual Go SQL cannot insert or rewrite protected context, manifests, operation digests or outcomes; sealed manifests are immutable to the kernel runtime.')

query("SET ROLE nex_control; SELECT status,request_digest,result FROM execution_operations WHERE false;")
print("Go protected-outcome reads passed with SELECT-only operation privileges.")
