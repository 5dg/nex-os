#!/usr/bin/env python3
"""Restore synthetic local data to a disposable DB and verify a pinned journal.

This does not qualify production backup encryption, custody, RPO or RTO.
"""
import hashlib,json,os,pathlib,shutil,subprocess,tempfile,uuid
root=pathlib.Path(__file__).resolve().parent.parent
environment=os.environ.copy()
for name in ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH']:environment.pop(name,None)
docker=['docker','--host=unix:///var/run/docker.sock']
compose=docker+['compose','-f',str(root/'deploy/local/compose.yaml')]
database='restore_'+uuid.uuid4().hex
def sql(db,statement):
    p=subprocess.run(docker+['exec','-i','nex-local-postgres-1','psql','-U','nex','-d',db,'-X','-t','-A','-v','ON_ERROR_STOP=1'],input=statement.encode(),capture_output=True,env=environment,check=True)
    return p.stdout.strip()
def fingerprint(db):
    values={}
    for name in ['tenants','users','delegations','resources','document_bodies','model_routes','export_destinations','jobs','approvals','execution_operations','execution_manifests','audit_events','schema_migrations']:
        rows=sql(db,'SELECT to_jsonb(t)::text FROM '+name+' t ORDER BY to_jsonb(t)::text;')
        values[name]=hashlib.sha256(rows).hexdigest()
    return values
created=False
try:
    # Only pause services owned by this Compose project. Journal writes finish
    # before the control-plane shutdown completes; data files remain retained.
    subprocess.run(compose+['stop','worker','control'],env=environment,check=True,capture_output=True)
    subprocess.run(compose+['stop','model','executor','guard','evidence'],env=environment,check=True,capture_output=True)
    original=fingerprint('nex')
    with tempfile.TemporaryDirectory(prefix='nex-restore-') as directory:
        directory=pathlib.Path(directory)
        checkpoint=subprocess.run([str(root/'bin/evidence'),'verify',str(root/'.local/evidence'),str(root/'.local/evidence-public')],capture_output=True,check=True).stdout
        (directory/'checkpoint.json').write_bytes(checkpoint)
        shutil.copytree(root/'.local/evidence',directory/'journal')
        # Receipts are authoritative local artifacts and uncertainty fences. Copy
        # both stores while all writers are stopped; never reset pending files.
        def file_hashes(path):
            return {str(item.relative_to(path)):hashlib.sha256(item.read_bytes()).hexdigest() for item in path.rglob('*') if item.is_file()}
        receipt_copies=[]
        for name in ['model-receipts','export-receipts']:
            source=root/'.local'/name;target=directory/name
            expected=file_hashes(source);shutil.copytree(source,target)
            assert file_hashes(target)==expected,'Restored receipt bytes differ: '+name
            receipt_copies.append(str(target))
        subprocess.run(['go','run','./scripts/receipt-restore-check',*receipt_copies],cwd=root,env=environment,check=True)
        policy=(root/'policies/guard.rego').read_bytes()
        (directory/'guard.rego').write_bytes(policy)
        assert hashlib.sha256((directory/'guard.rego').read_bytes()).digest()==hashlib.sha256(policy).digest(), 'Restored policy source differs'
        with (directory/'snapshot.dump').open('wb') as output:
            subprocess.run(docker+['exec','nex-local-postgres-1','pg_dump','-U','nex','-d','nex','-n','public','-Fc'],stdout=output,stderr=subprocess.PIPE,env=environment,check=True)
        sql('postgres','CREATE DATABASE '+database+';');created=True
        with (directory/'snapshot.dump').open('rb') as source:
            subprocess.run(docker+['exec','-i','nex-local-postgres-1','pg_restore','--clean','--if-exists','-U','nex','-d',database],stdin=source,capture_output=True,env=environment,check=True)
        assert fingerprint(database)==original,'Restored application/policy/audit state differs'
        subprocess.run([str(root/'bin/evidence'),'verify',str(directory/'journal'),str(root/'.local/evidence-public'),str(directory/'checkpoint.json')],capture_output=True,check=True)
    print('Restore passed: application/security/manifest/result/audit rows match; copied journal matches its pinned checkpoint; copied receipt bytes and completed/uncertain lookup semantics match.')
finally:
    if created:sql('postgres','DROP DATABASE '+database+';')
    subprocess.run(compose+['up','-d','--no-build','--pull','never','evidence','guard','model','executor','control','worker'],env=environment,check=True,capture_output=True)
