#!/usr/bin/env python3
"""Bounded synthetic runtime checks for one explicitly diagnostic image."""
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import tempfile
import time

DOCKER=['docker','--host=unix:///var/run/docker.sock']


def docker(*args, check=True, timeout=20):
    # Avoid collecting arbitrary daemon/tool output in memory; cap the freshly
    # created temporary file at 2 MiB in the child process.
    maximum = 2 * 1024**2
    def limit(): resource.setrlimit(resource.RLIMIT_FSIZE,(maximum,maximum))
    with tempfile.TemporaryFile(dir=os.environ.get('RUNNER_TEMP')) as out:
        result = subprocess.run([*DOCKER,*args], stdout=out, stderr=subprocess.STDOUT,
                                timeout=timeout, preexec_fn=limit)
        out.seek(0)
        data=out.read(maximum+1)
    if len(data)>=maximum:raise RuntimeError('Docker command output exceeded limit')
    result.stdout=data.decode('utf-8',errors='replace')
    if check and result.returncode:raise subprocess.CalledProcessError(result.returncode,result.args)
    return result


def names(role, run, attempt):
    root='nex-image-probe-'+run+'-'+attempt+'-'+role
    return [root,root+'-1000'] if role=='guard' else [root]


def reconcile(name, image, owner, role):
    """Stop only a same-name container whose immutable identity and labels match."""
    listing=docker('container','ls','--all','--quiet','--no-trunc','--filter','name=^/'+name+'$',check=False)
    if listing.returncode: raise RuntimeError('cannot inspect owned container list')
    ids=listing.stdout.split()
    if not ids:return
    if len(ids)!=1 or not re.fullmatch(r'[0-9a-f]{64}',ids[0]):raise RuntimeError('ambiguous owned container identity')
    obj=json.loads(docker('inspect',ids[0]).stdout)
    if len(obj)!=1:raise RuntimeError('unexpected owned container inspection')
    data=obj[0];labels=data['Config'].get('Labels') or {}
    if (data['Id']!=ids[0] or data['Name']!='/'+name or data['Image']!=image or
        labels.get('org.nex.diagnostic.owner')!=owner or labels.get('org.nex.diagnostic.role')!=role):
        raise RuntimeError('foreign container or changed diagnostic identity')
    if data['State']['Running']:
        docker('stop','--time','10',ids[0],timeout=20)
    listing=docker('container','ls','--all','--quiet','--no-trunc','--filter','name=^/'+name+'$',check=False)
    if listing.returncode or listing.stdout.strip():raise RuntimeError('owned container absence not confirmed')


def wait_for(name, predicate, seconds=45):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        state=docker('inspect','--format','{{.State.Running}}',name,check=False)
        if state.returncode or state.stdout.strip()!='true':
            raise RuntimeError('diagnostic container exited before readiness')
        if predicate(): return
        time.sleep(1)
    raise TimeoutError('diagnostic readiness timed out')


def smoke(role, image, owner, uid=None):
    run=os.environ['GITHUB_RUN_ID'];attempt=os.environ['GITHUB_RUN_ATTEMPT']
    if not re.fullmatch(r'[0-9]+',run) or not re.fullmatch(r'[0-9]+',attempt):raise ValueError('invalid run id')
    if not re.fullmatch(r'[0-9a-f]{32}',owner):raise ValueError('invalid diagnostic owner')
    name=names(role,run,attempt)[-1] if uid else names(role,run,attempt)[0]
    with tempfile.TemporaryDirectory(prefix='nex-image-diagnostic-') as temp:
        args=['run','--detach','--rm','--network','none','--memory','1g','--cpus','2','--name',name,
              '--label','org.nex.diagnostic.owner='+owner,'--label','org.nex.diagnostic.role='+role]
        if role=='postgres':
            args+=['--tmpfs','/var/lib/postgresql/data:rw,size=512m','--env','POSTGRES_PASSWORD=synthetic-only-password']
        elif role=='workspace':
            args+=['--env','APP_ENV=development']
        elif role=='guard':
            key=Path(temp)/'guard-key';key.write_bytes(b'0'*32);key.chmod(0o444)
            if uid: args+=['--user',uid+':'+uid]
            args+=['--mount','type=bind,src='+str(key)+',dst=/guard-key,readonly',
                   '--env','APP_ENV=development','--env','GUARD_KEY_FILE=/guard-key',
                   '--env','OPA_URL=http://127.0.0.1:8181']
        else:raise ValueError('invalid role')
        try:
            docker(*args,image,timeout=40)
            if role=='postgres':
                wait_for(name,lambda:docker('exec',name,'pg_isready','-U','postgres',check=False).returncode==0)
                docker('exec',name,'psql','-U','postgres','-v','ON_ERROR_STOP=1','-c',"SELECT xmlparse(document '<x>ok</x>');")
            elif role=='guard':
                wait_for(name,lambda:'Nex.Guard started; profile=development; synthetic data only' in docker('logs','--tail','50',name,check=False).stdout)
            else:
                command="fetch('http://127.0.0.1:3000/').then(r=>{if(r.status>=500)process.exit(1)}).catch(()=>process.exit(1))"
                wait_for(name,lambda:docker('exec',name,'node','-e',command,check=False).returncode==0)
            print(role + (('/uid-'+uid) if uid else '') + ' synthetic startup passed')
        finally:
            # Also executes when the Docker client timed out after daemon create.
            reconcile(name,image,owner,role)

if __name__=='__main__':
    try:
        if len(sys.argv)!=4 or not re.fullmatch(r'sha256:[0-9a-f]{64}',sys.argv[2]):raise ValueError('immutable image ID required')
        role,image,owner=sys.argv[1:]
        smoke(role,image,owner)
        if role=='guard':smoke(role,image,owner,'1000')
    except (ValueError,RuntimeError,OSError,TimeoutError,subprocess.SubprocessError) as error:
        print('synthetic runtime diagnostic incomplete: '+str(error),file=sys.stderr)
        sys.exit(1)
