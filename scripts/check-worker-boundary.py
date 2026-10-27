#!/usr/bin/env python3
"""Probe only local container endpoints from the worker's network namespace."""
import json,os,subprocess
environment=os.environ.copy()
for name in ['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH']:environment.pop(name,None)
docker=['docker','--host=unix:///var/run/docker.sock']
def inspect(name,expression):
    return json.loads(subprocess.run(docker+['inspect',name,'--format',expression],env=environment,capture_output=True,text=True,check=True).stdout)
worker='nex-local-worker-1'
networks=inspect(worker,'{{json .NetworkSettings.Networks}}')
assert list(networks)==['nex-local_worker-link'], 'Worker joined a privileged network'
mounts=inspect(worker,'{{json .Mounts}}')
assert [m['Destination'] for m in mounts]==['/run/secrets/worker_key'], 'Unexpected worker credential or data mount'
targets=[['control','control',8080,True]]
for service,port in [('postgres',5432),('model',8082),('executor',8083),('guard',50051),('evidence',8084),('opa',8181)]:
    values=inspect('nex-local-'+service+'-1','{{json .NetworkSettings.Networks}}')
    address=next(iter(values.values()))['IPAddress']
    targets.append([service,address,port,False])
program='''
const net=require('node:net');const assert=require('node:assert/strict');
const targets=JSON.parse(process.argv[1]);
const connect=(host,port)=>new Promise(resolve=>{const socket=net.createConnection({host,port});let done=false;const finish=value=>{if(done)return;done=true;socket.destroy();resolve(value)};socket.setTimeout(1000,()=>finish(false));socket.once('connect',()=>finish(true));socket.once('error',()=>finish(false))});
(async()=>{for(const [name,host,port,expected] of targets){assert.equal(await connect(host,port),expected,'Unexpected worker access to '+name)}console.log('Worker boundary passed: broker reachable; database, model, executor, Guard, evidence and policy endpoints inaccessible; only worker identity mounted.')})().catch(error=>{console.error(error.message);process.exit(1)});
'''
subprocess.run(docker+['run','--rm','--network','container:'+worker,'node:24.19.0-bookworm-slim@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df','node','-e',program,json.dumps(targets)],env=environment,check=True)
