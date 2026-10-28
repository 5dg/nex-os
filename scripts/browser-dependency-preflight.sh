#!/usr/bin/env bash
# Dependency-only startup before cold compilers; never a DOM qualification gate.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 - "$@" <<'PY'
import argparse, hashlib, json, os, pathlib, re, secrets, shutil, subprocess, tempfile, time

parser=argparse.ArgumentParser(description='Build and check the exact browser fixture; native sandbox default, no automatic fallback.')
parser.add_argument('--output',type=pathlib.Path,required=True)
parser.add_argument('--sandbox-mode',choices=('native','disabled-fixture-only'),default='native')
parser.add_argument('--sandbox-approval')
args=parser.parse_args()
approved_exception='https://github.com/5dg/nex-os/actions/runs/40786456380'
source=pathlib.Path.cwd()
output=args.output
if not output.is_absolute() or output.exists() or output.is_symlink() or output.resolve().is_relative_to(source):
    raise SystemExit('Fresh absolute output outside source required')
os.umask(0o077)
output.mkdir(parents=True,mode=0o700)
env={k:v for k,v in os.environ.items() if k not in ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH')}
docker=['docker','--host=unix:///var/run/docker.sock']
owner='nex-browser-preflight-'+secrets.token_hex(6)
report={'schema_version':1,'scope':'browser dependency startup only; not DOM, application TLS or candidate qualification',
        'status':'failed','stage':'validate explicit sandbox mode','startup_budget_seconds':45,'effective_sandbox':args.sandbox_mode,'network':'none'}
container=None
private=None
image=None
def run(argv,timeout=30,check=True):
    return subprocess.run(argv,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout,check=check)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def write_report():
    (output/'startup-result.json').write_text(json.dumps(report,indent=2)+'\n')
try:
    if args.sandbox_mode=='disabled-fixture-only':
        # Root reviewed the measured native startup failure in this hosted run.
        # This opt-in is a synthetic tool exception, not an application setting.
        if args.sandbox_approval!=approved_exception:raise ValueError('SANDBOX_APPROVAL_REQUIRED')
        report['approval_reference']=approved_exception
    elif args.sandbox_approval is not None:
        raise ValueError('UNEXPECTED_SANDBOX_APPROVAL')
    report['stage']='build fixture'
    fixture=source/'apps/workspace/tests/browser'
    driver=source/'tests/qualification/browser/dependency-preflight.mjs'
    inputs={name:digest(fixture/name) for name in ('Dockerfile','entry.mjs','package.json','package-lock.json')}
    report['fixture_inputs_sha256']=inputs
    report['driver_sha256']=digest(driver)
    # Same pinned image, Dockerfile frontend and normal TLS inputs as the later
    # candidate pipeline. A supplied environment image never bypasses this build.
    build=docker+['build','--no-cache','--build-arg','BUILDKIT_SYNTAX=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e',
        '--secret','id=proxy_ca,src='+os.environ.get('NEX_BUILD_CA','/etc/ssl/certs/ca-certificates.crt'),
        '--iidfile',str(output/'browser-image-id'),'-f',str(fixture/'Dockerfile'),str(source)]
    # Build output is ordinary pinned-tool construction output. Browser runtime
    # diagnostics below are projected to fixed codes, never private Chrome logs.
    subprocess.run(build,env=env,check=True,timeout=900)
    image=(output/'browser-image-id').read_text().strip()
    if not re.fullmatch(r'sha256:[0-9a-f]{64}',image):raise ValueError('INVALID_IMAGE_ID')
    report['image_id']=image
    report['stage']='verify image inputs'
    check=run(docker+['run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--entrypoint','node',image,'--input-type=module','-e',
        'import{readFileSync}from"node:fs";import{createHash}from"node:crypto";for(const n of["entry.mjs","package.json","package-lock.json"])console.log(n+" "+createHash("sha256").update(readFileSync("/fixture/"+n)).digest("hex"));'])
    if dict(line.split() for line in check.stdout.splitlines())!={k:v for k,v in inputs.items() if k!='Dockerfile'}:
        raise ValueError('FIXTURE_INPUT_MISMATCH')
    private=pathlib.Path(tempfile.mkdtemp(prefix='.browser-preflight-private-',dir=output.parent))
    report['stage']='prepare public trust'
    run(['openssl','req','-x509','-newkey','rsa:2048','-sha256','-nodes','-days','1','-subj','/CN=Nex dependency preflight only',
        '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign',
        '-keyout',str(private/'ca.key'),'-out',str(private/'ca.crt')],timeout=20)
    (private/'ca.key').unlink()
    (private/'ca.crt').chmod(0o444)
    report['public_ca_sha256']=digest(private/'ca.crt')
    results=private/'results';results.mkdir(mode=0o770);results.chmod(0o770)
    report['stage']='create isolated fixture'
    created=run(docker+['create','--name',owner,'--label','org.nex.browser-preflight='+owner,'--network','none','--read-only','--init',
        '--group-add',str(os.getgid()),'--cap-drop','ALL','--security-opt','no-new-privileges:true','--shm-size','256m',
        '--tmpfs','/home/node:rw,nosuid,nodev,size=256m,uid=1000,gid=1000,mode=0700',
        '--tmpfs','/tmp:rw,nosuid,nodev,size=64m,mode=1777',
        '--mount',f'type=bind,src={private}/ca.crt,dst=/trust/ca.crt,readonly',
        '--mount',f'type=bind,src={driver},dst=/driver/qualification-browser.mjs,readonly',
        '--mount',f'type=bind,src={results},dst=/results',
        '-e','APP_ENV=development','-e','NEX_PROFILE=synthetic-qualification',
        '-e','NEX_BROWSER_FIXTURE_NO_SANDBOX='+('1' if args.sandbox_mode=='disabled-fixture-only' else '0'),
        '-e','NEX_BROWSER_PREFLIGHT_SANDBOX_MODE='+args.sandbox_mode,
        '-e','NEX_BROWSER_PREFLIGHT_SANDBOX_APPROVAL='+report.get('approval_reference',''),image])
    container=created.stdout.strip()
    if not re.fullmatch(r'[0-9a-f]{64}',container):raise ValueError('INVALID_CONTAINER_ID')
    report['stage']='browser startup'
    started=time.monotonic()
    try:
        run(docker+['start',container],timeout=5)
        waited=run(docker+['wait',container],timeout=max(.1,45-(time.monotonic()-started)))
        report['exit_code']=int(waited.stdout.strip())
    except subprocess.TimeoutExpired:
        report['failure']='STARTUP_TIMEOUT'
        raise
    finally:
        report['startup_elapsed_ms']=round((time.monotonic()-started)*1000)
    logs=run(docker+['logs',container],check=False)
    codes=('BROWSER_SANDBOX_UNAVAILABLE','BROWSER_STARTUP_UNAVAILABLE','BROWSER_ASSERTION_FAILED','BROWSER_FIXTURE_UNAVAILABLE')
    for code in codes:
        if code in logs.stdout+logs.stderr:report['failure']=code;break
    for name in ('browser-engine.json','dependency-driver.json'):
        run(docker+['cp',container+':/results/'+name,str(output/name)],check=False)
    if report['exit_code']!=0:raise ValueError('STARTUP_FAILED')
    engine_path=output/'browser-engine.json';driver_path=output/'dependency-driver.json'
    if engine_path.stat().st_size>1024*1024 or driver_path.stat().st_size>4096:raise ValueError('INVALID_RESULT_SIZE')
    engine=json.loads(engine_path.read_text());driver_result=json.loads(driver_path.read_text())
    if engine.get('effective_sandbox')!=args.sandbox_mode or engine.get('public_ca_sha256')!=report['public_ca_sha256'] or driver_result.get('status')!='passed' or driver_result.get('effective_sandbox')!=args.sandbox_mode or driver_result.get('approval_reference')!=report.get('approval_reference'):
        raise ValueError('INVALID_STARTUP_RESULT')
    report['status']='passed';report['stage']='complete'
except Exception as error:
    report.setdefault('failure',str(error) if str(error) in ('SANDBOX_APPROVAL_REQUIRED','UNEXPECTED_SANDBOX_APPROVAL') else 'DEPENDENCY_PREFLIGHT_FAILED')
finally:
    if container:
        try:
            actual=json.loads(run(docker+['inspect',container]).stdout)[0]
            if actual['Image']!=image or actual['Config']['Labels'].get('org.nex.browser-preflight')!=owner:raise ValueError('Container ownership changed')
            run(docker+['rm','-f',container],timeout=20)
        except Exception:
            report['status']='failed';report['cleanup_failure']='OWNED_CONTAINER_CLEANUP_FAILED'
    if private and not report.get('cleanup_failure'):
        shutil.rmtree(private)
    write_report()
print(json.dumps(report,sort_keys=True))
raise SystemExit(0 if report['status']=='passed' else 1)
PY
