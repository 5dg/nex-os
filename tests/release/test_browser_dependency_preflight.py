"""Offline process-boundary checks; never invokes Docker or starts Chromium."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
STUB = r'''#!/usr/bin/env python3
import hashlib,json,os,pathlib,sys
root=pathlib.Path(os.environ['PREFLIGHT_TEST_ROOT']); args=sys.argv[1:]
assert all(name not in os.environ for name in ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'))
with (root/'calls.jsonl').open('a') as log:log.write(json.dumps([pathlib.Path(sys.argv[0]).name,*args])+'\n')
mode=os.environ.get('PREFLIGHT_TEST_MODE','pass')
if pathlib.Path(sys.argv[0]).name=='openssl':
 pathlib.Path(args[args.index('-keyout')+1]).write_text('test-private-key')
 pathlib.Path(args[args.index('-out')+1]).write_text('test-public-ca')
 sys.exit(0)
args=args[1:] # exact local Docker socket option
action=args[0]; image='sha256:'+'a'*64; cid='b'*64
if action=='build':pathlib.Path(args[args.index('--iidfile')+1]).write_text('malformed' if mode=='bad-image' else image)
elif action=='run':
 source=pathlib.Path(os.environ['PREFLIGHT_SOURCE'])/'apps/workspace/tests/browser'
 for name in ('entry.mjs','package.json','package-lock.json'):print(name+' '+hashlib.sha256((source/name).read_bytes()).hexdigest())
elif action=='create':
 mounts=[args[i+1] for i,x in enumerate(args) if x=='--mount']
 ca=next(x.split('src=')[1].split(',dst=')[0] for x in mounts if 'dst=/trust/ca.crt' in x)
 assert not pathlib.Path(ca).with_name('ca.key').exists()
 state={'Image':image,'Config':{'Labels':{'org.nex.browser-preflight':args[args.index('--label')+1].split('=',1)[1]}},'public_ca_sha256':hashlib.sha256(pathlib.Path(ca).read_bytes()).hexdigest()}
 (root/'state.json').write_text(json.dumps(state));print(cid)
elif action=='wait':print('1' if mode=='sandbox' else '0')
elif action=='logs':print('BROWSER_SANDBOX_UNAVAILABLE' if mode=='sandbox' else '')
elif action=='cp':
 if mode=='sandbox':sys.exit(1)
 state=json.loads((root/'state.json').read_text())
 value={'effective_sandbox':'native','public_ca_sha256':state['public_ca_sha256']} if 'browser-engine.json' in args[1] else {'status':'passed'}
 if mode=='bad-engine' and 'effective_sandbox' in value:value['effective_sandbox']='disabled-fixture-only'
 pathlib.Path(args[2]).write_text(json.dumps(value))
elif action=='inspect':
 state=json.loads((root/'state.json').read_text())
 if mode=='foreign-owner':state['Config']['Labels']['org.nex.browser-preflight']='different-owner'
 print(json.dumps([state]))
elif action not in ('start','rm'):sys.exit(2)
'''


class DependencyPreflightTests(unittest.TestCase):
    def execute(self, mode):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for command in ('docker', 'openssl'):
                path = root / command
                path.write_text(STUB)
                path.chmod(0o755)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                       PREFLIGHT_TEST_ROOT=str(root), PREFLIGHT_SOURCE=str(ROOT),
                       PREFLIGHT_TEST_MODE=mode, NEX_BROWSER_FIXTURE_NO_SANDBOX='1',
                       DOCKER_HOST='tcp://forbidden.example:2375')
            output = root / 'public-output'
            command = ['bash', str(ROOT / 'scripts/browser-dependency-preflight.sh'), '--output', str(output)]
            if mode == 'timeout':
                # Inject the process-boundary timeout rather than sleeping45s;
                # execute the unchanged coordinator body and all other stubbed
                # child commands normally. No production test hook is added.
                launcher = '''import pathlib,subprocess,sys,unittest.mock
script=pathlib.Path(sys.argv[1]); destination=sys.argv[2]
body=script.read_text().split("<<'PY'\\n",1)[1].rsplit('\\nPY',1)[0]
actual=subprocess.run
def bounded(command,*args,_actual=actual,**kwargs):
 if command[0]=='docker' and command[2]=='wait':raise subprocess.TimeoutExpired(command,kwargs['timeout'])
 return _actual(command,*args,**kwargs)
sys.argv=['-', '--output',destination]
with unittest.mock.patch('subprocess.run',side_effect=bounded):exec(compile(body,str(script),'exec'))
'''
                command = [os.sys.executable, '-c', launcher, str(ROOT / 'scripts/browser-dependency-preflight.sh'), str(output)]
            result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=20)
            report = json.loads((output / 'startup-result.json').read_text())
            calls = [json.loads(line) for line in (root / 'calls.jsonl').read_text().splitlines()]
            self.assertEqual(bool(list(root.glob('.browser-preflight-private-*'))), mode == 'foreign-owner')
            return result, report, calls

    def test_success_uses_one_exact_image_native_sandbox_and_no_network(self):
        result, report, calls = self.execute('pass')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report['status'], 'passed')
        self.assertIn('not DOM', report['scope'])
        docker = [call for call in calls if call[0] == 'docker']
        self.assertTrue(all(call[1] == '--host=unix:///var/run/docker.sock' for call in docker))
        create = next(call for call in docker if call[2] == 'create')
        self.assertEqual(create[create.index('--network') + 1], 'none')
        self.assertIn('--read-only', create)
        self.assertIn('no-new-privileges:true', create)
        self.assertIn('NEX_BROWSER_FIXTURE_NO_SANDBOX=0', create)
        self.assertNotIn('NEX_BROWSER_FIXTURE_NO_SANDBOX=1', create)
        for action in ('build', 'create', 'start', 'rm'):
            self.assertEqual(sum(call[2] == action for call in docker), 1)

    def test_sandbox_failure_is_retained_without_retry_or_fallback(self):
        result, report, calls = self.execute('sandbox')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(report['failure'], 'BROWSER_SANDBOX_UNAVAILABLE')
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(sum(call[0] == 'docker' and call[2] == 'start' for call in calls), 1)
        self.assertEqual(sum(call[0] == 'docker' and call[2] == 'rm' for call in calls), 1)

    def test_malformed_image_id_never_launches(self):
        result, report, calls = self.execute('bad-image')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(report['status'], 'failed')
        self.assertFalse(any(call[0] == 'docker' and call[2] == 'create' for call in calls))

    def test_weakened_engine_result_cannot_pass(self):
        result, report, _ = self.execute('bad-engine')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(report['status'], 'failed')

    def test_startup_timeout_fails_and_removes_owned_container(self):
        result, report, calls = self.execute('timeout')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(report['failure'], 'STARTUP_TIMEOUT')
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(sum(call[0] == 'docker' and call[2] == 'rm' for call in calls), 1)

    def test_cleanup_identity_mismatch_never_removes_foreign_container(self):
        result, report, calls = self.execute('foreign-owner')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(report['cleanup_failure'], 'OWNED_CONTAINER_CLEANUP_FAILED')
        self.assertFalse(any(call[0] == 'docker' and call[2] == 'rm' for call in calls))


if __name__ == '__main__':
    unittest.main()
