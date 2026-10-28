"""Execute the actual local launcher with offline command fixtures; no daemon."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class LocalBuildTransportTests(unittest.TestCase):
    def run_launcher(self, action, fail_pull=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root/'scripts').mkdir(); (root/'bin').mkdir(); (root/'tools').mkdir()
            shutil.copy2(ROOT/'scripts/local.sh', root/'scripts/local.sh')
            (root/'deploy/local').mkdir(parents=True)
            shutil.copy2(ROOT/'deploy/local/compose.yaml', root/'deploy/local/compose.yaml')
            def executable(path, contents):
                path.write_text(contents); path.chmod(0o755)
            for path in (root/'scripts/build-local.sh',root/'bin/evidence',root/'tools/python3',root/'tools/curl'):
                executable(path, '#!/bin/sh\nexit 0\n')
            executable(root/'tools/docker', '#!'+sys.executable+'\n'+'''import json,os,re,sys
from pathlib import Path
args=sys.argv[1:]
command=args[args.index('-f')+2:]
record={'args':args,'command':command,'bake':os.environ.get('COMPOSE_BAKE'),'ca':os.environ.get('NEX_BUILD_CA')}
if command==['pull','opa']:
 manifest=Path(args[args.index('-f')+1]).read_text()
 record['image']=re.search(r'^  opa:\\n    image: (.+)$',manifest,re.M).group(1)
with open(os.environ['NEX_TEST_DOCKER_CAPTURE'],'a') as stream:
 stream.write(json.dumps(record)+'\\n')
if command==['pull','opa'] and os.environ.get('NEX_TEST_FAIL_PULL')=='1':
 sys.exit(42)
''')
            log = root/'docker.jsonl'; ca = root/'public-ca.crt'; ca.write_text('public fixture CA')
            environment = {**os.environ, 'PATH':str(root/'tools')+os.pathsep+os.environ['PATH'],
                           'COMPOSE_BAKE':'true','NEX_BUILD_CA':str(ca),'BUILDX_CONFIG':str(root/'buildx'),
                           'NEX_TEST_DOCKER_CAPTURE':str(log),'NEX_TEST_FAIL_PULL':'1' if fail_pull else '0'}
            result = subprocess.run(['bash', str(root/'scripts/local.sh'),action],env=environment,capture_output=True,text=True)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertTrue(all(call['ca']==str(ca) for call in calls))
            self.assertTrue(all('--host=unix:///var/run/docker.sock' in call['args'] for call in calls))
            self.assertFalse(any('--allow=' in argument or '--privileged' in argument for call in calls for argument in call['args']))
            return result, calls

    def test_only_compose_build_disables_bake_and_preserves_public_ca_input(self):
        result, calls = self.run_launcher('up')
        self.assertEqual(result.returncode,0,result.stderr)
        builds = [call for call in calls if call['command']==['build']]
        self.assertEqual(len(builds),1)
        self.assertEqual(builds[0]['bake'],'false')
        self.assertTrue(all(call['bake']=='true' for call in calls if call not in builds))

    def test_up_prefetches_only_pinned_opa_before_starting_services(self):
        result, calls = self.run_launcher('up')
        self.assertEqual(result.returncode,0,result.stderr)
        commands = [call['command'] for call in calls]
        pulls = [call for call in calls if call['command'][0]=='pull']
        self.assertEqual(len(pulls),1)
        self.assertEqual(pulls[0]['command'],['pull','opa'])
        self.assertEqual(pulls[0]['image'],'openpolicyagent/opa@sha256:02d31f4e34dcae04d87b542796aa0d089e42039fe6bbc5601587be44fb218963')
        self.assertLess(commands.index(['pull','opa']),next(i for i, command in enumerate(commands) if command[0]=='up'))
        self.assertIn(['up','-d','--no-build','--pull','never','issuer','opa','guard','control','model','executor','evidence','worker','workspace'],commands)

    def test_start_does_not_build_or_prefetch_images(self):
        result, calls = self.run_launcher('start')
        self.assertEqual(result.returncode,0,result.stderr)
        commands = [call['command'] for call in calls]
        self.assertFalse(any(command[0] in ('pull','build') for command in commands))
        self.assertIn(['up','-d','--no-build','--pull','never','issuer','opa','guard','control','model','executor','evidence','worker','workspace'],commands)

    def test_failed_pinned_pull_aborts_without_fallback_or_service_start(self):
        result, calls = self.run_launcher('up',fail_pull=True)
        self.assertEqual(result.returncode,42,result.stderr)
        self.assertEqual([call['command'] for call in calls],[['build'],['pull','opa']])


if __name__=='__main__': unittest.main()
