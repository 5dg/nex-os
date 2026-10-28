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
    def test_only_compose_build_disables_bake_and_preserves_public_ca_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root/'scripts').mkdir(); (root/'bin').mkdir(); (root/'tools').mkdir()
            shutil.copy2(ROOT/'scripts/local.sh', root/'scripts/local.sh')
            def executable(path, contents):
                path.write_text(contents); path.chmod(0o755)
            for path in (root/'scripts/build-local.sh',root/'bin/evidence',root/'tools/python3',root/'tools/curl'):
                executable(path, '#!/bin/sh\nexit 0\n')
            executable(root/'tools/docker', '#!'+sys.executable+'\n'+'''import json,os,sys
with open(os.environ['NEX_TEST_DOCKER_CAPTURE'],'a') as stream:
 stream.write(json.dumps({'args':sys.argv[1:],'bake':os.environ.get('COMPOSE_BAKE'),'ca':os.environ.get('NEX_BUILD_CA')})+'\\n')
''')
            log = root/'docker.jsonl'; ca = root/'public-ca.crt'; ca.write_text('public fixture CA')
            environment = {**os.environ, 'PATH':str(root/'tools')+os.pathsep+os.environ['PATH'],
                           'COMPOSE_BAKE':'true','NEX_BUILD_CA':str(ca),'BUILDX_CONFIG':str(root/'buildx'),
                           'NEX_TEST_DOCKER_CAPTURE':str(log)}
            result = subprocess.run(['bash', str(root/'scripts/local.sh'),'up'],env=environment,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            builds = [call for call in calls if call['args'][-1]=='build']
            self.assertEqual(len(builds),1)
            self.assertEqual(builds[0]['bake'],'false')
            self.assertTrue(all(call['ca']==str(ca) for call in calls))
            self.assertTrue(all(call['bake']=='true' for call in calls if call not in builds))
            self.assertTrue(all('--host=unix:///var/run/docker.sock' in call['args'] for call in calls))
            self.assertFalse(any('--allow=' in argument or '--privileged' in argument for call in calls for argument in call['args']))


if __name__=='__main__': unittest.main()
