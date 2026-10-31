"""Foundation wiring tests; image reconstruction has its own byte-level tests."""
import importlib.util
import hashlib
import json
import contextlib
import io
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('nex_foundation_opa', SCRIPTS / 'foundation-opa.py')
foundation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(foundation)


class FoundationOPATests(unittest.TestCase):
    def test_pinned_opa_sum_patch_reconstructs_exact_upstream_and_overlay(self):
        overlay = SCRIPTS.parent / 'deploy/qualification/opa'
        patch_path = overlay / 'opa-v4.patch'
        expected = (overlay / 'go.sum').read_bytes()
        integrity = (SCRIPTS / 'apply-opa-overlay.sh').read_text()
        for path in (patch_path, overlay / 'go.sum'):
            self.assertIn(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name, integrity)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'go.sum').write_bytes(expected)
            command = ['git', '-C', str(root), 'apply', '--include=go.sum']
            subprocess.run(command + ['--reverse', str(patch_path)], check=True)
            self.assertEqual(hashlib.sha256((root / 'go.sum').read_bytes()).hexdigest(),
                             '77629297a1b141d6ea9ec6d99b3af212e5781b9a0feb45bdefaba0c167d91499')
            subprocess.run(command + [str(patch_path)], check=True)
            self.assertEqual((root / 'go.sum').read_bytes(), expected)

    def test_compiler_identity_rejects_wrong_digest_repository_or_platform(self):
        valid = {'Id': 'sha256:' + 'a' * 64, 'RepoDigests': [foundation.GO_IMAGE],
                 'Os': 'linux', 'Architecture': 'amd64'}
        for change in ({'RepoDigests': ['golang@sha256:' + 'b' * 64]},
                       {'RepoDigests': ['other@' + foundation.GO_IMAGE.split('@')[1]]},
                       {'RepoDigests': []}, {'Os': 'windows'}, {'Architecture': 'arm64'}):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                ca = root / 'ca'; ca.write_text('public trust')
                compiler = {**valid, **change}
                def run(args, **kwargs):
                    output = json.dumps(compiler) if args[2:4] == ['image', 'inspect'] else None
                    return subprocess.CompletedProcess(args, 0, output)
                with patch.object(foundation, 'ROOT', root), \
                     patch.object(foundation, 'identity', return_value={'revision': 'a' * 40}), \
                     patch.object(foundation.subprocess, 'check_output', return_value='1700000000\n'), \
                     patch.object(foundation.subprocess, 'run', side_effect=run):
                    with self.assertRaisesRegex(ValueError, 'compiler image identity'):
                        foundation.build(root / 'evidence', ca)
                self.assertEqual(json.loads((root / 'evidence/compiler-identity.json').read_text()), compiler)

    def test_synthetic_audit_scans_the_exact_opa_override_at_all_severities(self):
        image_id = 'sha256:' + 'd' * 64
        commands = []
        def run(command, **kwargs):
            commands.append(command)
            output = '[]' if kwargs.get('text') else b'{}'
            return subprocess.CompletedProcess(command, 0, output, '' if kwargs.get('text') else b'')
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(sys, 'argv', ['release-audit.py', temporary]), \
             patch.object(subprocess, 'run', side_effect=run), \
             patch('shutil.which', return_value=sys.executable), \
             patch.dict(os.environ, {'NEX_RELEASE_PROFILE': 'synthetic-qualification', 'NEX_OPA_IMAGE': image_id}), \
             contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
            runpy.run_path(str(SCRIPTS / 'release-audit.py'), run_name='__main__')
        inspections = [cmd for cmd in commands if cmd[:4] == ['docker', '--host=unix:///var/run/docker.sock', 'image', 'inspect']]
        self.assertEqual(len(inspections), 1)
        self.assertIn(image_id, inspections[0])
        scans = [cmd for cmd in commands if cmd[:2] == ['trivy', 'image'] and cmd[-1] == image_id]
        self.assertEqual(len(scans), 1)
        self.assertIn('UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL', scans[0])
        self.assertIn('--exit-code', scans[0])
        self.assertEqual(scans[0][scans[0].index('--exit-code') + 1], '1')

    def test_uses_one_source_bound_image_and_fails_on_source_change_before_load(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            out = root / 'evidence'
            ca = root / 'ca'; ca.write_text('public trust')
            source = {'revision': 'a' * 40, 'inputs': {'sha256': 'b' * 64}}
            changed = {'revision': 'a' * 40, 'inputs': {'sha256': 'c' * 64}}
            image_id = 'sha256:' + 'd' * 64
            layers = [foundation.BASE_LAYER, 'sha256:' + 'e' * 64]
            receipt = {'id': image_id, 'layers': layers}
            calls = []

            def run(args, **kwargs):
                calls.append((args, kwargs['env']))
                command = args[2:]
                if command[0] == 'run':
                    (out / 'bin/opa').write_bytes(b'compiler output')
                if command[:2] == ['image', 'inspect']:
                    if command[2] == foundation.GO_IMAGE:
                        value = {'RepoDigests': [foundation.GO_IMAGE], 'Os': 'linux', 'Architecture': 'amd64'}
                    elif command[2] == foundation.VENDOR_IMAGE:
                        value = {'fixture': 'vendor checked by reconstruction'}
                    else:
                        value = {'Id': image_id, 'RootFS': {'Layers': layers}, 'Labels': {
                            'org.nex.source.inputs': 'b' * 64, 'org.opencontainers.image.revision': 'a' * 40}}
                    return type('Result', (), {'stdout': json.dumps(value)})()
                return type('Result', (), {'stdout': None})()

            with patch.object(foundation, 'ROOT', root), patch.object(foundation, 'identity', side_effect=[source, source]), \
                 patch.object(foundation.subprocess, 'check_output', return_value='1700000000\n'), \
                 patch.object(foundation.subprocess, 'run', side_effect=run), \
                 patch.object(foundation, 'reconstruct', return_value=receipt), \
                 patch.object(foundation, 'verify_reconstruction') as verify, \
                 patch.dict(foundation.os.environ, {'DOCKER_HOST': 'tcp://untrusted', 'HTTPS_PROXY': 'http://proxy.invalid'}, clear=False):
                self.assertEqual(foundation.build(out, ca), image_id)
                verify.assert_called_once()
                self.assertTrue((out / 'receipt.json').is_file())
                self.assertTrue(any(call[0][2:4] == ['image', 'load'] for call in calls))
                self.assertTrue(all('DOCKER_HOST' not in environment for _, environment in calls))
                compiler = next(args for args, _ in calls if args[2] == 'run')
                self.assertIn('HTTPS_PROXY', compiler)
                self.assertIn('--read-only', compiler)
            out2 = root / 'changed-evidence'
            calls.clear()
            # The mocked compile writes into its own requested output directory.
            out = out2
            with patch.object(foundation, 'ROOT', root), patch.object(foundation, 'identity', side_effect=[source, changed]), \
                 patch.object(foundation.subprocess, 'check_output', return_value='1700000000\n'), \
                 patch.object(foundation.subprocess, 'run', side_effect=run), \
                 patch.object(foundation, 'reconstruct', return_value=receipt), \
                 patch.object(foundation, 'verify_reconstruction'):
                with self.assertRaisesRegex(ValueError, 'source changed'):
                    foundation.build(out2, ca)
                self.assertFalse(any(call[0][2:4] == ['image', 'load'] for call in calls))


if __name__ == '__main__':
    unittest.main()
