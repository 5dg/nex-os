"""Negative controls for the nonrelease image diagnostic."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PATH = Path(__file__).with_name('bounded.py')
spec = importlib.util.spec_from_file_location('runtime_candidate_bounded', PATH)
bounded = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bounded)


class BoundedDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / 'nex-runtime-guard'
        self.output.mkdir()
        self.image = 'sha256:' + 'a' * 64
        (self.output / 'image-id.txt').write_text(self.image + '\n')
        self.scanner = self.root / 'nex-runtime-trivy/trivy'
        self.scanner.parent.mkdir()
        self.scanner.write_bytes(b'pinned scanner fixture')
        self.environment = patch.dict(os.environ, {'RUNNER_TEMP': str(self.root),
            'TRIVY_CACHE_DIR': str(self.root / 'cache'), 'GITHUB_SHA': 'b' * 40,
            'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'})
        self.environment.start(); self.addCleanup(self.environment.stop)
        self.root_probe = patch.object(bounded.diagnostic, 'probe', return_value=str(self.root).encode())
        self.root_probe.start(); self.addCleanup(self.root_probe.stop)

    def test_build_keeps_exact_source_and_admission(self):
        with patch.object(bounded.diagnostic, 'admit', return_value={'free': 1}) as admit, \
             patch.object(bounded.diagnostic, 'invoke', return_value=0) as invoke:
            self.assertEqual(bounded.main('guard', 'build'), 0)
        admit.assert_called_once_with(self.output, self.root, 'guard')
        args = invoke.call_args.args
        command = args[0]
        self.assertIn('org.nex.diagnostic.source=' + 'b' * 40, command)
        self.assertIn('org.nex.diagnostic.scope=non-release', command)
        self.assertEqual(command[command.index('--platform') + 1], 'linux/amd64')
        self.assertEqual(args[6], bounded.diagnostic.FORECAST['guard'])

    def test_scan_requires_pinned_scanner_and_exact_all_severity_image(self):
        with patch.object(bounded.diagnostic, 'sha', return_value=bounded.diagnostic.SCANNER_SHA256), \
             patch.object(bounded.diagnostic, 'validate_cache_filesystem'), \
             patch.object(bounded.diagnostic, 'admit_scan', return_value={'free': 1}), \
             patch.object(bounded.diagnostic, 'invoke', return_value=1) as invoke:
            self.assertEqual(bounded.main('guard', 'scan'), 1)
        command = invoke.call_args.args[0]
        self.assertEqual(command[-1], self.image)
        self.assertEqual(command[command.index('--severity') + 1], 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL')
        self.assertEqual(command[command.index('--exit-code') + 1], '1')
        self.assertEqual(invoke.call_args.kwargs['stdout_limit'], 16*1024**2)
        self.assertNotIn('--ignore-unfixed', command)

    def test_database_download_is_bounded_and_does_not_reuse_an_image(self):
        with patch.object(bounded.diagnostic, 'sha', return_value=bounded.diagnostic.SCANNER_SHA256), \
             patch.object(bounded.diagnostic, 'validate_cache_filesystem'), \
             patch.object(bounded.diagnostic, 'admit', return_value={'free': 1}), \
             patch.object(bounded.diagnostic, 'invoke', return_value=0) as invoke:
            self.assertEqual(bounded.main('guard', 'database'), 0)
        command = invoke.call_args.args[0]
        self.assertIn('--download-db-only', command)
        self.assertEqual(command[command.index('--db-repository') + 1], 'ghcr.io/aquasecurity/trivy-db:2')
        self.assertNotIn(self.image, command)
        self.assertEqual(invoke.call_args.args[6], bounded.diagnostic.FORECAST['guard'])

    def test_failed_smoke_is_failed_and_reconciles_only_its_owned_containers(self):
        with patch.object(bounded.shutil, 'disk_usage', return_value=SimpleNamespace(free=5*1024**3)), \
             patch.object(bounded.secrets, 'token_hex', return_value='a' * 32), \
             patch.object(bounded.diagnostic, 'invoke', return_value=1), \
             patch.object(bounded.diagnostic.owned_smoke, 'reconcile') as reconcile:
            self.assertEqual(bounded.main('guard', 'smoke'), 1)
        self.assertEqual(reconcile.call_count, 2)
        for call in reconcile.call_args_list:
            self.assertEqual(call.args[1:], (self.image, 'a' * 32, 'guard'))
            self.assertTrue(call.args[0].startswith('nex-image-probe-123-1-guard'))

    def test_rejects_unknown_role_unpinned_scanner_and_bad_image(self):
        with self.assertRaises(ValueError):
            bounded.main('../workspace', 'build')
        with patch.object(bounded.diagnostic, 'sha', return_value='0' * 64):
            with self.assertRaisesRegex(ValueError, 'scanner identity'):
                bounded.main('guard', 'scan')
        (self.output / 'image-id.txt').write_text('latest')
        with patch.object(bounded.diagnostic, 'sha', return_value=bounded.diagnostic.SCANNER_SHA256), \
             patch.object(bounded.diagnostic, 'validate_cache_filesystem'):
            with self.assertRaisesRegex(ValueError, 'immutable built image'):
                bounded.main('guard', 'scan')

    def test_workflow_rejects_substituted_image_even_under_python_optimization(self):
        workflow = (PATH.parents[2] / '.github/workflows/runtime-candidate-diagnostic.yml').read_text()
        script = textwrap.dedent(workflow.split(" <<'PY'\n", 1)[1].split('\n          PY\n', 1)[0])
        inspect = self.root / 'inspect.json'
        valid = {'Id': self.image, 'Os': 'linux', 'Architecture': 'amd64',
                 'Config': {'User': '65532:65532', 'Labels': {
                     'org.nex.diagnostic.scope': 'non-release', 'org.nex.diagnostic.source': 'b' * 40}}}
        def check(image):
            inspect.write_text(json.dumps([image]))
            return subprocess.run([sys.executable, '-O', '-c', script, str(inspect),
                                   self.image, 'b' * 40, 'guard'], capture_output=True).returncode
        self.assertEqual(check(valid), 0)
        for field, value in (('Id', 'sha256:' + 'c' * 64), ('Os', 'windows'), ('Architecture', 'arm64')):
            with self.subTest(field=field):
                self.assertNotEqual(check({**valid, field: value}), 0)
        for config in ({**valid['Config'], 'User': 'root'},
                       {**valid['Config'], 'Labels': {'org.nex.diagnostic.scope': 'non-release',
                                                     'org.nex.diagnostic.source': 'c' * 40}}):
            self.assertNotEqual(check({**valid, 'Config': config}), 0)


if __name__ == '__main__':
    unittest.main()
