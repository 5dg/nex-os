"""Real captured-tree CLI smoke: no Git/Docker and no inherited bytecode flag."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import source_record


class GitlessCLITests(unittest.TestCase):
    def test_verify_and_builder_import_preflight_do_not_write_captured_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / 'source'
            (root / 'scripts').mkdir(parents=True)
            for name in ('candidate.py', 'source_record.py', 'image_record.py',
                         'canonical-build.py', 'canonical_image.py', 'opa_image.py', 'resource_admission.py', 'phase_admission.py', 'image_archive.py', 'candidate-evidence.py', 'verify-provenance.py'):
                shutil.copy2(SCRIPTS / name, root / 'scripts' / name)
            (root / 'go.mod').write_text('module example.invalid/gitless\n')
            source_record.atomic_json(root / source_record.COMPANION, {
                'schema_version': 1, 'revision': 'a' * 40, 'source_epoch': 1700000000,
                'inputs': source_record.inputs(root, canonical=True)})
            source = source_record.identity(root, canonical=True)
            archive = base / 'source.tar'
            with tarfile.open(archive, 'w') as saved:
                for path in sorted(root.rglob('*')):
                    if path.is_file():
                        saved.add(path, arcname=path.relative_to(root), recursive=False)
            manifest = base / 'candidate.json'
            source_record.atomic_json(manifest, {'schema_version': 1, 'run_id': '123456abcdef',
                'source_directory': 'source', 'source': source,
                'archive': {'path': 'source.tar', 'sha256': source_record.sha256(archive)}})
            def physical_snapshot():
                return {str(path.relative_to(root)): (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mode & 0o7777)
                        for path in root.rglob('*') if path.is_file()}
            before = physical_snapshot()
            env = os.environ.copy()
            env.pop('PYTHONDONTWRITEBYTECODE', None)
            env.pop('PYTHONPYCACHEPREFIX', None)
            commands = [
                [sys.executable, str(root / 'scripts/candidate.py'), 'verify', '--candidate', str(manifest)],
                *[[sys.executable, str(root / 'scripts' / name), '--help'] for name in
                  ('canonical-build.py', 'candidate-evidence.py', 'verify-provenance.py')],
            ]
            for command in commands:
                with self.subTest(script=Path(command[1]).name):
                    outcome = subprocess.run(command, env=env, cwd=base, capture_output=True, timeout=10)
                    self.assertEqual(outcome.returncode, 0, outcome.stderr.decode(errors='replace')[:1500])
                    self.assertEqual(before, physical_snapshot(), 'captured source changed during CLI validation/import')
                    self.assertFalse(any(root.rglob('__pycache__')), 'captured CLI created a bytecode cache')
            rejected = subprocess.run([sys.executable, str(root / 'scripts/canonical-build.py'),
                '--candidate', str(manifest), '--build', 'one', '--ca', str(base / 'missing-ca.crt')],
                env=env, cwd=base, capture_output=True, timeout=10)
            self.assertEqual(rejected.returncode, 1)
            self.assertIn(b'verified build CA bundle required', rejected.stderr)
            self.assertFalse((base / 'builds').exists(), 'CA preflight must reject before builder/runtime admission')
            self.assertEqual(before, physical_snapshot())
            self.assertFalse(any(root.rglob('__pycache__')))
            self.assertEqual(source, source_record.identity(root, canonical=True))


if __name__ == '__main__':
    unittest.main()
