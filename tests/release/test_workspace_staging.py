"""Exercise the actual prebuild verifier with a captured tree and npm-like output."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/verify-workspace-staging.mjs'


class WorkspaceStagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.authored = self.source / 'apps/workspace'
        self.authored.mkdir(parents=True)
        for name in ('package.json', 'package-lock.json', 'next.config.ts', 'app/page.tsx',
                     'lib/nested/logic.ts', 'components/Button.tsx', 'tests/target/fixture.ts'):
            path = self.authored / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{}' if name.endswith('.json') else '// captured authored input\n')
            path.chmod(0o644)
        files = {str(path.relative_to(self.source)): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in sorted(self.authored.rglob('*')) if path.is_file()}
        modes = {name: 0o644 for name in files}
        self.identity = hashlib.sha256(json.dumps({'files': files, 'modes': modes}, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        (self.source / '.nex-source.json').write_text(json.dumps({'schema_version': 1, 'inputs': {'files': files, 'modes': modes, 'sha256': self.identity}}))
        self.staged = self.root / 'staged'
        shutil.copytree(self.authored, self.staged)

    def run_check(self, phase='installed', succeeds=True):
        report = self.root / 'report.json'
        result = subprocess.run(['node', str(SCRIPT), str(self.source), str(self.staged), phase, str(report)],
                                env={**os.environ, 'NEX_SOURCE_INPUT_SHA256': self.identity}, capture_output=True, text=True)
        if succeeds:
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(report.read_text())
            self.assertEqual(data['source_input_sha256'], self.identity)
            self.assertEqual(data['phase'], phase)
            self.assertEqual(len(data['files']), 7)
            return data
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(report.exists(), result.stderr)

    def test_pristine_capture_matches(self):
        self.assertEqual(self.run_check('pristine')['allowed_generated_roots'], [])

    def test_frozen_install_tree_allows_only_root_dependencies(self):
        (self.staged / 'node_modules/.bin').mkdir(parents=True)
        (self.staged / 'node_modules/package.js').write_text('// dependency')
        (self.staged / 'node_modules/.bin/tool').symlink_to('../package.js')
        self.assertEqual(self.run_check()['allowed_generated_roots'], ['node_modules'])

    def test_changed_content_rejected(self):
        (self.staged / 'lib/nested/logic.ts').write_text('// changed')
        self.run_check(succeeds=False)

    def test_deleted_source_rejected(self):
        (self.staged / 'app/page.tsx').unlink()
        self.run_check(succeeds=False)

    def test_changed_mode_rejected(self):
        (self.staged / 'next.config.ts').chmod(0o755)
        self.run_check(succeeds=False)

    def test_authored_symlink_rejected(self):
        path = self.staged / 'app/page.tsx'
        path.unlink()
        path.symlink_to(self.authored / 'app/page.tsx')
        self.run_check(succeeds=False)

    def test_nested_injected_source_rejected(self):
        (self.staged / 'lib/nested/injected.ts').write_text('// injection')
        self.run_check(succeeds=False)

    def test_nested_generated_name_is_not_an_exception(self):
        (self.staged / 'app/node_modules').mkdir()
        self.run_check(succeeds=False)

    def test_no_preexisting_cache_in_pristine_tree(self):
        (self.staged / 'node_modules').mkdir()
        self.run_check('pristine', succeeds=False)

    def test_no_next_output_before_build(self):
        (self.staged / '.next').mkdir()
        self.run_check(succeeds=False)

    def test_dependency_root_symlink_rejected(self):
        (self.staged / 'node_modules').symlink_to(self.authored, target_is_directory=True)
        self.run_check(succeeds=False)

    def test_mutated_source_does_not_redefine_capture(self):
        (self.authored / 'app/page.tsx').write_text('// changed')
        shutil.copy2(self.authored / 'app/page.tsx', self.staged / 'app/page.tsx')
        self.run_check(succeeds=False)

    def test_unbound_companion_rejected(self):
        self.identity = 'f' * 64
        self.run_check(succeeds=False)


if __name__ == '__main__':
    unittest.main()
