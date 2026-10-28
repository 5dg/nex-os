"""Exercise inventory coverage offline; stub only the resolved Go-module query."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts'


class SourceInventoryTests(unittest.TestCase):
    def fixture(self, base):
        root = base / 'source'
        def put(name, value):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value)
        for name in ('release-inventory.py', 'source_record.py'):
            put('scripts/' + name, (SCRIPTS / name).read_text())
        for name in ('go.mod', 'go.sum', 'services/guard-kernel/Cargo.toml'):
            put(name, '')
        put('services/guard-kernel/Cargo.lock', 'version = 4\n[[package]]\nname="test"\nversion="1.0.0"\nsource="registry+https://example.invalid"\nchecksum="' + 'a' * 64 + '"\n')
        put('deploy/local/compose.yaml', 'services:\n  app:\n    image: example:fixed\n')
        put('deploy/qualification/compose.yaml', json.dumps({'services': {'app': {'image': 'example:fixed'}}}))
        put('deploy/qualification/pki.json', '{}')
        for directory in ('apps/workspace', 'apps/workspace/tests/browser'):
            put(directory + '/package.json', '{}')
            put(directory + '/package-lock.json', json.dumps({'packages': {'': {}, 'node_modules/shared': {'version': '1.0.0'}}}))
        put('apps/workspace/tests/browser/Dockerfile', 'FROM example:fixed\n')
        tools = base / 'tools'
        tools.mkdir()
        go = tools / 'go'
        go.write_text('#!' + sys.executable + '\nimport json\nprint(json.dumps({"Path":"example.invalid/module","Version":"v1.2.3"}))\n')
        go.chmod(0o755)
        return root, {**os.environ, 'PATH': str(tools) + os.pathsep + os.environ['PATH'], 'NEX_RELEASE_PROFILE': 'synthetic-qualification'}

    def test_browser_packages_and_build_inputs_are_bound_without_losing_shared_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root, env = self.fixture(base)
            out = base / 'inventory'
            command = [sys.executable, '-B', str(root / 'scripts/release-inventory.py'), str(out)]
            result = subprocess.run(command, env=env, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            bom = json.loads((out / 'source-sbom.cdx.json').read_text())
            shared = next(item for item in bom['components'] if item['name'] == 'shared')
            sources = {item['value'] for item in shared['properties'] if item['name'] == 'nex:dependency-source'}
            self.assertEqual(sources, {'apps/workspace/package-lock.json', 'apps/workspace/tests/browser/package-lock.json'})
            hashes = json.loads((out / 'inventory-inputs.json').read_text())['sha256']
            for name in ('package.json', 'package-lock.json', 'Dockerfile'):
                path = 'apps/workspace/tests/browser/' + name
                self.assertEqual(hashes[path], hashlib.sha256((root / path).read_bytes()).hexdigest())
            (root / 'apps/workspace/tests/browser/Dockerfile').write_text('FROM example:changed\n')
            result = subprocess.run(command, env=env, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            changed = json.loads((out / 'source-sbom.cdx.json').read_text())
            self.assertNotEqual(bom['serialNumber'], changed['serialNumber'])

    def test_missing_browser_lock_cannot_produce_a_complete_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root, env = self.fixture(base)
            (root / 'apps/workspace/tests/browser/package-lock.json').unlink()
            out = base / 'inventory'
            result = subprocess.run([sys.executable, '-B', str(root / 'scripts/release-inventory.py'), str(out)], env=env, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((out / 'source-sbom.cdx.json').exists())


if __name__ == '__main__':
    unittest.main()
