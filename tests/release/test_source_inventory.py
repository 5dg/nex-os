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
        put('deploy/qualification/gosu/go.mod', 'module github.com/tianon/gosu\n')
        put('deploy/qualification/gosu/go.sum', 'fixture-checksum\n')
        put('deploy/qualification/gosu/upstream-inputs.json', '{"scope":"fixture downstream overlay"}')
        for name in ('go.mod', 'go.sum', 'opa-v4.patch', 'crit.patch', 'nex_v4_algorithms_test.go', 'LICENSE'):
            put('deploy/qualification/opa/' + name, 'fixture-' + name)
        for name in ('apply-opa-overlay.sh', 'canonical-opa.sh'):
            put('scripts/' + name, 'fixture-' + name)
        for directory in ('apps/workspace', 'apps/workspace/tests/browser'):
            put(directory + '/package.json', '{}')
            put(directory + '/package-lock.json', json.dumps({'packages': {'': {}, 'node_modules/shared': {'version': '1.0.0'}}}))
        put('apps/workspace/tests/browser/Dockerfile', 'FROM example:fixed\n')
        tools = base / 'tools'
        tools.mkdir()
        go = tools / 'go'
        go.write_text('#!' + sys.executable + '\nimport json,os\n'
                      'assert os.environ.get("GOWORK") == "off"\n'
                      'print(json.dumps({"Main":True,"Path":"fixture/main","Dir":os.getcwd()}))\n'
                      'print(json.dumps({"Path":"example.invalid/module","Version":"v1.2.3"}))\n'
                      'if os.getcwd().endswith("/gosu"): print(json.dumps({"Path":"github.com/moby/sys/user","Version":"v0.4.1"}))\n'
                      'if os.getcwd().endswith("/opa"): print(json.dumps({"Path":"github.com/lestrrat-go/jwx/v4","Version":"v4.6.0"}))\n')
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
            common_go = next(item for item in bom['components'] if item['name'] == 'example.invalid/module')
            go_sources = {item['value'] for item in common_go['properties'] if item['name'] == 'nex:dependency-source'}
            self.assertEqual(go_sources, {'go.mod', 'deploy/qualification/gosu/go.mod', 'deploy/qualification/opa/go.mod'})
            go_scopes = {item['value'] for item in common_go['properties'] if item['name'] == 'nex:dependency-scope'}
            self.assertEqual(go_scopes, {'application', 'gosu-downstream-overlay', 'opa-downstream-overlay'})
            vendor_go = next(item for item in bom['components'] if item['name'] == 'github.com/moby/sys/user')
            self.assertEqual(vendor_go['version'], 'v0.4.1')
            self.assertIn({'name': 'nex:dependency-scope', 'value': 'gosu-downstream-overlay'}, vendor_go['properties'])
            opa_go = next(item for item in bom['components'] if item['name'] == 'github.com/lestrrat-go/jwx/v4')
            self.assertEqual(opa_go['version'], 'v4.6.0')
            self.assertIn({'name': 'nex:dependency-scope', 'value': 'opa-downstream-overlay'}, opa_go['properties'])
            hashes = json.loads((out / 'inventory-inputs.json').read_text())['sha256']
            for name in ('package.json', 'package-lock.json', 'Dockerfile'):
                path = 'apps/workspace/tests/browser/' + name
                self.assertEqual(hashes[path], hashlib.sha256((root / path).read_bytes()).hexdigest())
            for name in ('go.mod', 'go.sum', 'upstream-inputs.json'):
                path = 'deploy/qualification/gosu/' + name
                self.assertEqual(hashes[path], hashlib.sha256((root / path).read_bytes()).hexdigest())
            for name in ('go.mod', 'go.sum', 'opa-v4.patch', 'crit.patch', 'nex_v4_algorithms_test.go', 'LICENSE'):
                path = 'deploy/qualification/opa/' + name
                self.assertEqual(hashes[path], hashlib.sha256((root / path).read_bytes()).hexdigest())
            for name in ('apply-opa-overlay.sh', 'canonical-opa.sh'):
                path = 'scripts/' + name
                self.assertEqual(hashes[path], hashlib.sha256((root / path).read_bytes()).hexdigest())
            (root / 'apps/workspace/tests/browser/Dockerfile').write_text('FROM example:changed\n')
            result = subprocess.run(command, env=env, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            changed = json.loads((out / 'source-sbom.cdx.json').read_text())
            self.assertNotEqual(bom['serialNumber'], changed['serialNumber'])
            (root / 'deploy/qualification/gosu/upstream-inputs.json').write_text('{"scope":"changed upstream binding"}')
            result = subprocess.run(command, env=env, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            changed_vendor = json.loads((out / 'source-sbom.cdx.json').read_text())
            self.assertNotEqual(changed['serialNumber'], changed_vendor['serialNumber'])
            (root / 'deploy/qualification/opa/crit.patch').write_text('changed OPA patch')
            result = subprocess.run(command, env=env, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            changed_opa = json.loads((out / 'source-sbom.cdx.json').read_text())
            self.assertNotEqual(changed_vendor['serialNumber'], changed_opa['serialNumber'])

    def test_missing_browser_lock_cannot_produce_a_complete_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root, env = self.fixture(base)
            (root / 'apps/workspace/tests/browser/package-lock.json').unlink()
            out = base / 'inventory'
            result = subprocess.run([sys.executable, '-B', str(root / 'scripts/release-inventory.py'), str(out)], env=env, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((out / 'source-sbom.cdx.json').exists())

    def test_missing_vendor_input_cannot_fall_back_to_application_graph(self):
        for name in ('go.mod', 'go.sum', 'upstream-inputs.json'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root, env = self.fixture(base)
                (root / 'deploy/qualification/gosu' / name).unlink()
                out = base / 'inventory'
                result = subprocess.run([sys.executable, '-B', str(root / 'scripts/release-inventory.py'), str(out)], env=env, capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((out / 'source-sbom.cdx.json').exists())

    def test_failed_or_mismatched_vendor_graph_does_not_emit_partial_inventory(self):
        for outcome in ('failure', 'parent-root'):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root, env = self.fixture(base)
                go = base / 'tools/go'
                go.write_text('#!' + sys.executable + '\nimport json,os,sys\n'
                              + ('if os.getcwd().endswith("/gosu"): sys.exit(1)\n' if outcome == 'failure' else '')
                              + 'print(json.dumps({"Main":True,"Path":"fixture/main","Dir":' + repr(str(root)) + '}))\n')
                out = base / 'inventory'
                result = subprocess.run([sys.executable, '-B', str(root / 'scripts/release-inventory.py'), str(out)], env=env, capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((out / 'source-sbom.cdx.json').exists())

    def test_missing_or_symlinked_opa_input_cannot_emit_inventory(self):
        for name in ('go.mod', 'go.sum', 'opa-v4.patch', 'crit.patch', 'nex_v4_algorithms_test.go', 'LICENSE'):
            for symlink in (False, True):
                with self.subTest(name=name, symlink=symlink), tempfile.TemporaryDirectory() as temporary:
                    base = Path(temporary); root, env = self.fixture(base)
                    path = root / 'deploy/qualification/opa' / name
                    path.unlink()
                    if symlink:
                        path.symlink_to(root / 'go.mod')
                    out = base / 'inventory'
                    result = subprocess.run([sys.executable, '-B', str(root / 'scripts/release-inventory.py'), str(out)], env=env, capture_output=True, timeout=10)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse((out / 'source-sbom.cdx.json').exists())

    def test_opa_graph_failure_cannot_fall_back_or_emit_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); root, env = self.fixture(base)
            go = base / 'tools/go'
            go.write_text('#!' + sys.executable + '\nimport json,os,sys\n'
                          'if os.getcwd().endswith("/opa"): sys.exit(1)\n'
                          'print(json.dumps({"Main":True,"Path":"fixture/main","Dir":os.getcwd()}))\n')
            out = base / 'inventory'
            result = subprocess.run([sys.executable, '-B', str(root / 'scripts/release-inventory.py'), str(out)], env=env, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((out / 'source-sbom.cdx.json').exists())


if __name__ == '__main__':
    unittest.main()
