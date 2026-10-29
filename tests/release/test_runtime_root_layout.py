"""Public scratch trust layout must remain readable under a restrictive umask."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('runtime_root_builder', SCRIPTS / 'canonical-build.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class RuntimeRootTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.package = self.root / 'package'; self.package.mkdir()
        self.trust = self.package / 'trust'; self.trust.mkdir()
        self.certificate = self.trust / 'ca-certificates.crt'
        self.content = b'-----BEGIN CERTIFICATE-----\npublic-fixture-only\n-----END CERTIFICATE-----\n'
        self.certificate.write_bytes(self.content)
        self.digest = hashlib.sha256(self.content).hexdigest()

    def prepare(self):
        return builder.prepare_runtime_root(self.package, self.digest)

    def test_umask_077_preserves_public_bytes_and_all_nonroot_traversal_permissions(self):
        self.certificate.chmod(0o600)
        previous = os.umask(0o077)
        try:
            layout = self.prepare()
        finally:
            os.umask(previous)
        root = self.package / 'runtime-root'
        directories = [root, root / 'etc', root / 'etc/ssl', root / 'etc/ssl/certs']
        for path in directories:
            with self.subTest(path=path):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o555)
                self.assertEqual(path.stat().st_mode & 0o005, 0o005)
        target = root / 'etc/ssl/certs/ca-certificates.crt'
        self.assertEqual(target.read_bytes(), self.content)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o444)
        self.assertEqual(stat.S_IMODE(self.certificate.stat().st_mode), 0o600)
        self.assertEqual(layout['public_ca_sha256'], self.digest)
        self.assertEqual(layout['directories'], {'.': 0o555, 'etc': 0o555, 'etc/ssl': 0o555, 'etc/ssl/certs': 0o555})
        self.assertEqual({path.relative_to(root).as_posix() for path in root.rglob('*')},
                         {'etc', 'etc/ssl', 'etc/ssl/certs', 'etc/ssl/certs/ca-certificates.crt'})

    def test_substituted_public_bundle_is_rejected_before_creating_root(self):
        self.certificate.write_bytes(b'substituted')
        with self.assertRaisesRegex(ValueError, 'frozen compiler digest'):
            self.prepare()
        self.assertFalse((self.package / 'runtime-root').exists())

    def test_ca_symlink_is_not_followed(self):
        outside = self.root / 'outside'; outside.write_bytes(self.content)
        self.certificate.unlink(); self.certificate.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'regular CA'):
            self.prepare()
        self.assertEqual(outside.read_bytes(), self.content)
        self.assertFalse((self.package / 'runtime-root').exists())

    def test_trust_directory_symlink_is_not_followed(self):
        outside = self.root / 'outside'; self.trust.rename(outside); self.trust.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'directories'):
            self.prepare()
        self.assertFalse((self.package / 'runtime-root').exists())

    def test_extra_private_file_is_rejected_without_copy(self):
        private = self.trust / 'private.key'; private.write_bytes(b'never copy this fixture')
        with self.assertRaisesRegex(ValueError, 'only the regular CA'):
            self.prepare()
        self.assertEqual(private.read_bytes(), b'never copy this fixture')
        self.assertFalse((self.package / 'runtime-root').exists())

    def test_existing_or_broken_link_output_is_never_overwritten(self):
        target = self.package / 'runtime-root'
        outside = self.root / 'missing'
        target.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'fresh'):
            self.prepare()
        self.assertTrue(target.is_symlink()); self.assertFalse(outside.exists())
        target.unlink(); target.mkdir(); sentinel = target / 'preserve'; sentinel.write_text('original')
        with self.assertRaisesRegex(ValueError, 'fresh'):
            self.prepare()
        self.assertEqual(sentinel.read_text(), 'original')

    def test_source_mutation_during_copy_rejects_incomplete_output(self):
        copy = builder.shutil.copyfileobj
        def changed(source, destination):
            copy(source, destination)
            self.certificate.write_bytes(b'changed during copy')
        with patch.object(builder.shutil, 'copyfileobj', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'changed during'):
                self.prepare()

    def test_compiler_boundary_binds_layout_and_actual_export_in_phase_metadata(self):
        instance = builder.Builder.__new__(builder.Builder)
        instance.path = self.root; instance.package = self.package
        instance.bin = self.root / 'bin'; instance.bin.mkdir()
        instance.manifest = self.root / 'manifest.json'; instance.record = {}
        instance.eviction_plan = {}; instance.discard_owned_scratch = lambda name: False
        for name in ('control', 'dev-issuer', 'model', 'executor', 'worker', 'evidence', 'qualification-edge', 'qualification-policy-edge', 'qualification-pki', 'qualification-issuer', 'qualification-receiver-readiness'):
            path = instance.bin / name; path.write_bytes(b'fixture compiled public binary'); path.chmod(0o555)
        for name in ('go-version.txt', 'go-target.txt', 'go-compiler.sha256'):
            (instance.bin / name).write_text('fixture pinned compiler metadata')
        (instance.bin / 'runtime-trust-bundle.sha256').write_text(self.digest + '  /package/trust/ca-certificates.crt\n')
        for name in ('usr/local/bin/gosu', 'usr/local/share/nex/gosu-build.txt', 'usr/local/share/nex/gosu-dependency-overlay.json'):
            path = self.package / 'postgres' / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('fixture public compiler export')
        instance.compiler_boundary('gosu')
        record = json.loads(instance.manifest.read_text())['phase_exports']['gosu']
        self.assertEqual(record['package/runtime-root/etc/ssl/certs/ca-certificates.crt'], {'sha256': self.digest, 'mode': 0o444})
        layout = json.loads(record['bin/runtime-root-layout.json']['text'])
        self.assertEqual(layout['public_ca_sha256'], self.digest)
        self.assertEqual(set(layout['directories'].values()), {0o555})
        self.assertEqual(record['bin/runtime-root-layout.json']['sha256'], hashlib.sha256((instance.bin / 'runtime-root-layout.json').read_bytes()).hexdigest())

    def test_both_runtime_consumers_copy_the_explicit_tree_and_keep_nonroot_user(self):
        for role in ('control', 'fixtures'):
            dockerfile = SCRIPTS.parent / f'deploy/qualification/Dockerfile.{role}.runtime'
            instructions = [line.strip() for line in dockerfile.read_text().splitlines() if line.strip() and not line.startswith('#')]
            with self.subTest(role=role):
                self.assertEqual(instructions[:2], ['FROM scratch', 'COPY runtime-root/ /'])
                self.assertIn('USER 65532:65532', instructions)
                self.assertTrue(any(line.startswith('COPY --chmod=0555 bin/') for line in instructions))
                self.assertFalse(any('trust/ca-certificates.crt' in line for line in instructions))


if __name__ == '__main__':
    unittest.main()
