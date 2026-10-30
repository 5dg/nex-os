"""Corruption and provenance fixtures; no Docker or network required."""
import hashlib
import io
import importlib.util
import json
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import opa_image
import candidate
from canonical_image import archive_identity

spec = importlib.util.spec_from_file_location('nex_canonical_build_for_opa', SCRIPTS / 'canonical-build.py')
canonical_build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(canonical_build)
evidence_spec = importlib.util.spec_from_file_location('nex_candidate_evidence_for_opa', SCRIPTS / 'candidate-evidence.py')
candidate_evidence = importlib.util.module_from_spec(evidence_spec)
evidence_spec.loader.exec_module(candidate_evidence)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def tar_bytes(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for name, data in entries:
            tar.addfile(opa_image.tar_entry(name, len(data), 0o644, 0), io.BytesIO(data))
    return out.getvalue()


class OPAImageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='nex-opa-image-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = tar_bytes([('etc/ssl/cert', b'synthetic trust')])
        self.old = tar_bytes([('opa', b'old vendor binary')])
        self.base_id = 'sha256:' + digest(self.base)
        self.old_id = 'sha256:' + digest(self.old)
        self.vendor_config = {'os': 'linux', 'architecture': 'amd64',
                              'config': {'User': '1000:1000', 'Entrypoint': ['/opa'], 'Cmd': ['run'],
                                         'Env': ['SSL_CERT_FILE=/etc/ssl/cert'], 'Labels': {'vendor': 'fixture', 'org.opencontainers.image.vendor': 'upstream-vendor', 'org.opencontainers.image.source': 'https://example.invalid/upstream'},
                                         'WorkingDir': '/fixture', 'ArgsEscaped': True},
                              'rootfs': {'type': 'layers', 'diff_ids': [self.base_id, self.old_id]},
                              'history': [{'created_by': 'old executable'}]}
        config = opa_image.encoded(self.vendor_config)
        self.config_id = 'sha256:' + digest(config)
        vendor = 'example.invalid/opa@sha256:' + 'a' * 64
        self.inspect = {'Id': self.config_id, 'RepoDigests': [vendor], 'Os': 'linux', 'Architecture': 'amd64',
                        'RootFS': {'Layers': [self.base_id, self.old_id]}}
        self.archive = self.root / 'vendor.tar'
        manifest = opa_image.encoded([{'Config': digest(config) + '.json', 'RepoTags': [], 'Layers': ['base/layer.tar', 'old/layer.tar']}])
        self.archive.write_bytes(tar_bytes([('manifest.json', manifest), (digest(config) + '.json', config),
                                            ('base/layer.tar', self.base), ('old/layer.tar', self.old)]))
        self.binary = self.root / 'opa'; self.binary.write_bytes(b'new candidate binary')
        self.license = self.root / 'LICENSE'; self.license.write_bytes(b'synthetic license')
        for name, value in {'VENDOR_IMAGE': vendor, 'VENDOR_CONFIG': self.config_id,
                            'BASE_LAYER': self.base_id, 'VENDOR_EXEC_LAYER': self.old_id,
                            'LICENSE_SHA256': digest(self.license.read_bytes())}.items():
            p = patch.object(opa_image, name, value); p.start(); self.addCleanup(p.stop)

    def build(self, name='output.tar'):
        return opa_image.reconstruct(self.archive, self.inspect, self.binary, self.license,
                                     self.root / name, 1700000000, 'a' * 40, 'b' * 64)

    def test_exact_base_old_binary_absent_and_source_bound(self):
        result = self.build()
        path = self.root / 'output.tar'
        self.assertEqual(result['layers'][0], self.base_id)
        self.assertEqual(archive_identity(path)['id'], result['id'])
        verified = opa_image.verify_reconstruction(path, result, digest(self.binary.read_bytes()), 'a' * 40, 'b' * 64, 1700000000)
        self.assertEqual(verified['id'], result['id'])
        with self.assertRaises(ValueError):
            opa_image.verify_reconstruction(path, result, '0' * 64, 'a' * 40, 'b' * 64, 1700000000)
        with self.assertRaises(ValueError):
            opa_image.verify_reconstruction(path, {**result, 'vendor_config_base64': 'e30='}, digest(self.binary.read_bytes()), 'a' * 40, 'b' * 64, 1700000000)
        self.assertNotIn(b'old vendor binary', path.read_bytes())
        with tarfile.open(path) as archive:
            manifest = json.load(archive.extractfile('manifest.json'))[0]
            config = json.load(archive.extractfile(manifest['Config']))
            self.assertEqual(archive.extractfile(manifest['Layers'][0]).read(), self.base)
            self.assertEqual(config['config']['WorkingDir'], '/fixture')
            self.assertTrue(config['config']['ArgsEscaped'])
            self.assertEqual(config['config']['Labels']['vendor'], 'fixture')
            self.assertNotIn('org.opencontainers.image.vendor', config['config']['Labels'])
            self.assertEqual(config['config']['Labels']['org.opencontainers.image.source'], 'https://github.com/5dg/nex-os')
            self.assertEqual(config['config']['Labels']['org.nex.source.inputs'], 'b' * 64)
            self.assertEqual(config['config']['Labels']['org.opencontainers.image.revision'], 'a' * 40)
            self.assertNotIn('history', config)
        again = self.build('output-2.tar')
        self.assertEqual(result['archive_sha256'], again['archive_sha256'])

    def test_tampered_identity_or_bytes_fail(self):
        for field in ('Id', 'RepoDigests', 'Architecture', 'RootFS'):
            with self.subTest(field=field):
                original = self.inspect[field]
                self.inspect[field] = None
                with self.assertRaises((ValueError, AttributeError)):
                    self.build(field + '.tar')
                self.inspect[field] = original
        data = bytearray(self.archive.read_bytes())
        where = data.index(b'synthetic trust'); data[where] ^= 1
        self.archive.write_bytes(data)
        with self.assertRaises(ValueError):
            self.build('tampered.tar')

    def test_tagged_vendor_archive_allowed_but_output_remains_untagged(self):
        with tarfile.open(self.archive) as archive:
            manifest = json.load(archive.extractfile('manifest.json'))
            config = archive.extractfile(manifest[0]['Config']).read()
        manifest[0]['RepoTags'] = ['example.invalid/opa:locally-tagged']
        self.archive.write_bytes(tar_bytes([('manifest.json', opa_image.encoded(manifest)),
                                            (digest(config) + '.json', config),
                                            ('base/layer.tar', self.base), ('old/layer.tar', self.old)]))
        with self.assertRaisesRegex(ValueError, 'must be untagged'):
            archive_identity(self.archive)
        result = self.build('from-tagged-vendor.tar')
        with tarfile.open(self.root / 'from-tagged-vendor.tar') as archive:
            generated = json.load(archive.extractfile('manifest.json'))
        self.assertEqual(generated[0]['RepoTags'], [])
        self.assertEqual(archive_identity(self.root / 'from-tagged-vendor.tar')['id'], result['id'])

    def test_existing_or_symlinked_output_and_source_are_rejected(self):
        target = self.root / 'present.tar'; target.write_bytes(b'keep')
        with self.assertRaises(ValueError):
            self.build('present.tar')
        self.assertEqual(target.read_bytes(), b'keep')
        link = self.root / 'linked.tar'; link.symlink_to(target)
        with self.assertRaises(ValueError):
            self.build('linked.tar')
        self.binary.unlink(); self.binary.symlink_to(target)
        with self.assertRaises(ValueError):
            self.build('linked-source.tar')

    def test_untrusted_license_and_old_binary_fail(self):
        self.license.write_bytes(b'substituted license')
        with self.assertRaises(ValueError):
            self.build('bad-license.tar')
        self.license.write_bytes(b'synthetic license')
        self.binary.write_bytes(b'old vendor binary')
        with self.assertRaises(ValueError):
            self.build('old.tar')

    def test_matching_vendor_base_with_old_executable_is_rejected(self):
        forbidden = tar_bytes([('opa', b'old vendor binary')])
        base_id = 'sha256:' + digest(forbidden)
        config = dict(self.vendor_config)
        config['rootfs'] = {'type': 'layers', 'diff_ids': [base_id, self.old_id]}
        raw_config = opa_image.encoded(config)
        config_id = 'sha256:' + digest(raw_config)
        manifest = opa_image.encoded([{'Config': digest(raw_config) + '.json', 'RepoTags': [], 'Layers': ['base/layer.tar', 'old/layer.tar']}])
        self.archive.write_bytes(tar_bytes([('manifest.json', manifest), (digest(raw_config) + '.json', raw_config),
                                            ('base/layer.tar', forbidden), ('old/layer.tar', self.old)]))
        self.inspect['Id'] = config_id
        self.inspect['RootFS']['Layers'] = [base_id, self.old_id]
        with patch.object(opa_image, 'BASE_LAYER', base_id), patch.object(opa_image, 'VENDOR_CONFIG', config_id):
            with self.assertRaisesRegex(ValueError, 'executable present'):
                self.build('forbidden.tar')

    def test_candidate_verification_requires_source_labels_receipt_and_binary(self):
        result = self.build()
        build_dir = self.root / 'builds' / 'one'; (build_dir / 'images').mkdir(parents=True)
        archive = build_dir / 'images' / 'opa.tar'; archive.write_bytes((self.root / 'output.tar').read_bytes())
        proof = build_dir / 'opa-reconstruction.json'; proof.write_text(json.dumps(result))
        record = {'id': result['id'], 'layers': result['layers'], 'archive_origin': 'verified-vendor-base-reconstruction-v1',
                  'archive': {'path': 'images/opa.tar', 'sha256': digest(archive.read_bytes())},
                  'reconstruction': {'path': proof.name, 'sha256': digest(proof.read_bytes())}}
        other_id = 'sha256:' + 'c' * 64
        images = {name: {'id': other_id} for name in candidate.IMAGE_ENV}
        images['opa'] = record
        build = {'images': images, 'binaries': {'opa': digest(self.binary.read_bytes())}}
        manifest = build_dir / 'manifest.json'; manifest.write_text(json.dumps(build))
        data = {'source': {'revision': 'a' * 40, 'source_epoch': 1700000000, 'inputs': {'sha256': 'b' * 64}},
                'builds': {'one': {'path': 'builds/one/manifest.json', 'sha256': digest(manifest.read_bytes())}}}
        labels = {'org.nex.source.inputs': 'b' * 64, 'org.opencontainers.image.revision': 'a' * 40,
                  'org.nex.opa.downstream': 'true', 'org.nex.opa.vendor-base': opa_image.VENDOR_IMAGE}
        response = {'id': result['id'], 'labels': labels, 'layers': result['layers'], 'digests': []}
        def inspect(command, **_kwargs):
            if result['id'] in command:
                return json.dumps(response)
            return json.dumps({'id': other_id, 'labels': labels, 'layers': [], 'digests': []})
        args = SimpleNamespace(candidate=self.root / 'candidate.json', build='one')
        with patch.object(candidate, 'load', return_value=(data, self.root, self.root)), patch.object(candidate.subprocess, 'check_output', side_effect=inspect):
            candidate.verify_images(args)
            labels['org.nex.source.inputs'] = '0' * 64
            with self.assertRaises(ValueError):
                candidate.verify_images(args)
            labels['org.nex.source.inputs'] = 'b' * 64
            response['layers'] = [self.base_id, self.old_id]
            with self.assertRaises(ValueError):
                candidate.verify_images(args)
            response['layers'] = result['layers']
            archive.write_bytes(archive.read_bytes() + b'tamper')
            with self.assertRaises(ValueError):
                candidate.verify_images(args)

    def test_compiler_boundary_requires_all_opa_outputs(self):
        instance = canonical_build.Builder.__new__(canonical_build.Builder)
        instance.path = self.root; instance.bin = self.root / 'bin'; instance.bin.mkdir()
        instance.package = self.root / 'package'; (instance.package / 'opa').mkdir(parents=True)
        instance.manifest = self.root / 'manifest.json'; instance.record = {}
        instance.discard_owned_scratch = lambda _name: False
        instance.discard_opa_scratch_files = lambda: []
        for name in ('source-files.bin', 'source-tree.bin'):
            (instance.package / 'opa' / name).write_bytes(b'fixture inventory')
        names = ['opa', 'opa-build.txt', 'opa-source-inventory.txt', 'opa-bundle-tests.txt',
                 'opa-topdown-tests.txt', 'opa-private-key-tests.txt', 'opa-rest-tests.txt', 'opa-jwe-tests.txt']
        for name in names[:-1]:
            path = instance.bin / name; path.write_bytes(b'fixture')
            if name == 'opa': path.chmod(0o755)
        (instance.bin / 'opa-source-inventory.txt').write_text(''.join(digest(b'fixture inventory') + '  /package/opa/' + name + '\n' for name in ('source-files.bin', 'source-tree.bin')))
        with self.assertRaisesRegex(ValueError, 'opa-jwe-tests.txt'):
            instance.compiler_boundary('opa')
        self.assertFalse(instance.manifest.exists())
        (instance.bin / names[-1]).write_bytes(b'fixture')
        instance.compiler_boundary('opa')
        exports = json.loads(instance.manifest.read_text())['phase_exports']['opa']
        self.assertEqual(set(exports), {'bin/' + name for name in names} | {'package/opa/source-files.bin', 'package/opa/source-tree.bin'})
        self.assertEqual(exports['bin/opa']['sha256'], digest(b'fixture'))

    def test_opa_scratch_cleanup_preserves_unrelated_and_rejects_symlinks(self):
        instance = canonical_build.Builder.__new__(canonical_build.Builder)
        instance.path = self.root; instance.work = self.root / 'work'; instance.work.mkdir()
        info = instance.work.stat(); instance.work_identity = (info.st_dev, info.st_ino)
        owned = instance.work / 'opa-files-before'; owned.write_bytes(b'reproducible scratch')
        unrelated = instance.work / 'unrelated'; unrelated.write_bytes(b'keep')
        self.assertEqual(instance.discard_opa_scratch_files(), ['opa-files-before'])
        self.assertEqual(unrelated.read_bytes(), b'keep')
        owned.symlink_to(unrelated)
        with self.assertRaises(ValueError):
            instance.discard_opa_scratch_files()
        self.assertTrue(owned.is_symlink())
        self.assertEqual(unrelated.read_bytes(), b'keep')

    def test_candidate_evidence_rejects_changed_opa_compiler_receipt(self):
        build = self.root / 'builds' / 'one'; build.mkdir(parents=True)
        names = ['bin/opa', 'bin/opa-build.txt', 'bin/opa-source-inventory.txt', 'bin/opa-bundle-tests.txt',
                 'bin/opa-topdown-tests.txt', 'bin/opa-private-key-tests.txt', 'bin/opa-rest-tests.txt',
                 'bin/opa-jwe-tests.txt', 'package/opa/source-files.bin', 'package/opa/source-tree.bin']
        exports = {}
        for name in names:
            path = build / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b'fixture')
            exports[name] = {'sha256': digest(b'fixture'), 'mode': path.stat().st_mode & 0o7777}
        source = {'revision': 'a' * 40}
        record = {'source': source, 'status': 'built', 'build_mode': 'canonical-container',
                  'binaries': {'opa': digest(b'fixture')}, 'phase_exports': {'opa': exports},
                  'images': {'opa': {'archive_origin': 'verified-vendor-base-reconstruction-v1'}}}
        manifest = build / 'manifest.json'; manifest.write_text(json.dumps(record))
        subject = {'source': source, 'builds': {'one': {'path': 'builds/one/manifest.json', 'sha256': digest(manifest.read_bytes())}}}
        candidate_evidence.build_record(subject, self.root, 'one')
        (build / 'package/opa/source-files.bin').write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'OPA compiler evidence'):
            candidate_evidence.build_record(subject, self.root, 'one')


if __name__ == '__main__':
    unittest.main()
