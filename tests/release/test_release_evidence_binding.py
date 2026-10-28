"""Actual artifact substitution against local comparison; no Docker or Git."""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import candidate
import image_record
import source_record
spec = importlib.util.spec_from_file_location('candidate_evidence', SCRIPTS / 'candidate-evidence.py')
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class ReleaseEvidenceBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / 'source'
        self.source.mkdir()
        (self.source / 'go.mod').write_text('module example.invalid/comparison\n')
        source_record.atomic_json(self.source / source_record.COMPANION, {
            'schema_version': 1, 'revision': 'a' * 40, 'source_epoch': 1700000000,
            'inputs': source_record.inputs(self.source, canonical=True)})
        identity = source_record.identity(self.source, canonical=True)
        archive = self.base / 'source.tar'
        with tarfile.open(archive, 'w') as saved:
            for path in sorted(self.source.iterdir()):
                saved.add(path, arcname=path.name, recursive=False)
        self.manifest = self.base / 'candidate.json'
        self.record = {'schema_version': 1, 'run_id': '123456abcdef', 'source_directory': 'source',
            'source': identity, 'archive': {'path': 'source.tar', 'sha256': source_record.sha256(archive)}, 'builds': {}}
        self.builds = {}
        for name in ('one', 'two'):
            directory = self.base / 'builds' / name
            (directory / 'bin').mkdir(parents=True)
            binaries = {}
            for binary in ('guard-kernel', 'evidence', 'qualification-pki'):
                path = directory / 'bin' / binary
                path.write_bytes(('synthetic ' + binary).encode())
                path.chmod(0o755)
                binaries[binary] = source_record.sha256(path)
            images = {role: self.make_image(directory, role, b'A') for role in candidate.IMAGE_ENV}
            self.builds[name] = {'source': identity, 'status': 'built', 'build_mode': 'canonical-container',
                'binaries': binaries, 'images': images}
            self.save_build(name)
        source_record.atomic_json(self.manifest, self.record)

    def make_image(self, directory, name, content):
        layer_bytes = io.BytesIO()
        with tarfile.open(fileobj=layer_bytes, mode='w') as layer:
            member = tarfile.TarInfo('usr/bin/synthetic')
            member.mode = 0o755
            member.size = len(content)
            layer.addfile(member, io.BytesIO(content))
        layer = layer_bytes.getvalue()
        config = json.dumps({'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + hashlib.sha256(layer).hexdigest()]}}).encode()
        blobs = {'manifest.json': json.dumps([{'Config': 'config.json', 'Layers': ['layer.tar']}]).encode(),
            'config.json': config, 'layer.tar': layer}
        images = directory / 'images'
        images.mkdir(exist_ok=True)
        archive = images / (name + '.tar')
        with tarfile.open(archive, 'w') as saved:
            for path, value in blobs.items():
                member = tarfile.TarInfo(path)
                member.size = len(value)
                saved.addfile(member, io.BytesIO(value))
        payload = image_record.payload(archive, directory / (name + '-payload.json'))
        return {'id': 'sha256:' + hashlib.sha256(config).hexdigest(),
            'layers': ['sha256:' + hashlib.sha256(layer).hexdigest()],
            'archive': {'path': 'images/' + name + '.tar', 'sha256': source_record.sha256(archive)}, 'payload': payload}

    def save_build(self, name):
        path = self.base / 'builds' / name / 'manifest.json'
        source_record.atomic_json(path, self.builds[name])
        self.record['builds'][name] = {'path': str(path.relative_to(self.base)), 'sha256': source_record.sha256(path)}
        source_record.atomic_json(self.manifest, self.record)

    def compare(self):
        with contextlib.redirect_stdout(io.StringIO()):
            return evidence.compare(argparse.Namespace(candidate=self.manifest))

    def test_matching_actual_artifacts_compare_successfully(self):
        self.assertEqual(self.compare(), 0)

    def test_host_diagnostic_record_cannot_be_canonical_comparison(self):
        self.builds['one']['build_mode'] = 'local-host-development'
        self.save_build('one')
        with self.assertRaises(ValueError):
            self.compare()

    def test_exported_binary_substitution_is_rejected(self):
        (self.base / 'builds/two/bin/guard-kernel').write_bytes(b'changed after build')
        with self.assertRaises(ValueError):
            self.compare()

    def test_payload_report_substitution_is_rejected(self):
        path = self.base / 'builds/two/control-payload.json'
        data = json.loads(path.read_text())
        data['files']['usr/bin/synthetic']['sha256'] = '0' * 64
        source_record.atomic_json(path, data)
        with self.assertRaises(ValueError):
            self.compare()

    def test_archive_content_cannot_reuse_stale_recorded_payload_identity(self):
        original = self.builds['two']['images']['control']['payload']
        changed = self.make_image(self.base / 'builds/two', 'control', b'B')
        changed['payload'] = original
        self.builds['two']['images']['control'] = changed
        self.save_build('two')
        with self.assertRaises(ValueError):
            self.compare()

    def test_seal_records_missing_candidate_history_gate_as_unrun(self):
        names = ('qualification', 'proof-parity', 'shutdown', 'packaged-shutdown',
                 'dom-browser', 'vulnerability-scans', 'hosted-ci',
                 'durable-retention', 'provenance-attestation')
        self.record['results'] = [{'name': name, 'status': 'passed'} for name in names]
        source_record.atomic_json(self.manifest, self.record)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(evidence.seal(argparse.Namespace(candidate=self.manifest)), 1)
        release = json.loads((self.base / 'release-manifest.json').read_text())
        self.assertEqual(release['checks']['history-pagination'], 'unrun')
        self.assertEqual(release['release_gate'], 'blocked')


if __name__ == '__main__':
    unittest.main()
