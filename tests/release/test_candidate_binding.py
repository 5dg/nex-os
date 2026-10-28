"""Independent corruption fixtures for candidate/source identity; no Docker/Git."""
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
import source_record
import image_record
import candidate


class SourceBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='nex-candidate-proof-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'source'
        (self.root / 'scripts').mkdir(parents=True)
        (self.root / 'go.mod').write_text('module example.invalid/synthetic\n')
        self.script = self.root / 'scripts' / 'tool.sh'
        self.script.write_text('#!/bin/sh\nexit 0\n')
        self.script.chmod(0o755)
        self.bind()

    def bind(self):
        data = {'schema_version': 1, 'revision': 'a' * 40, 'source_epoch': 1700000000,
                'inputs': source_record.inputs(self.root, canonical=True)}
        source_record.atomic_json(self.root / source_record.COMPANION, data)
        return source_record.identity(self.root, canonical=True)

    def test_gitless_archive_positive_and_source_corruption(self):
        self.assertFalse((self.root / '.git').exists())
        self.assertEqual(self.bind()['revision'], 'a' * 40)
        self.script.write_text('#!/bin/sh\nexit 1\n')
        with self.assertRaises(ValueError):
            source_record.identity(self.root, canonical=True)

    def test_permission_change_is_not_metadata_nondeterminism(self):
        self.script.chmod(0o644)
        with self.assertRaises(ValueError):
            source_record.identity(self.root, canonical=True)

    def test_setuid_mode_substitution_rejected(self):
        self.script.chmod(0o4755)
        with self.assertRaises(ValueError):
            source_record.identity(self.root, canonical=True)

    def test_authored_symlink_and_local_env_rejected(self):
        target = self.base / 'other-file'
        target.write_text('outside source\n')
        self.script.unlink()
        self.script.symlink_to(target)
        with self.assertRaises(ValueError):
            source_record.identity(self.root, canonical=True)
        self.script.unlink()
        self.script.write_text('#!/bin/sh\nexit 0\n')
        self.script.chmod(0o755)
        (self.root / 'scripts' / '.env').write_text('SYNTHETIC=not-a-secret\n')
        with self.assertRaises(ValueError):
            source_record.identity(self.root, canonical=True)

    def tools(self, mode='canonical-container'):
        tools = self.base / 'builds' / 'one' / 'bin'
        tools.mkdir(parents=True)
        binaries = {}
        for name in ('evidence', 'qualification-pki'):
            path = tools / name
            path.write_bytes(('synthetic-' + name).encode())
            binaries[name] = source_record.sha256(path)
        record = tools / 'build-inputs.json'
        source_record.atomic_json(record, {'build_mode': mode, 'inputs': self.bind()['inputs'], 'binaries': binaries})
        return record

    def test_stale_or_symlinked_host_binary_is_rejected(self):
        record = self.tools()
        source_record.verify_artifacts(record, self.root, ('evidence', 'qualification-pki'))
        binary = record.parent / 'evidence'
        original = binary.read_bytes()
        binary.write_bytes(b'different stale binary')
        with self.assertRaises(ValueError):
            source_record.verify_artifacts(record, self.root, ('evidence', 'qualification-pki'))
        binary.unlink()
        target = self.base / 'same-bytes-outside-artifacts'
        target.write_bytes(original)
        binary.symlink_to(target)
        with self.assertRaises(ValueError):
            source_record.verify_artifacts(record, self.root, ('evidence', 'qualification-pki'))

    def test_canonical_start_rejects_host_build_tool_record(self):
        compose = self.root / 'deploy' / 'qualification' / 'compose.yaml'
        compose.parent.mkdir(parents=True)
        compose.write_text(json.dumps({'networks': {'private-link': {'internal': True}}}))
        source = self.bind()
        archive = self.base / 'source.tar'
        with tarfile.open(archive, 'w') as tar:
            tar.add(self.root / 'go.mod', arcname='go.mod')
        record = self.tools(mode='local-host-development')
        build_path = record.parent.parent / 'manifest.json'
        images = {name: {'id': 'sha256:' + str(i) * 64} for i, name in enumerate(candidate.IMAGE_ENV, 1)}
        source_record.atomic_json(build_path, {'source': source, 'build_mode': 'canonical-container',
                                               'status': 'built', 'images': images})
        manifest = self.base / 'candidate.json'
        source_record.atomic_json(manifest, {'schema_version': 1, 'run_id': '123456abcdef',
            'source_directory': 'source', 'source': source,
            'archive': {'path': 'source.tar', 'sha256': source_record.sha256(archive)},
            'primary_project': 'nex-alpha04-123456abcdef', 'restore_project': 'nex-alpha04-123456abcdef-restore',
            'builds': {'one': {'path': 'builds/one/manifest.json', 'sha256': source_record.sha256(build_path)}}})
        with contextlib.redirect_stdout(io.StringIO()):
            candidate.ipam(argparse.Namespace(candidate=manifest, block='10.233.0.0/20'))
            with self.assertRaises(ValueError):
                candidate.environment(argparse.Namespace(candidate=manifest, build='one', restore=False))


class ImagePayloadTests(unittest.TestCase):
    def layer(self, entries):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w') as tar:
            for name, data in entries:
                info = tarfile.TarInfo(name)
                info.mode = 0o644
                info.uid = info.gid = 0
                encoded = data.encode()
                info.size = len(encoded)
                tar.addfile(info, io.BytesIO(encoded))
        return output.getvalue()

    def test_whiteouts_preserve_only_merged_content(self):
        with tempfile.TemporaryDirectory(prefix='nex-image-proof-') as tmp:
            root = Path(tmp)
            archive = root / 'image.tar'
            with tarfile.open(archive, 'w') as saved:
                blobs = {'manifest.json': json.dumps([{'Config': 'config.json', 'Layers': ['one.tar', 'two.tar']}]).encode(),
                         'config.json': b'{}',
                         'one.tar': self.layer([('drop/a', 'old'), ('keep', 'stable'), ('d/old', 'old')]),
                         'two.tar': self.layer([('.wh.drop', ''), ('d/.wh..wh..opq', ''), ('d/new', 'new')])}
                for name, blob in blobs.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(blob)
                    saved.addfile(info, io.BytesIO(blob))
            output = root / 'payload.json'
            result = image_record.payload(archive, output)
            files = json.loads(output.read_text())['files']
            self.assertEqual(set(files), {'keep', 'd/new'})
            self.assertEqual(files['d/new']['sha256'], hashlib.sha256(b'new').hexdigest())
            self.assertEqual(result['entries'], 2)


if __name__ == '__main__':
    unittest.main()
