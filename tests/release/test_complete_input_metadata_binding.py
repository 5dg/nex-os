"""Independent source/security-metadata substitutions; no Git or Docker."""
import argparse
import contextlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
import source_record
import image_record
import candidate


class CompleteSourceBindingTests(unittest.TestCase):
    def test_authored_nested_binary_and_target_sources_are_bound(self):
        for relative in ('services/guard-kernel/src/bin/helper.rs',
                         'services/guard-kernel/src/target/helper.rs',
                         'tests/fixtures/bin/fixture.go'):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / 'go.mod').write_text('module example.invalid/fixture\n')
                path = root / relative
                path.parent.mkdir(parents=True)
                path.write_text('original authored source\n')
                original = source_record.inputs(root, canonical=True)
                self.assertIn(relative, original['files'], 'authored input must be covered')
                path.write_text('changed authored source\n')
                changed = source_record.inputs(root, canonical=True)
                self.assertNotEqual(original['sha256'], changed['sha256'])
                path.chmod(0o755)
                mode_changed = source_record.inputs(root, canonical=True)
                self.assertNotEqual(changed['sha256'], mode_changed['sha256'])

    def test_generated_output_roots_do_not_become_authored_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'go.mod').write_text('module example.invalid/fixture\n')
            original = source_record.inputs(root, canonical=True)
            for relative in ('bin/evidence', 'services/guard-kernel/target/debug/guard-kernel'):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'synthetic generated output')
            self.assertEqual(original['sha256'], source_record.inputs(root, canonical=True)['sha256'])

    def test_canonical_identity_rejects_injected_ignored_looking_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'go.mod').write_text('module example.invalid/fixture\n')
            source_record.atomic_json(root / source_record.COMPANION,
                {'schema_version': 1, 'revision': 'a' * 40, 'source_epoch': 1700000000,
                 'inputs': source_record.inputs(root, canonical=True)})
            injected = root / 'bin' / 'compiled-input'
            injected.parent.mkdir()
            injected.write_bytes(b'could influence include_str or embed')
            with self.assertRaises(ValueError):
                source_record.identity(root, canonical=True)

    def test_capture_rejects_tracked_ignored_looking_compiler_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout = root / 'checkout'
            checkout.mkdir()
            archive_bytes = io.BytesIO()
            with tarfile.open(fileobj=archive_bytes, mode='w') as archive:
                for name, content in (
                    ('go.mod', b'module example.invalid/fixture\n'),
                    ('services/guard-kernel/src/lib.rs', b'const X: &str = include_str!("../../../bin/compiled-input");'),
                    ('bin/compiled-input', b'committed compiler input')):
                    member = tarfile.TarInfo(name)
                    member.size = len(content)
                    archive.addfile(member, io.BytesIO(content))
            def git_result(_root, *arguments):
                if arguments[0] == 'status': return ''
                if arguments[0] == 'show': return '1700000000'
                return 'a' * 40
            args = argparse.Namespace(source=checkout, revision='HEAD', run_id='123456abcdef', output=root / 'candidate')
            # Mock only read-only Git responses/archive; no checkout/index mutation.
            with patch.object(candidate, 'git', side_effect=git_result), patch.object(candidate.subprocess, 'check_output', return_value=archive_bytes.getvalue()), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(ValueError):
                    candidate.capture(args)


class SecurityMetadataBindingTests(unittest.TestCase):
    def image_payload(self, root, name, pax_headers):
        layer_bytes = io.BytesIO()
        with tarfile.open(fileobj=layer_bytes, mode='w', format=tarfile.PAX_FORMAT) as layer:
            member = tarfile.TarInfo('usr/bin/synthetic-helper')
            content = b'same executable bytes'
            member.size = len(content)
            member.mode = 0o755
            member.uid = member.gid = 0
            member.pax_headers = pax_headers
            layer.addfile(member, io.BytesIO(content))
        archive = root / (name + '.tar')
        with tarfile.open(archive, mode='w') as saved:
            blobs = {'manifest.json': json.dumps([{'Config': 'config.json', 'Layers': ['layer.tar']}]).encode(),
                     'config.json': b'{}', 'layer.tar': layer_bytes.getvalue()}
            for filename, blob in blobs.items():
                member = tarfile.TarInfo(filename)
                member.size = len(blob)
                saved.addfile(member, io.BytesIO(blob))
        return image_record.payload(archive, root / (name + '.json'))['sha256']

    def test_xattr_or_capability_substitution_changes_identity_or_fails_closed(self):
        for key, value in (('SCHILY.xattr.security.capability', 'fixture-capability-a'),
                           ('LIBARCHIVE.xattr.security.capability', 'Zml4dHVyZS1jYXBhYmlsaXR5'),
                           ('SCHILY.xattr.user.fixture', 'fixture-value-a')):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                baseline = self.image_payload(root, 'baseline', {})
                try:
                    changed = self.image_payload(root, 'changed', {key: value})
                except ValueError:
                    # Unsupported metadata must be rejected, not silently omitted.
                    continue
                self.assertNotEqual(baseline, changed, 'security metadata must not disappear from rootfs identity')
                other = self.image_payload(root, 'other', {key: value + '-different'})
                self.assertNotEqual(changed, other, 'changed metadata value must be bound')

    def test_hardlink_keeps_original_inode_when_target_path_is_replaced(self):
        def layer(entries):
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode='w') as archive:
                for name, content, target in entries:
                    member = tarfile.TarInfo(name)
                    member.mode = 0o644
                    if target is not None:
                        member.type = tarfile.LNKTYPE
                        member.linkname = target
                        archive.addfile(member)
                    else:
                        member.size = len(content)
                        archive.addfile(member, io.BytesIO(content))
            return data.getvalue()
        def image(root, name, layers):
            path = root / (name + '.tar')
            names = [str(i) + '.tar' for i in range(len(layers))]
            blobs = {'manifest.json': json.dumps([{'Config':'config.json','Layers':names}]).encode(), 'config.json':b'{}', **dict(zip(names,layers))}
            with tarfile.open(path, mode='w') as saved:
                for filename, content in blobs.items():
                    member = tarfile.TarInfo(filename)
                    member.size = len(content)
                    saved.addfile(member, io.BytesIO(content))
            return image_record.payload(path, root / (name + '.json'))['sha256']
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            try:
                original_inode = image(root, 'original-inode', [layer([('a', b'A', None), ('b', None, 'a')]), layer([('a', b'B', None)])])
                replacement_inode = image(root, 'replacement-inode', [layer([('a', b'B', None), ('b', None, 'a')])])
            except ValueError:
                return  # Explicit unsupported-hardlink refusal is safe.
            # First image b still links the old A inode. Second image b is B.
            self.assertNotEqual(original_inode, replacement_inode, 'link target path alone loses original inode content')


if __name__ == '__main__':
    unittest.main()
