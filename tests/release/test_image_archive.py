"""Outer timestamp transformation preserves actual bytes/security metadata."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
import image_archive
import image_record


class ImageArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.epoch = 1700000000

    def fixture(self, name='raw.tar', mtime=1700000010, pax=None, duplicate=False, link=False):
        layer_stream = io.BytesIO()
        with tarfile.open(fileobj=layer_stream, mode='w:', format=tarfile.PAX_FORMAT) as layer:
            member = tarfile.TarInfo('usr/lib/vendor-fixture.so'); member.mode = 0o640
            member.uid = 9; member.gid = 10; member.mtime = 37
            content = b'preserve exact vendor bytes'; member.size = len(content)
            member.pax_headers = {'SCHILY.xattr.security.capability': 'opaque-inner-capability'}
            layer.addfile(member, io.BytesIO(content))
        layer_bytes = layer_stream.getvalue(); self.layer_bytes = layer_bytes
        layer_digest = hashlib.sha256(layer_bytes).hexdigest()
        layer_path = 'blobs/sha256/' + layer_digest
        config = json.dumps({'architecture': 'amd64', 'os': 'linux', 'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + layer_digest]}}).encode()
        self.image_id = 'sha256:' + hashlib.sha256(config).hexdigest()
        config_path = 'blobs/sha256/' + self.image_id[7:]
        manifest = json.dumps([{'Config': config_path, 'RepoTags': None, 'Layers': [layer_path]}]).encode()
        path = self.root / name
        with tarfile.open(path, 'w:', format=tarfile.PAX_FORMAT) as archive:
            directory = tarfile.TarInfo('blobs/sha256'); directory.type = tarfile.DIRTYPE
            directory.mode = 0o751; directory.uid = 7; directory.gid = 9; directory.mtime = mtime
            directory.uname = 'preserved-user'; directory.gname = 'preserved-group'
            archive.addfile(directory)
            for entry_name, content in ((config_path, config), (layer_path, layer_bytes), ('manifest.json', manifest)):
                entry = tarfile.TarInfo(entry_name); entry.size = len(content); entry.mode = 0o640
                entry.mtime = mtime; entry.pax_headers = dict(pax or {})
                archive.addfile(entry, io.BytesIO(content))
            if duplicate: archive.addfile(directory)
            if link:
                entry = tarfile.TarInfo('link'); entry.type = tarfile.SYMTYPE; entry.linkname = config_path
                archive.addfile(entry)
        return path

    def test_actual_outputs_identical_with_only_mtime_and_checksum_bytes_changed(self):
        outputs = []
        for name, mtime in (('one', self.epoch + 1), ('two', self.epoch + 2)):
            source = self.fixture(name + '.raw.tar', mtime)
            output = self.root / (name + '.tar')
            report = image_archive.canonicalize(source, output, self.epoch, self.image_id)
            before, after = source.read_bytes(), output.read_bytes()
            permitted = {i for entry in report['members'].values()
                         for i in range(entry['header_offset'] + 136, entry['header_offset'] + 156)}
            self.assertTrue({i for i, pair in enumerate(zip(before, after)) if pair[0] != pair[1]} <= permitted)
            self.assertEqual(len(before), len(after))
            self.assertEqual(report['raw_sha256'], hashlib.sha256(before).hexdigest())
            self.assertEqual(report['emitted_sha256'], hashlib.sha256(after).hexdigest())
            self.assertEqual(report['image_id'], self.image_id)
            outputs.append(after)
        self.assertEqual(outputs[0], outputs[1])

    def test_opaque_non_time_pax_security_metadata_is_preserved(self):
        pax = {'SCHILY.xattr.security.capability': 'opaque-capability', 'SCHILY.acl.access': 'user::rw-', 'vendor.flag': 'preserve'}
        source = self.fixture(pax=pax); output = self.root / 'out.tar'
        report = image_archive.canonicalize(source, output, self.epoch, self.image_id)
        before, after = source.read_bytes(), output.read_bytes()
        permitted = {i for entry in report['members'].values()
                     for i in range(entry['header_offset'] + 136, entry['header_offset'] + 156)}
        self.assertTrue({i for i, pair in enumerate(zip(before, after)) if pair[0] != pair[1]} <= permitted)
        observed = image_archive.inspect(output, self.image_id)
        self.assertEqual(observed['manifest.json']['pax_headers'], pax)
        self.assertEqual(observed['blobs/sha256']['uid'], 7)
        self.assertEqual(observed['blobs/sha256']['mode'], 0o751)

    def test_inner_layer_bytes_timestamps_and_security_payload_are_unchanged(self):
        source = self.fixture(); output = self.root / 'out.tar'
        image_archive.canonicalize(source, output, self.epoch, self.image_id)
        with tarfile.open(output, 'r:') as archive:
            manifest = json.load(archive.extractfile('manifest.json'))[0]
            actual = archive.extractfile(manifest['Layers'][0]).read()
            self.assertEqual(actual, self.layer_bytes)
            with tarfile.open(fileobj=io.BytesIO(actual), mode='r:') as layer:
                self.assertEqual(layer.getmember('usr/lib/vendor-fixture.so').mtime, 37)
        left = image_record.payload(source, self.root / 'before-payload.json')
        right = image_record.payload(output, self.root / 'after-payload.json')
        self.assertEqual(left, right)
        self.assertEqual((self.root / 'before-payload.json').read_bytes(), (self.root / 'after-payload.json').read_bytes())

    def test_existing_canonical_header_is_not_reserialized(self):
        source = self.fixture(mtime=self.epoch); output = self.root / 'out.tar'
        report = image_archive.canonicalize(source, output, self.epoch, self.image_id)
        self.assertEqual(source.read_bytes(), output.read_bytes()); self.assertEqual(report['changes'], [])

    def test_pax_timestamp_override_fails_closed(self):
        source = self.fixture(pax={'mtime': '1700000010.25'}); output = self.root / 'out.tar'
        with self.assertRaisesRegex(ValueError, 'PAX timestamp'):
            image_archive.canonicalize(source, output, self.epoch, self.image_id)
        self.assertFalse(output.exists())

    def test_duplicate_and_link_members_fail_closed(self):
        for name, options in (('duplicate', {'duplicate': True}), ('link', {'link': True})):
            with self.subTest(name=name):
                source = self.fixture(name + '.tar', **options); output = self.root / (name + '-out.tar')
                with self.assertRaises(ValueError): image_archive.canonicalize(source, output, self.epoch, self.image_id)
                self.assertFalse(output.exists())

    def test_config_id_mismatch_fails_before_output_creation(self):
        source = self.fixture(); output = self.root / 'out.tar'
        with self.assertRaisesRegex(ValueError, 'inspected image ID'):
            image_archive.canonicalize(source, output, self.epoch, 'sha256:' + '0' * 64)
        self.assertFalse(output.exists())

    def test_broken_output_symlink_is_not_followed(self):
        source = self.fixture(); output = self.root / 'out.tar'; target = self.root / 'missing'
        output.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'must be new'):
            image_archive.canonicalize(source, output, self.epoch, self.image_id)
        self.assertTrue(output.is_symlink()); self.assertFalse(target.exists())


if __name__ == '__main__':
    unittest.main()
