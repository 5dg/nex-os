"""Final filesystem inode semantics from synthetic OCI layers, without Docker."""
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
import image_record


def regular(name, content=b'A', mode=0o644):
    return (name, tarfile.REGTYPE, content, '', mode)


def link(name, target, kind=tarfile.LNKTYPE, mode=0o644):
    return (name, kind, b'', target, mode)


class HardlinkSemanticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sequence = 0

    def payload(self, layers):
        blobs = {'config.json': b'{}'}
        names = []
        for number, entries in enumerate(layers):
            name = str(number) + '.tar'
            names.append(name)
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode='w') as layer:
                for path, kind, content, target, mode in entries:
                    member = tarfile.TarInfo(path)
                    member.type, member.linkname, member.mode = kind, target, mode
                    member.uid = member.gid = 0
                    member.size = len(content)
                    layer.addfile(member, io.BytesIO(content) if content else None)
            blobs[name] = data.getvalue()
        blobs['manifest.json'] = json.dumps([{'Config': 'config.json', 'Layers': names}]).encode()
        self.sequence += 1
        archive = self.root / (str(self.sequence) + '.tar')
        with tarfile.open(archive, mode='w') as saved:
            for name, content in blobs.items():
                member = tarfile.TarInfo(name)
                member.size = len(content)
                saved.addfile(member, io.BytesIO(content))
        return image_record.payload(archive, self.root / (str(self.sequence) + '.json'))['sha256']

    def test_replacing_target_does_not_replace_older_linked_inode(self):
        old = self.payload([[regular('a'), link('b', 'a')], [regular('a', b'B')]])
        new = self.payload([[regular('a', b'B'), link('b', 'a')]])
        self.assertNotEqual(old, new)  # b is A in the first filesystem and B in the second.

    def test_equivalent_live_aliases_have_creation_order_independent_identity(self):
        first = self.payload([[regular('a'), link('b', 'a')]])
        second = self.payload([[regular('b'), link('a', 'b')]])
        self.assertEqual(first, second)

    def test_identical_separate_files_are_not_one_shared_inode(self):
        shared = self.payload([[regular('a'), link('b', 'a')]])
        separate = self.payload([[regular('a'), regular('b')]])
        self.assertNotEqual(shared, separate)

    def test_whiteout_keeps_surviving_link_content(self):
        survivor = self.payload([[regular('a'), link('b', 'a')], [regular('.wh.a', b'')]])
        standalone = self.payload([[regular('b')]])
        self.assertEqual(survivor, standalone)

    def test_transitive_hardlinks_resolve_existing_regular_inode(self):
        transitive = self.payload([[regular('a'), link('b', 'a'), link('c', 'b')]])
        reordered = self.payload([[regular('c'), link('a', 'c'), link('b', 'a')]])
        self.assertEqual(transitive, reordered)

    def test_root_directory_permissions_are_part_of_identity(self):
        first = self.payload([[('.', tarfile.DIRTYPE, b'', '', 0o755), regular('a')]])
        second = self.payload([[('.', tarfile.DIRTYPE, b'', '', 0o700), regular('a')]])
        self.assertNotEqual(first, second)

    def test_unsupported_or_ambiguous_links_fail_closed(self):
        cases = {
            'missing': [[link('b', 'absent')]],
            'forward': [[link('b', 'a'), regular('a')]],
            'symlink-target': [[link('a', 'elsewhere', tarfile.SYMTYPE), link('b', 'a')]],
            'metadata-mismatch': [[regular('a', mode=0o755), link('b', 'a', mode=0o644)]],
            'self-target': [[regular('a'), link('a', 'a')]],
            'source-in-replaced-subtree': [[regular('a/b'), link('a', 'a/b')]],
            'symlink-ancestor': [[link('d', 'elsewhere', tarfile.SYMTYPE), regular('d/a')]],
            'link-payload': [[regular('a'), ('b', tarfile.LNKTYPE, b'X', 'a', 0o644)]],
        }
        for name, layers in cases.items():
            with self.subTest(case=name), self.assertRaises(ValueError):
                self.payload(layers)


if __name__ == '__main__':
    unittest.main()
