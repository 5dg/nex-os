"""The downstream gosu replacement must not discard or mask vendor bytes."""
import io
from pathlib import Path
import sys
import tarfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
import postgres_layer as layer


class PostgresLayerTest(unittest.TestCase):
    def setUp(self):
        self.old, self.new = b'vendor gosu', b'compiled gosu'
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode='w:', format=tarfile.USTAR_FORMAT) as archive:
            for name, data, mode in [('etc/apk/db/installed', b'package inventory', 0o644),
                                     (layer.TARGET, self.old, 0o755),
                                     ('usr/share/data', b'untouched', 0o644)]:
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.uid, info.gid = len(data), mode, 0, 0
                archive.addfile(info, io.BytesIO(data))
        self.raw = out.getvalue()
        self.origins = (patch.object(layer, 'OLD_DIFF_ID', layer.digest(self.raw)),
                        patch.object(layer, 'OLD_GOSU_SHA256', layer.digest(self.old)),
                        patch.object(layer, 'OLD_GOSU_SIZE', len(self.old)))
        for origin in self.origins:
            origin.start()
            self.addCleanup(origin.stop)

    def test_only_executable_bytes_change_and_result_is_repeatable(self):
        result = layer.replace_gosu(self.raw, self.new, layer.digest(self.new))
        self.assertEqual(result, layer.replace_gosu(self.raw, self.new, layer.digest(self.new)))
        with tarfile.open(fileobj=io.BytesIO(result), mode='r:') as archive:
            executable = archive.getmember(layer.TARGET)
            self.assertEqual((executable.mode, executable.uid, executable.gid), (0o755, 0, 0))
            self.assertEqual(archive.extractfile(executable).read(), self.new)
            self.assertEqual(archive.extractfile('etc/apk/db/installed').read(), b'package inventory')
            self.assertEqual(archive.extractfile('usr/share/data').read(), b'untouched')

    def test_vendor_or_compiler_substitution_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'diffID'):
            layer.replace_gosu(self.raw[:-1], self.new, layer.digest(self.new))
        with self.assertRaisesRegex(ValueError, 'replacement'):
            layer.replace_gosu(self.raw, self.new, layer.digest(b'other'))
        with self.assertRaisesRegex(ValueError, 'replacement'):
            layer.replace_gosu(self.raw, self.old, layer.digest(self.old))

    def test_invalid_tar_headers_and_trailer_are_rejected(self):
        header = bytearray(self.raw)
        header[0] ^= 1
        with patch.object(layer, 'OLD_DIFF_ID', layer.digest(header)):
            with self.assertRaisesRegex(ValueError, 'checksum'):
                layer.replace_gosu(bytes(header), self.new, layer.digest(self.new))
        trailer = bytearray(self.raw)
        trailer[-1] = 1
        with patch.object(layer, 'OLD_DIFF_ID', layer.digest(trailer)):
            with self.assertRaisesRegex(ValueError, 'trailer'):
                layer.replace_gosu(bytes(trailer), self.new, layer.digest(self.new))

    def test_duplicate_gosu_member_is_rejected(self):
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode='w:', format=tarfile.USTAR_FORMAT) as archive:
            for _ in range(2):
                info = tarfile.TarInfo(layer.TARGET)
                info.size = len(self.old)
                archive.addfile(info, io.BytesIO(self.old))
        raw = out.getvalue()
        with patch.object(layer, 'OLD_DIFF_ID', layer.digest(raw)):
            with self.assertRaisesRegex(ValueError, 'unexpected original'):
                layer.replace_gosu(raw, self.new, layer.digest(self.new))


if __name__ == '__main__':
    unittest.main()
