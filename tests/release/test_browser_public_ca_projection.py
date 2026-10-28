"""Exercise the coordinator's exact public-CA projection without any runtime.

The other-user read bit supplies cross-UID access; the runtime coordinator's
separate paired fixture probe verifies the actual UID mismatch in a container.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class PublicCAProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory()
        cls.base = Path(cls.workspace.name)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1',
                        '-subj', '/CN=Public projection test', '-addext', 'basicConstraints=critical,CA:TRUE',
                        '-keyout', str(cls.base / 'private.key'), '-out', str(cls.base / 'root.crt')],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        cls.certificate = (cls.base / 'root.crt').read_bytes()
        cls.private_key = (cls.base / 'private.key').read_bytes()
        subprocess.run(['openssl', 'req', '-x509', '-key', str(cls.base / 'private.key'), '-days', '1',
                        '-subj', '/CN=Not a root', '-addext', 'basicConstraints=critical,CA:FALSE',
                        '-out', str(cls.base / 'leaf.crt')], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=20)
        cls.leaf = (cls.base / 'leaf.crt').read_bytes()
        script = (ROOT / 'scripts/qualification-browser.sh').read_text()
        block = script.split('# BEGIN PUBLIC CA PROJECTION\n', 1)[1].split('# END PUBLIC CA PROJECTION', 1)[0]
        cls.program = block.split("<<'JS'\n", 1)[1].rsplit('\nJS', 1)[0]

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def project(self, content, *, existing=False, symlink=False):
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            source, target, metadata = base / 'source.crt', base / 'public.crt', base / 'identity.json'
            source.write_bytes(content)
            source.chmod(0o600)
            supplied = source
            if symlink:
                supplied = base / 'link.crt'
                supplied.symlink_to(source)
            if existing:
                target.write_bytes(b'preexisting preserved input')
            result = subprocess.run([shutil.which('node'), '--input-type=module', '-', str(supplied), str(target), str(metadata)],
                                    input=self.program, text=True, capture_output=True, timeout=10, umask=0o077)
            self.assertEqual(source.read_bytes(), content)
            self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o600)
            return result, target.read_bytes() if target.exists() else None, stat.S_IMODE(target.stat().st_mode) if target.exists() else None, json.loads(metadata.read_text()) if metadata.exists() else None

    def test_private_coordinator_root_is_projected_readable_across_uids_without_change(self):
        result, data, mode, record = self.project(self.certificate)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(data, self.certificate)
        self.assertEqual(mode, 0o444)
        self.assertTrue(mode & stat.S_IROTH)
        self.assertEqual(record['source_mode'], '600')
        self.assertEqual(record['public_ca_sha256'], hashlib.sha256(self.certificate).hexdigest())

    def test_private_key_or_multiple_certificates_never_project(self):
        for data in (self.private_key, self.certificate + self.private_key, self.certificate * 2, self.leaf, b'invalid', b'x' * (128 * 1024 + 1)):
            with self.subTest(kind=hashlib.sha256(data).hexdigest()):
                result, projected, _, record = self.project(data)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(projected)
                self.assertIsNone(record)

    def test_existing_output_is_not_overwritten(self):
        result, data, _, record = self.project(self.certificate, existing=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(data, b'preexisting preserved input')
        self.assertIsNone(record)

    def test_symlink_source_is_not_followed(self):
        result, data, _, record = self.project(self.certificate, symlink=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(data)
        self.assertIsNone(record)


if __name__ == '__main__':
    unittest.main()
