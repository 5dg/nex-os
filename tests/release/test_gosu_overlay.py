"""Verify frozen downstream gosu input substitution fails before source mutation."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/apply-gosu-overlay.sh'
OVERLAY = ROOT / 'deploy/qualification/gosu'
UPSTREAM_MOD = 'module github.com/tianon/gosu\n\ngo 1.20\n\nrequire (\n\tgithub.com/moby/sys/user v0.1.0\n\tgolang.org/x/sys v0.1.0\n)\n'
UPSTREAM_SUM = '''github.com/moby/sys/user v0.1.0 h1:WmZ93f5Ux6het5iituh9x2zAG7NFY9Aqi49jjE1PaQg=
github.com/moby/sys/user v0.1.0/go.mod h1:fKJhFOnsCN6xZ5gSfbM6zaHGgDJMrqt9/reuj4T7MmU=
golang.org/x/sys v0.1.0 h1:kunALQeHf1/185U1i0GOB/fy1IPRDDpuoOOqRReG57U=
golang.org/x/sys v0.1.0/go.mod h1:oPkhp1MJrh7nUepCBck5+mAzfO9JrbApNNgaTdGDITg=
'''


class GosuOverlayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name); self.source = self.base/'source'; self.source.mkdir()
        (self.source/'go.mod').write_text(UPSTREAM_MOD)
        (self.source/'go.sum').write_text(UPSTREAM_SUM)
        (self.source/'main.go').write_text('// upstream source fixture remains untouched\n')
        self.overlay = self.base/'overlay'; shutil.copytree(OVERLAY, self.overlay)

    def snapshot(self):
        return {path.name:path.read_bytes() for path in self.source.iterdir()}

    def apply(self):
        return subprocess.run(['sh', str(SCRIPT), str(self.overlay)], cwd=self.source, capture_output=True)

    def test_exact_upstream_and_overlay_replace_only_module_inputs(self):
        metadata = json.loads((self.overlay/'upstream-inputs.json').read_text())
        for name in ('go.mod', 'go.sum'):
            self.assertEqual(hashlib.sha256((self.source/name).read_bytes()).hexdigest(), metadata['upstream']['module_inputs'][name])
            self.assertEqual(hashlib.sha256((self.overlay/name).read_bytes()).hexdigest(), metadata['overlay_sha256'][name])
        before = self.snapshot()
        result = self.apply(); self.assertEqual(result.returncode, 0, result.stderr)
        after = self.snapshot()
        self.assertEqual(set(before), set(after))
        self.assertEqual(before['main.go'], after['main.go'])
        for name in ('go.mod', 'go.sum'):
            self.assertEqual(after[name], (self.overlay/name).read_bytes())

    def test_modified_upstream_module_input_rejects_without_mutation(self):
        (self.source/'go.mod').write_text(UPSTREAM_MOD+'// changed upstream\n')
        before = self.snapshot()
        self.assertNotEqual(self.apply().returncode, 0)
        self.assertEqual(self.snapshot(), before)

    def test_replaced_overlay_or_provenance_metadata_rejects_without_mutation(self):
        for name in ('go.mod', 'go.sum', 'upstream-inputs.json'):
            path = self.overlay/name; original = path.read_bytes(); path.write_bytes(original+b'\n')
            before = self.snapshot()
            with self.subTest(name=name):
                self.assertNotEqual(self.apply().returncode, 0)
                self.assertEqual(self.snapshot(), before)
            path.write_bytes(original)

    def test_module_symlink_rejects_without_touching_external_target(self):
        original = self.source/'go.mod'; outside = self.base/'outside.mod'
        original.rename(outside); original.symlink_to(outside)
        self.assertNotEqual(self.apply().returncode, 0)
        self.assertEqual(outside.read_text(), UPSTREAM_MOD)


if __name__ == '__main__': unittest.main()
