"""Fixed resource thresholds, actual shared devices, and retained denials."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
import phase_admission as admission


class PhaseAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / 'output'; self.output.mkdir()
        self.docker = self.root / 'docker'; self.docker.mkdir()
        self.record = self.root / 'admission.json'
        self.candidate = {'run_id': '123456abcdef', 'source': {'revision': 'a' * 40,
                          'inputs': {'sha256': 'b' * 64}}, 'builds': {'one': {'sha256': 'c' * 64}}}

    def run_admission(self, free):
        locations = {'output': (self.output, admission.QUALIFICATION_FORECAST),
                     'docker': (self.docker, admission.QUALIFICATION_FORECAST), 'host': (self.root, 0)}
        with patch.object(admission.shutil, 'disk_usage', return_value=shutil._ntuple_diskusage(20 * admission.GIB, 0, free)):
            return admission.admit(self.candidate, 'qualification', locations, {}, self.record)

    def test_shared_device_exact_boundary_admits_one_combined_forecast(self):
        result = self.run_admission(8 * admission.GIB)
        self.assertEqual(result['status'], 'admitted')
        self.assertEqual(len(result['filesystems']), 1)
        group = next(iter(result['filesystems'].values()))
        self.assertEqual(group['minimum_free_bytes'], 8 * admission.GIB)
        self.assertEqual(group['forecast_additional_bytes'], 6 * admission.GIB)
        self.assertEqual(set(group['paths']), {'output', 'docker', 'host'})
        self.assertEqual(result['source_input_sha256'], 'b' * 64)
        self.assertEqual(result['builds'], self.candidate['builds'])
        self.assertEqual(json.loads(self.record.read_text()), result)

    def test_one_byte_below_boundary_retains_denial(self):
        with self.assertRaisesRegex(ValueError, 'resource admission failed'):
            self.run_admission(8 * admission.GIB - 1)
        self.assertEqual(json.loads(self.record.read_text())['status'], 'blocked')
        self.assertEqual(list(self.output.iterdir()), [])

    def test_reserve_only_filesystem_boundary(self):
        for free, success in ((admission.RESERVE, True), (admission.RESERVE - 1, False)):
            with self.subTest(free=free), patch.object(admission.shutil, 'disk_usage',
                    return_value=shutil._ntuple_diskusage(20 * admission.GIB, 0, free)):
                if success:
                    admission.admit(self.candidate, 'bundle', {'temporary': (self.root, 0)}, {}, self.record)
                else:
                    with self.assertRaises(ValueError):
                        admission.admit(self.candidate, 'bundle', {'temporary': (self.root, 0)}, {}, self.record)

    def test_missing_actual_filesystem_denies_without_ancestor_fallback(self):
        with self.assertRaises(ValueError):
            admission.admit(self.candidate, 'qualification', {'docker': (self.root / 'missing', 6 * admission.GIB)}, {}, self.record)
        self.assertEqual(json.loads(self.record.read_text())['status'], 'blocked')

    def test_measurement_failure_is_retained(self):
        with patch.object(admission.shutil, 'disk_usage', side_effect=OSError('measurement failed')):
            with self.assertRaisesRegex(ValueError, 'measurement failed'):
                admission.admit(self.candidate, 'qualification', {'output': (self.output, 6 * admission.GIB)}, {}, self.record)
        self.assertEqual(json.loads(self.record.read_text())['status'], 'blocked')


if __name__ == '__main__':
    unittest.main()
