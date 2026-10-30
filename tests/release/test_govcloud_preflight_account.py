import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/govcloud-preflight.sh'


class ApprovedAccountPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log = self.root / 'calls.log'
        self.report = self.root / 'report.json'
        aws = self.root / 'aws'
        aws.write_text('''#!/usr/bin/env python3
import json, os, sys
with open(os.environ['FAKE_CALLS'], 'a') as f:
    f.write(' '.join(sys.argv[1:3]) + '\\n')
if sys.argv[1:3] == ['sts', 'get-caller-identity']:
    result = {'Account': os.environ['FAKE_ACCOUNT'], 'Arn': os.environ['FAKE_ARN']}
elif sys.argv[1:3] == ['bedrock', 'get-foundation-model']:
    result = {'modelDetails': {'modelId': 'example.model-v1'}}
elif sys.argv[1:3] == ['ec2', 'describe-vpc-endpoint-services']:
    result = {'ServiceNames': ['example']}
else:
    sys.exit(2)
print(json.dumps(result))
''')
        aws.chmod(0o755)
        self.env = {
            'PATH': str(self.root) + os.pathsep + os.environ.get('PATH', '/usr/bin:/bin'),
            'NEX_GOV_REGION': 'us-gov-west-1',
            'NEX_BEDROCK_MODEL_ID': 'example.model-v1',
            'NEX_APPROVED_ACCOUNT_ID': '123456789012',
            'NEX_PREFLIGHT_REPORT': str(self.report),
            'FAKE_CALLS': str(self.log),
            'FAKE_ACCOUNT': '123456789012',
            'FAKE_ARN': 'arn:aws-us-gov:sts::123456789012:assumed-role/test/session',
        }

    def run_preflight(self):
        return subprocess.run(['bash', str(SCRIPT)], cwd=ROOT, env=self.env,
                              text=True, capture_output=True, timeout=10)

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_missing_or_malformed_approved_account_never_calls_aws(self):
        for value in ('', '12345678901', '12345678901x'):
            with self.subTest(value=value):
                self.env['NEX_APPROVED_ACCOUNT_ID'] = value
                result = self.run_preflight()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.calls(), [])
                self.assertFalse(self.report.exists())

    def test_wrong_caller_account_or_arn_stops_before_inventory(self):
        for account, arn in [
            ('999999999999', 'arn:aws-us-gov:sts::999999999999:assumed-role/test/session'),
            ('123456789012', 'arn:aws-us-gov:sts::999999999999:assumed-role/test/session'),
            ('123456789012', 'arn:aws:sts::123456789012:assumed-role/test/session'),
        ]:
            with self.subTest(account=account, arn=arn):
                self.log.unlink(missing_ok=True)
                self.env.update(FAKE_ACCOUNT=account, FAKE_ARN=arn)
                result = self.run_preflight()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.calls(), ['sts get-caller-identity'])
                self.assertFalse(self.report.exists())

    def test_matching_identity_allows_inventory_but_not_readiness_claim(self):
        result = self.run_preflight()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), ['sts get-caller-identity',
                                        'bedrock get-foundation-model',
                                        'ec2 describe-vpc-endpoint-services'])
        report = json.loads(self.report.read_text())
        self.assertEqual(report['account_id'], '123456789012')
        self.assertIs(report['ready'], False)
        self.assertEqual(report['live_invocation'], 'UNRUN')
        self.assertEqual(report['authorization_scope_review'], 'UNVERIFIED')

    def test_existing_report_is_preserved_and_no_aws_calls_are_made(self):
        self.report.write_text('previous evidence')
        result = self.run_preflight()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.report.read_text(), 'previous evidence')

    def test_dangling_report_symlink_is_rejected(self):
        self.report.symlink_to(self.root / 'missing-target')
        result = self.run_preflight()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])
        self.assertFalse((self.root / 'missing-target').exists())


if __name__ == '__main__':
    unittest.main()
