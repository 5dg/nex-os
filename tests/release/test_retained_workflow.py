"""Exercise the exact hosted guard and bounded receipt-export code."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

WORKFLOW = Path(__file__).resolve().parents[2] / '.github/workflows/verify-retained.yml'


def step_body(name, next_name):
    workflow = WORKFLOW.read_text()
    step = workflow.split('- name: ' + name, 1)[1].split('- name: ' + next_name, 1)[0]
    return textwrap.dedent(step.split('run: |', 1)[1].split('\n      - uses:', 1)[0]).strip()


class RetainedWorkflowTests(unittest.TestCase):
    def test_guard_accepts_only_exact_main_and_bounded_identifiers(self):
        guard = step_body('Require exact trusted main and bounded identifiers', 'Install checksum-pinned attestation verifier')
        valid = {'GITHUB_REPOSITORY': '5dg/nex-os', 'GITHUB_REF': 'refs/heads/main',
                 'GITHUB_EVENT_NAME': 'workflow_dispatch', 'INPUT_RUN_ID': '17',
                 'INPUT_ARTIFACT_ID': '29', 'INPUT_SOURCE_REVISION': 'a' * 40,
                 'INPUT_SUBJECT_SHA256': 'b' * 64}
        def check(values):
            with tempfile.TemporaryDirectory() as tmp:
                output_path = Path(tmp) / 'github-env'
                output = str(output_path)
                result = subprocess.run(['bash', '-c', guard], env={**os.environ, **values, 'GITHUB_ENV': output}, capture_output=True, timeout=10)
                return result.returncode, output_path.read_text() if output_path.exists() else ''
        expected = ('INPUT_RUN_ID=17\nINPUT_ARTIFACT_ID=29\nINPUT_SOURCE_REVISION=' + 'a' * 40 +
                    '\nINPUT_SUBJECT_SHA256=' + 'b' * 64 + '\n')
        self.assertEqual(check(valid), (0, expected))
        for key, value in [('GITHUB_REPOSITORY', '5DG/nex-os'), ('GITHUB_REF', 'refs/heads/other'),
                           ('GITHUB_EVENT_NAME', 'push'), ('INPUT_RUN_ID', '0'),
                           ('INPUT_ARTIFACT_ID', '29;touch /tmp/not-executed'),
                           ('INPUT_SOURCE_REVISION', 'a' * 39), ('INPUT_SUBJECT_SHA256', 'B' * 64)]:
            with self.subTest(key=key, value=value):
                self.assertNotEqual(check({**valid, key: value})[0], 0)

        message = ('Release verification [verify-retained]\n\nproducer_run_id=17\nartifact_id=29\n'
                   'source_revision=' + 'a' * 40 + '\nsubject_sha256=' + 'b' * 64 + '\n')
        push = {**valid, 'GITHUB_EVENT_NAME': 'push', 'EVENT_HEAD_MESSAGE': message,
                'INPUT_RUN_ID': '', 'INPUT_ARTIFACT_ID': '', 'INPUT_SOURCE_REVISION': '', 'INPUT_SUBJECT_SHA256': ''}
        self.assertEqual(check(push), (0, expected))
        for changed in [message.replace('[verify-retained]', '[other]'),
                        message + 'artifact_id=30\n',
                        message.replace('artifact_id=29', 'artifact_id=29;touch /tmp/not-executed'),
                        message.replace('source_revision=' + 'a' * 40, 'source_revision=' + 'a' * 39),
                        message + '[verify-retained]\n']:
            with self.subTest(message=changed):
                code, output = check({**push, 'EVENT_HEAD_MESSAGE': changed})
                self.assertNotEqual(code, 0)
                self.assertEqual(output, '')

    def test_receipt_export_does_not_include_remote_metadata_or_raw_errors(self):
        script = step_body('Bound and retain non-secret verification receipts', 'Retain the bounded verification receipt')
        lines = script.splitlines()
        start, end = lines.index("python3 - <<'PY'"), lines.index('PY')
        code = '\n'.join(lines[start + 1:end])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'receipt'
            public = Path(tmp) / 'public'
            root.mkdir()
            proof = b'{"statement": "secret-fixture-marker"}\n'
            (root / 'origin.verified.json').write_bytes(proof)
            (root / 'origin.json').write_text(json.dumps({'origin_verification': 'passed',
                'verified_statements_sha256': hashlib.sha256(proof).hexdigest(),
                'source_revision': 'a' * 40, 'subject_sha256': 'b' * 64,
                'exit_code': 0, 'self_hosted_runners_denied': True,
                'repository': '5dg/nex-os', 'workflow': '5dg/nex-os/.github/workflows/ci.yml',
                'source_ref': 'refs/heads/main', 'verifier': {'version': '2.103.3',
                    'binary_sha256': 'b768184570b12536be4ac1528893f6340d1c6a7b40b56ad45bca9cd0e87ad34d'},
                'untrusted_extra': 'secret-fixture-marker'}))
            (root / 'completed-run-receipt.json').write_text(json.dumps({
                'repository': '5dg/nex-os', 'hosted_ci': 'failed', 'release_approval': False,
                'origin_verification': 'passed', 'workflow_run_id': 17, 'artifact_id': 29,
                'source_revision': 'a' * 40, 'subject_sha256': 'b' * 64,
                'retained_archive_sha256': 'c' * 64, 'durable_retention': 'passed',
                'synthetic_qualification_gate': 'blocked',
                'inner_artifacts_verified': True, 'inner_artifact_count': 1, 'inner_artifact_bytes': 22,
                'artifact_map_sha256': 'd' * 64, 'release_manifest_sha256': 'e' * 64,
                'internal_checks': {'qualification': 'passed', 'untrusted_extra': 'secret-fixture-marker'},
                'run_metadata': {'potentially_sensitive': 'secret-fixture-marker'},
                'artifact_metadata': {'potentially_sensitive': 'secret-fixture-marker'}}))
            (root / 'origin.error.txt').write_text('secret-fixture-marker')
            code = code.replace("'/tmp/nex-retained-receipt'", repr(str(root)))
            code = code.replace("'/tmp/nex-retained-public'", repr(str(public)))
            environment = {**os.environ, 'VERIFY_OUTCOME': 'failure', 'INPUT_RUN_ID': '17',
                'INPUT_ARTIFACT_ID': '29', 'INPUT_SOURCE_REVISION': 'a' * 40, 'INPUT_SUBJECT_SHA256': 'b' * 64}
            result = subprocess.run(['python3', '-c', code], env=environment, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(sorted(p.name for p in public.iterdir()), ['summary.json'])
            self.assertNotIn('secret-fixture-marker', (public / 'summary.json').read_text())
            self.assertEqual(json.loads((public / 'summary.json').read_text())['verification_step'], 'failure')
            conflicting_public = Path(tmp) / 'conflicting-public'
            conflicting_code = code.replace(repr(str(public)), repr(str(conflicting_public)))
            result = subprocess.run(['python3', '-c', conflicting_code], env={**environment, 'VERIFY_OUTCOME': 'success'}, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Conflicting qualification outcome', result.stderr.decode())
            (root / 'origin.verified.json').unlink()
            missing_public = Path(tmp) / 'missing-proof-public'
            missing_code = code.replace(repr(str(public)), repr(str(missing_public)))
            result = subprocess.run(['python3', '-c', missing_code], env=environment, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Successful origin requires its verified statements', result.stderr.decode())
            self.assertFalse((missing_public / 'summary.json').exists())


if __name__ == '__main__':
    unittest.main()
