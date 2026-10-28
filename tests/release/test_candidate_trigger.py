"""Evaluate the authored job conditions against trusted and untrusted events.

This tests event selection only, not execution by GitHub or signature validity.
"""
import argparse
import ast
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('trigger_retained_consumer', ROOT / 'scripts/verify-retained-candidate.py')
consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(consumer)
from resource_admission import load_policy


def job_block(job):
    workflow = (ROOT / '.github/workflows/ci.yml').read_text()
    return re.split(r'^  [a-zA-Z][a-zA-Z0-9_-]*:\n', workflow.split('  ' + job + ':\n', 1)[1], maxsplit=1, flags=re.MULTILINE)[0]


def condition(job):
    match = re.search(r'^    if: (.+)$', job_block(job), re.MULTILINE)
    if not match:
        raise AssertionError('job condition missing')
    return match.group(1)


def github_equal(left, right):
    if isinstance(left, str) and isinstance(right, str):
        return left.casefold() == right.casefold()
    if type(left) is type(right):
        return left == right
    # GitHub's loose equality coerces differing scalar types to numbers. This
    # matters for absent outputs: null and the empty string both coerce to zero.
    def number(value):
        if value is None:
            return 0
        if isinstance(value, (int, float)):
            return value
        if isinstance(value, str):
            if not value:
                return 0
            try:
                parsed = json.loads(value)
                if type(parsed) in (int, float):
                    return parsed
            except ValueError:
                pass
        return math.nan
    return number(left) == number(right)


class GitHubComparison(ast.NodeTransformer):
    def visit_Compare(self, node):
        if len(node.ops) != 1 or not isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            raise AssertionError('unsupported condition comparison')
        operation = 'github_equal' if isinstance(node.ops[0], ast.Eq) else 'github_not_equal'
        return ast.copy_location(ast.Call(func=ast.Name(id=operation, ctx=ast.Load()), args=[node.left, node.comparators[0]], keywords=[]), node)


def step_shell(job, step):
    block = job_block(job).split('      - name: ' + step + '\n', 1)[1].split('\n      - ', 1)[0]
    return textwrap.dedent(block.split('        run: |\n', 1)[1]).strip()


def selected(job, *, event='push', repository='5dg/nex-os', ref='refs/heads/main', message='[qualify-candidate] Final reviewed candidate', manual=False, subject='a' * 64):
    values = {
        'github.event.head_commit.message': message,
        'github.repository': repository, 'github.event_name': event, 'github.ref': ref,
        'inputs.canonical_candidate': manual,
        'needs.canonical-candidate.outputs.subject_sha256': subject,
    }
    return evaluate_condition(condition(job), values)


def evaluate_condition(expression, values, *, preceding_steps_succeeded=True):
    # Evaluate the actual YAML expression. Only the authored boolean subset is
    # accepted; new operators/functions require an explicit test-model change.
    for index, (path, value) in enumerate(values.items()):
        expression = expression.replace(path, 'value_' + str(index))
    expression = expression.replace('&&', ' and ').replace('||', ' or ')
    tree = ast.parse(expression, mode='eval')
    permitted = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.Compare, ast.Eq, ast.NotEq,
                 ast.Name, ast.Load, ast.Constant, ast.Call)
    if any(not isinstance(node, permitted) for node in ast.walk(tree)):
        raise AssertionError('unsupported condition syntax')
    tree = ast.fix_missing_locations(GitHubComparison().visit(tree))
    environment = {'value_' + str(index): value for index, value in enumerate(values.values())}
    # GitHub contains is case-insensitive and treats a missing string as empty.
    environment.update(contains=lambda text, needle: needle.casefold() in (text or '').casefold(), always=lambda: True,
                       success=lambda: preceding_steps_succeeded,
                       github_equal=github_equal, github_not_equal=lambda left, right: not github_equal(left, right))
    return bool(eval(compile(tree, '<authored workflow condition>', 'eval'), {'__builtins__': {}}, environment))


class CandidateTriggerTests(unittest.TestCase):
    def test_reviewed_main_opt_in_and_manual_dispatch_run_both_jobs(self):
        for job in ('canonical-candidate', 'candidate-origin'):
            with self.subTest(job=job):
                self.assertTrue(selected(job))
                self.assertTrue(selected(job, event='workflow_dispatch', manual=True, message=None))

    def test_untrusted_or_unselected_events_cannot_run_either_job(self):
        cases = [
            {'event': 'pull_request'}, {'event': 'pull_request_target'}, {'event': 'workflow_run'},
            {'repository': 'other/nex-os'}, {'ref': 'refs/heads/feature'}, {'ref': 'refs/tags/main'},
            {'event': 'workflow_dispatch', 'manual': False},
            {'event': 'workflow_dispatch', 'manual': True, 'ref': 'refs/heads/feature'},
            {'message': 'Routine checkpoint'}, {'message': None},
            {'message': 'Routine checkpoint', 'manual': True},
        ]
        for job in ('canonical-candidate', 'candidate-origin'):
            for case in cases:
                with self.subTest(job=job, event=case):
                    self.assertFalse(selected(job, **case))

    def test_origin_requires_a_real_producer_subject_even_when_trigger_selected(self):
        self.assertTrue(selected('canonical-candidate', subject=''))
        self.assertFalse(selected('candidate-origin', subject=''))
        self.assertFalse(selected('candidate-origin', event='workflow_dispatch', manual=True, subject=''))
        self.assertFalse(selected('candidate-origin', subject=None))

    def test_case_variants_may_select_a_job_but_exact_first_guard_denies_admission(self):
        for job in ('canonical-candidate', 'candidate-origin'):
            steps = job_block(job).split('    steps:\n', 1)[1]
            self.assertTrue(steps.startswith('      - name: Require exact trusted main\n'))
            shell = step_shell(job, 'Require exact trusted main')
            self.assertNotIn('${{', shell, 'event values must never become shell source')
            self.assertIn('"$GITHUB_REPOSITORY"', shell)
            self.assertIn('"$GITHUB_REF"', shell)
            for repository, ref in [('5dg/nex-os', 'refs/heads/main'), ('5dg/nex-os', 'refs/heads/Main'), ('5DG/NEX-OS', 'refs/heads/main')]:
                with self.subTest(job=job, repository=repository, ref=ref):
                    self.assertTrue(selected(job, repository=repository, ref=ref))
                    result = subprocess.run(['bash', '-c', shell], env={**os.environ, 'GITHUB_REPOSITORY': repository, 'GITHUB_REF': ref}, capture_output=True, timeout=5)
                    self.assertEqual(result.returncode == 0, repository == '5dg/nex-os' and ref == 'refs/heads/main')
            self.assertTrue(selected(job, message='[QUALIFY-CANDIDATE] Final reviewed candidate'))
        for line in job_block('canonical-candidate').splitlines():
            if line.strip().startswith('if: always()'):
                self.assertIn("steps.trusted_main.outcome == 'success'", line, 'failed exact admission must not run always-on artifact steps')

    def test_retained_consumer_accepts_exact_push_source_without_relaxing_origin(self):
        args = argparse.Namespace(run_id=17, artifact_id=29, source_revision='a' * 40)
        run = {'id': 17, 'head_sha': args.source_revision, 'head_branch': 'main', 'event': 'push',
               'path': '.github/workflows/ci.yml', 'repository': {'full_name': '5dg/nex-os'},
               'head_repository': {'full_name': '5dg/nex-os'}, 'status': 'completed', 'conclusion': 'success'}
        artifact = {'id': 29, 'name': 'alpha04-candidate-subject', 'expired': False,
                    'workflow_run': {'id': 17, 'head_sha': args.source_revision, 'head_branch': 'main'},
                    'digest': 'sha256:' + 'b' * 64}
        self.assertEqual(consumer.validate_metadata(run, artifact, args), 'b' * 64)
        for field, value in (('event', 'pull_request'), ('head_branch', 'feature'), ('head_sha', 'c' * 40)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                consumer.validate_metadata({**run, field: value}, artifact, args)


class ExecutionMetadataRetentionTests(unittest.TestCase):
    def retention(self):
        return job_block('canonical-candidate').split('      - name: Retain non-secret candidate execution metadata\n', 1)[1]

    def test_failure_metadata_requires_exact_trusted_admission_but_not_subject_success(self):
        expression = re.search(r'^        if: (.+)$', self.retention(), re.MULTILINE).group(1)
        for outcome in ('success', 'failure', 'skipped', 'cancelled', None):
            for succeeded in (False, True):
                with self.subTest(outcome=outcome, succeeded=succeeded):
                    self.assertEqual(evaluate_condition(expression, {'steps.trusted_main.outcome': outcome},
                        preceding_steps_succeeded=succeeded), outcome == 'success')
        self.assertFalse(selected('canonical-candidate', event='pull_request'))
        self.assertFalse(selected('canonical-candidate', message='Routine checkpoint'))
        self.assertFalse(selected('canonical-candidate', ref='refs/heads/feature'))

    def test_exact_metadata_allowlist_excludes_private_and_large_payloads(self):
        retained = self.retention()
        paths = retained.split('          path: |\n', 1)[1].split('          if-no-files-found:', 1)[0]
        actual = [line.strip() for line in paths.splitlines() if line.strip()]
        relative = ['candidate.json', 'release-manifest.json', 'pipeline.log', 'reproducibility.json',
                    '*admission*.json', 'evidence/*admission*.json',
                    'evidence/dom-browser-*.log', 'evidence/qualification-*.log',
                    'evidence/browser-*/dom/browser-results.json',
                    'evidence/browser-*/operator/browser-results.json',
                    'evidence/browser-*/revocation/browser-results.json',
                    'evidence/browser-*/fixture-inputs.json',
                    'evidence/browser-*/fixture-trust-input.json',
                    'evidence/browser-*/dom/browser-engine.json',
                    'evidence/browser-*/operator/browser-engine.json',
                    'evidence/browser-*/revocation/browser-engine.json',
                    'evidence/browser-dependency-preflight/startup-result.json',
                    'evidence/browser-dependency-preflight/browser-engine.json',
                    'evidence/browser-dependency-preflight/browser-image-id', 'builds/*/manifest.json']
        self.assertEqual(actual, ['/tmp/nex-ci-candidate/' + path for path in relative])
        self.assertIn('          name: alpha04-candidate-execution-metadata\n', retained)
        self.assertIn('          if-no-files-found: error\n', retained)
        self.assertNotIn('**', paths)
        self.assertNotIn('include-hidden-files:', retained)
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            expected = {'candidate.json', 'release-manifest.json', 'pipeline.log', 'reproducibility.json',
                        'bundle-admission-1.json', 'evidence/qualification-admission-1.json',
                        'evidence/dom-browser-123.log', 'evidence/qualification-456.log',
                        'evidence/browser-abc/dom/browser-results.json',
                        'evidence/browser-abc/operator/browser-results.json',
                        'evidence/browser-def/revocation/browser-results.json',
                        'evidence/browser-abc/fixture-inputs.json',
                        'evidence/browser-abc/fixture-trust-input.json',
                        'evidence/browser-abc/dom/browser-engine.json',
                        'evidence/browser-abc/operator/browser-engine.json',
                        'evidence/browser-def/revocation/browser-engine.json',
                        'evidence/browser-dependency-preflight/startup-result.json',
                        'evidence/browser-dependency-preflight/browser-engine.json',
                        'evidence/browser-dependency-preflight/browser-image-id',
                        'builds/one/manifest.json', 'builds/two/manifest.json'}
            excluded = {'private/tls.key', 'backups/database.sql', 'source/go.mod', 'builds/one/bin/control',
                        'evidence/private/secret-admission.json', 'candidate-bundle.tar.gz',
                        'evidence/other-gate-123.log', 'evidence/private/dom-browser-123.log',
                        'evidence/browser-abc/dom/chromium.log', 'evidence/browser-abc/private/browser-engine.json',
                        'evidence/browser-abc/private/fixture-trust-input.json',
                        'evidence/browser-abc/fixture-trust-input.key',
                        'evidence/browser-abc/public-ca.crt', 'evidence/browser-abc/ca.key',
                        'evidence/browser-abc/dom/profile/Cookies', 'evidence/browser-abc/private/browser-results.json',
                        'evidence/browser-dependency-preflight/chromium.log',
                        'evidence/browser-dependency-preflight/profile/Cookies',
                        '.local/browser-private-abc/dom/browser-results.json',
                        'source/evidence/dom-browser-123.log'}
            for name in expected | excluded:
                path = base / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('fixture')
            matched = {str(path.relative_to(base)) for pattern in relative for path in base.glob(pattern)}
            self.assertEqual(matched, expected)


class BrowserDependencyPreflightTests(unittest.TestCase):
    STEP = 'Preflight the pinned browser dependency before cold compilation'

    def test_preflight_runs_after_exact_admission_and_tools_before_cold_pipeline(self):
        block = job_block('canonical-candidate')
        self.assertLess(block.index('Require exact trusted main'), block.index(self.STEP))
        self.assertLess(block.index('Prepare pinned verification tools'), block.index(self.STEP))
        self.assertLess(block.index(self.STEP), block.index('Execute canonical candidate'))
        step = block.split('      - name: ' + self.STEP + '\n', 1)[1].split('\n      - ', 1)[0]
        self.assertNotIn('continue-on-error', step)
        self.assertNotIn('if:', step)
        self.assertIn('--sandbox-mode disabled-fixture-only --sandbox-approval https://github.com/5dg/nex-os/actions/runs/40786456380', step)
        self.assertEqual(step.count('NEX_BROWSER_FIXTURE_NO_SANDBOX=1'), 1)
        self.assertNotIn('--ignore-certificate-errors', step)
        self.assertNotIn('dom-browser', step)

    def test_only_successful_preflight_forwards_an_immutable_image(self):
        valid_image = 'sha256:' + 'a' * 64
        approval = 'https://github.com/5dg/nex-os/actions/runs/40786456380'
        valid_result = {'status': 'passed', 'image_id': valid_image,
                        'effective_sandbox': 'disabled-fixture-only', 'approval_reference': approval}
        cases = [(0, valid_image, valid_result), (1, valid_image, valid_result),
                 (0, 'mutable:tag', valid_result), (0, 'sha256:' + 'a' * 63, valid_result),
                 (0, valid_image + '\nINJECTED=value', valid_result)]
        for field, value in [('status', 'failed'), ('image_id', 'sha256:' + 'b' * 64),
                             ('effective_sandbox', 'native'), ('approval_reference', None),
                             ('approval_reference', 'https://github.com/other/repo/actions/runs/40786456380')]:
            cases.append((0, valid_image, {**valid_result, field: value}))
        for exit_code, image_id, result in cases:
            with self.subTest(exit_code=exit_code, image_id=image_id, result=result), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                script = base / 'source/scripts/browser-dependency-preflight.sh'
                script.parent.mkdir(parents=True)
                script.write_text('set -eu\n[[ "$1" == --output && "$3" == --sandbox-mode && "$4" == disabled-fixture-only && "$5" == --sandbox-approval && "$6" == https://github.com/5dg/nex-os/actions/runs/40786456380 ]]\nmkdir -p "$2"\nprintf "%s\\n" "$FIXTURE_IMAGE" > "$2/browser-image-id"\nprintf "%s\\n" "$FIXTURE_RESULT" > "$2/startup-result.json"\nexit "$FIXTURE_EXIT"\n')
                environment = base / 'github-env'
                shell = step_shell('canonical-candidate', self.STEP).replace('/tmp/nex-ci-candidate', str(base))
                completed = subprocess.run(['bash', '-c', shell], capture_output=True, timeout=5,
                    env={**os.environ, 'GITHUB_ENV': str(environment), 'FIXTURE_IMAGE': image_id,
                         'FIXTURE_EXIT': str(exit_code), 'FIXTURE_RESULT': json.dumps(result)})
                expected = exit_code == 0 and image_id == valid_image and result == valid_result
                self.assertEqual(completed.returncode == 0, expected)
                if expected:
                    self.assertEqual(environment.read_text(), 'NEX_BROWSER_FIXTURE_IMAGE=' + image_id + '\nNEX_BROWSER_FIXTURE_NO_SANDBOX=1\n')
                else:
                    self.assertFalse(environment.exists(), 'failed or malformed startup must not export a fixture')


class OriginBundleRetentionTests(unittest.TestCase):
    def retention(self):
        return job_block('candidate-origin').split('      - name: Retain the separate signed origin bundle\n', 1)[1]

    def test_only_successful_attestation_with_a_bundle_can_be_retained(self):
        expression = re.search(r'^        if: (.+)$', self.retention(), re.MULTILINE).group(1)
        for succeeded in (False, True):
            for outcome in ('success', 'failure', 'cancelled', 'skipped', None):
                for bundle in ('/tmp/generated-attestation.json', '', None):
                    with self.subTest(succeeded=succeeded, outcome=outcome, bundle=bundle):
                        actual = evaluate_condition(expression, {'steps.attest.outcome': outcome,
                            'steps.attest.outputs.bundle-path': bundle}, preceding_steps_succeeded=succeeded)
                        self.assertEqual(actual, succeeded and outcome == 'success' and bool(bundle))

    def test_origin_retains_exact_action_output_separately_from_unchanged_subject(self):
        block = job_block('candidate-origin')
        attest = block.split('      - name: Attest build and evidence origin; this is not release approval\n', 1)[1].split('\n      - ', 1)[0]
        self.assertIn('        id: attest\n', attest)
        self.assertIn('actions/attest-build-provenance@96278af6caaf10aea03fd8d33a09a777ca52d62f', attest)
        self.assertIn('          subject-path: /tmp/retained-candidate/candidate-bundle.tar.gz', attest)
        retained = self.retention()
        self.assertIn('actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02', retained)
        self.assertIn('          name: alpha04-candidate-origin\n', retained)
        self.assertIn('          path: ${{ steps.attest.outputs.bundle-path }}\n', retained)
        self.assertIn('          if-no-files-found: error\n', retained)
        self.assertIn('          retention-days: 30\n', retained)
        self.assertNotIn('run:', retained, 'retaining origin must not mutate the attested subject')
        self.assertNotIn('overwrite:', retained)
        self.assertIn('          name: alpha04-candidate-subject\n', job_block('canonical-candidate'))
        self.assertLess(block.index('Bind the downloaded subject'), block.index('        id: attest\n'))
        self.assertLess(block.index('        id: attest\n'), block.index('Retain the separate signed origin bundle'))


class WorkflowAdmissionPolicyTests(unittest.TestCase):
    def fixture(self, base):
        capture = base / 'candidate'
        source = capture / 'source'
        source.mkdir(parents=True)
        candidate = capture / 'candidate.json'
        candidate.write_text(json.dumps({'source': {'revision': 'a' * 40, 'inputs': {'sha256': 'b' * 64}}}))
        policy = base / 'reviewed-policy.json'
        tools = base / 'tools'
        tools.mkdir()
        docker = tools / 'docker'
        docker.write_text('#!' + sys.executable + '\nimport os,sys,json\n'
                          "assert sys.argv[1:] == ['--host=unix:///var/run/docker.sock', 'info', '--format', '{{json .Driver}}']\n"
                          "assert not any(key in os.environ for key in ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'))\n"
                          "print(json.dumps('overlay2'))\n")
        docker.chmod(0o755)
        environment = base / 'github-env'
        env = {**os.environ, 'GITHUB_SHA': 'a' * 40, 'GITHUB_ENV': str(environment),
               'PATH': str(tools) + os.pathsep + os.environ['PATH'],
               'DOCKER_HOST': 'tcp://unrelated.invalid:2375', 'DOCKER_CONTEXT': 'unrelated', 'DOCKER_TLS_VERIFY': '1'}
        shell = step_shell('canonical-candidate', 'Record reviewed measured second-build admission').splitlines()
        self.assertEqual(shell[0], "python3 - <<'PYCODE'")
        self.assertEqual(shell[-1], 'PYCODE')
        code = '\n'.join(shell[1:-1])
        # Execute the actual authored policy code; remap only fixture file paths.
        code = code.replace("'/tmp/nex-ci-candidate/candidate.json'", repr(str(candidate)))
        code = code.replace("'/tmp/nex-ci-second-build-policy.json'", repr(str(policy)))
        return code, env, source, policy, environment

    def test_policy_precedes_build_and_binds_exact_source_driver_and_reviewed_budgets(self):
        block = job_block('canonical-candidate')
        self.assertLess(block.index('Capture the exact trusted main source'), block.index('Record reviewed measured second-build admission'))
        self.assertLess(block.index('Record reviewed measured second-build admission'), block.index('Prepare pinned verification tools'))
        self.assertLess(block.index('Record reviewed measured second-build admission'), block.index('Execute canonical candidate'))
        with tempfile.TemporaryDirectory() as temporary:
            code, env, source, policy, environment = self.fixture(Path(temporary))
            result = subprocess.run([sys.executable, '-c', code], env=env, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(stat.S_IMODE(policy.stat().st_mode), 0o600)
            loaded = load_policy(policy, source, 'b' * 64, 'overlay2')['record']
            self.assertEqual(loaded['minimum_estimated_peak_additional_bytes'], 8 * 1024 ** 3)
            self.assertEqual(loaded['safety_margin_bytes'], 2 * 1024 ** 3)
            self.assertEqual(loaded['reserve_bytes'], 2 * 1024 ** 3)
            self.assertEqual(loaded['approval']['record'], 'docs/architecture/ALPHA04_RELEASE_CONTRACT.md#measured-second-build-admission; root review 2026-10-28; trusted main ' + 'a' * 40)
            self.assertEqual(environment.read_text(), 'NEX_CANONICAL_SECOND_ADMISSION_POLICY=' + str(policy) + '\n')
            before = policy.read_bytes()
            repeated = subprocess.run([sys.executable, '-c', code], env=env, capture_output=True, timeout=10)
            self.assertNotEqual(repeated.returncode, 0, 'an old policy must never be replaced silently')
            self.assertEqual(policy.read_bytes(), before)

    def test_different_captured_revision_cannot_create_approval_or_export_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, env, source, policy, environment = self.fixture(Path(temporary))
            result = subprocess.run([sys.executable, '-c', code], env={**env, 'GITHUB_SHA': 'c' * 40}, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'Captured source differs', result.stderr)
            self.assertFalse(policy.exists())
            self.assertFalse(environment.exists())


if __name__ == '__main__':
    unittest.main()
