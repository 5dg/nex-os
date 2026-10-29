"""Second-build policy and actual first-build metrics; no Docker or disk load."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
from resource_admission import GIB, load_policy, second_admission, summarize_measurements, phase_settings, phase_record_digest, inherit_phase_settings, image_forecast
spec = importlib.util.spec_from_file_location('second_admission_builder', SCRIPTS / 'canonical-build.py')
compiler = importlib.util.module_from_spec(spec); spec.loader.exec_module(compiler)


class SecondBuildAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'; self.source.mkdir()
        self.path = self.root / 'policy.json'
        self.policy = {'schema_version': 1, 'kind': 'measured-second-build-v1',
                       'source_input_sha256': 'a'*64, 'docker_driver': 'vfs',
                       'minimum_estimated_peak_additional_bytes': 8*GIB,
                       'safety_margin_bytes': 2*GIB, 'reserve_bytes': 2*GIB,
                       'approval': {'authority': 'root', 'decision': 'approved',
                                    'record': 'root reviewed fixed formula before execution, fixture'}}
        self.path.write_text(json.dumps(self.policy))
        self.bound = self.load()
        self.candidate = {'source': {'inputs': {'sha256': 'a'*64}}, 'run_id': '123456abcdef',
                          'builds': {'one': {'path': 'builds/one/manifest.json', 'sha256': 'b'*64}}}
        self.docker = {'driver': 'vfs', 'data_root': '/var/lib/docker'}
        self.initial = {'docker_free': 30*GIB, 'temporary_free': 25*GIB}
        self.final = {'docker_free': 26*GIB, 'temporary_free': 23*GIB}
        self.commands = [{'exit_code': 0, 'observed_initial_free': self.initial.copy(),
                          'observed_final_free': self.final.copy(),
                          'observed_minimum_free': {'docker_free': 20*GIB, 'temporary_free': 22*GIB}}]
        self.first = {'source': self.candidate['source'], 'run_id': self.candidate['run_id'],
                      'build_id': 'one', 'build_mode': 'canonical-container', 'status': 'built',
                      'compilation_scratch_discarded': True, 'commands': self.commands,
                      'resource_budget': {'docker': self.docker, 'second_admission_policy': self.bound, 'phase_settings': phase_settings({}),
                                          'measurements': summarize_measurements(self.initial, self.commands, self.final)}}

    def load(self):
        return load_policy(self.path, self.source, 'a'*64, 'vfs')

    def derive(self):
        return second_admission(self.candidate, self.first, 'b'*64, self.bound, self.docker)

    def first_phase_plan(self):
        plan = {'schema_version': 1, 'strategy': 'pinned-containers-bind-outputs',
                'source_input_sha256': 'a'*64, 'docker_driver': 'vfs', 'lead_review': 'approved',
                'docker_minimum_free': 12*GIB, 'temporary_minimum_free': 12*GIB,
                'packaging_image_estimated_peak_additional': {'workspace': 4*GIB, 'postgres': 8*GIB},
                'compiler_cache_evictions': [{'after': 'rust', 'requested': compiler.COMPILERS['rust'], 'image_id': 'sha256:'+'c'*64}]}
        self.first['resource_budget']['reviewed_plan'] = {'sha256': hashlib.sha256(json.dumps(plan, indent=2).encode()).hexdigest(),
                                                        'record_sha256': phase_record_digest(plan), 'record': plan}
        self.first['resource_budget']['phase_settings'] = phase_settings(plan)
        return plan

    def test_phase_inheritance_binds_exact_plan_and_never_inherits_whole_build_floors(self):
        self.first_phase_plan()
        floors = self.derive()['minimum_free'].copy()
        result = inherit_phase_settings(self.candidate, self.first, 'b'*64, self.docker)
        self.assertEqual(result['settings'], self.first['resource_budget']['phase_settings'])
        self.assertEqual(result['original_plan_sha256'], self.first['resource_budget']['reviewed_plan']['sha256'])
        self.assertEqual(result['first_build_manifest_sha256'], 'b'*64)
        self.assertFalse(result['whole_build_floors_inherited'])
        self.assertNotIn('docker_minimum_free', result['settings'])
        self.assertEqual(self.derive()['minimum_free'], floors)

    def test_source_defaults_have_no_external_inheritance(self):
        self.first['resource_budget']['phase_settings'] = phase_settings({})
        self.assertIsNone(inherit_phase_settings(self.candidate, self.first, 'b'*64, self.docker))

    def test_missing_or_substituted_phase_plan_fails_closed(self):
        self.first_phase_plan()
        original = copy.deepcopy(self.first)
        for change in ('missing-plan', 'changed-record', 'missing-record-hash', 'changed-settings', 'changed-source', 'wrong-first-hash'):
            self.first = copy.deepcopy(original)
            budget = self.first['resource_budget']
            digest = 'b'*64
            if change == 'missing-plan': del budget['reviewed_plan']
            elif change == 'changed-record': budget['reviewed_plan']['record']['packaging_image_estimated_peak_additional']['workspace'] += GIB
            elif change == 'missing-record-hash': del budget['reviewed_plan']['record_sha256']
            elif change == 'changed-settings': budget['phase_settings']['compiler_cache_evictions'] = []
            elif change == 'changed-source': self.first['source'] = {'inputs': {'sha256': 'f'*64}}
            else: digest = 'f'*64
            with self.subTest(change=change), self.assertRaises(ValueError):
                inherit_phase_settings(self.candidate, self.first, digest, self.docker)

    def test_unreviewed_phase_budget_below_floor_rejected(self):
        with self.assertRaises(ValueError):
            phase_settings({'packaging_image_estimated_peak_additional': {'workspace': 4*GIB-1}})

    def test_postgres_default_and_reviewed_floor_eight_other_roles_unchanged(self):
        self.assertEqual(image_forecast('postgres', {}), 8*GIB)
        self.assertEqual(image_forecast('postgres', {'postgres': 9*GIB}), 9*GIB)
        for role in ('control', 'guard', 'fixtures', 'workspace'):
            self.assertEqual(image_forecast(role, {}), 6*GIB)
            self.assertEqual(image_forecast(role, {role: 4*GIB}), 4*GIB)
        for budget in (4*GIB, 6*GIB, 8*GIB-1, True):
            with self.subTest(budget=budget), self.assertRaisesRegex(ValueError, 'PostgreSQL >= 8 GiB'):
                phase_settings({'packaging_image_estimated_peak_additional': {'postgres': budget}})

    def test_bound_first_plan_cannot_inherit_previous_postgres_six_gib_floor(self):
        plan = self.first_phase_plan()
        plan['packaging_image_estimated_peak_additional']['postgres'] = 6*GIB
        original = self.first['resource_budget']['reviewed_plan']
        original['record_sha256'] = phase_record_digest(plan)
        original['sha256'] = hashlib.sha256(json.dumps(plan).encode()).hexdigest()
        self.first['resource_budget']['phase_settings']['packaging_image_estimated_peak_additional']['postgres'] = 6*GIB
        with self.assertRaisesRegex(ValueError, 'PostgreSQL >= 8 GiB'):
            inherit_phase_settings(self.candidate, self.first, 'b'*64, self.docker)

    def test_exact_predeclared_policy_is_hashed_from_same_bytes(self):
        self.assertEqual(self.bound['record'], self.policy)
        self.assertEqual(self.bound['sha256'], hashlib.sha256(self.path.read_bytes()).hexdigest())

    def test_formula_uses_observed_peak_plus_margin_and_floor(self):
        result = self.derive()
        self.assertEqual(result['estimated_peak_additional'], {'docker': 12*GIB, 'temporary': 8*GIB})
        self.assertEqual(result['minimum_free'], {'docker': 14*GIB, 'temporary': 10*GIB})
        self.assertEqual(result['first_build_manifest_sha256'], 'b'*64)
        self.assertEqual(result['policy'], self.bound)

    def test_missing_in_source_symlink_or_unreviewed_policy_rejects(self):
        for path in (None, self.root/'missing', Path('relative.json')):
            with self.subTest(path=path), self.assertRaises(ValueError):
                load_policy(path, self.source, 'a'*64, 'vfs')
        inside = self.source/'policy.json'; inside.write_bytes(self.path.read_bytes())
        link = self.root/'link.json'; link.symlink_to(self.path)
        for path in (inside, link):
            with self.subTest(path=path), self.assertRaises(ValueError):
                load_policy(path, self.source, 'a'*64, 'vfs')
        self.policy['approval']['decision'] = 'pending'; self.path.write_text(json.dumps(self.policy))
        with self.assertRaises(ValueError): self.load()

    def test_source_driver_formula_and_type_substitutions_reject(self):
        for name, changed in [('source_input_sha256', 'c'*64), ('docker_driver', 'overlay2'),
                              ('minimum_estimated_peak_additional_bytes', GIB), ('safety_margin_bytes', 0),
                              ('reserve_bytes', 0), ('schema_version', True), ('unknown_override', True)]:
            value = copy.deepcopy(self.policy); value[name] = changed; self.path.write_text(json.dumps(value))
            with self.subTest(name=name), self.assertRaises(ValueError): self.load()

    def test_first_build_source_status_policy_manifest_and_driver_binding_reject(self):
        original = copy.deepcopy(self.first)
        cases = [('source', {}), ('run_id', 'other'), ('build_id', 'two'), ('status', 'failed'),
                 ('build_mode', 'diagnostic'), ('packaging_reconciliation_required', True),
                 ('compilation_scratch_discarded', False)]
        for name, value in cases:
            self.first = copy.deepcopy(original); self.first[name] = value
            with self.subTest(name=name), self.assertRaises(ValueError): self.derive()
        self.first = copy.deepcopy(original)
        self.first['resource_budget']['second_admission_policy']['sha256'] = 'd'*64
        with self.assertRaises(ValueError): self.derive()
        self.first = copy.deepcopy(original); self.first['resource_budget']['docker']['driver'] = 'overlay2'
        with self.assertRaises(ValueError): self.derive()
        self.first = original; self.candidate['builds']['one']['sha256'] = 'e'*64
        with self.assertRaises(ValueError): self.derive()

    def test_missing_or_contradictory_command_observations_reject(self):
        for field in ('observed_initial_free', 'observed_minimum_free', 'observed_final_free'):
            commands = copy.deepcopy(self.commands); del commands[0][field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                summarize_measurements(self.initial, commands, self.final)
        commands = copy.deepcopy(self.commands); commands[0]['observed_minimum_free']['docker_free'] = 27*GIB
        with self.assertRaises(ValueError): summarize_measurements(self.initial, commands, self.final)
        commands = copy.deepcopy(self.commands); commands[0]['exit_code'] = 1
        with self.assertRaises(ValueError): summarize_measurements(self.initial, commands, self.final)
        commands = copy.deepcopy(self.commands); commands[0]['resource_sampling_failed'] = True
        with self.assertRaises(ValueError): summarize_measurements(self.initial, commands, self.final)

    def test_missing_summary_or_changed_peak_cannot_reduce_admission(self):
        for field in ('measured_peak_additional', 'complete', 'final_retained_free', 'initial_free'):
            original = copy.deepcopy(self.first); del self.first['resource_budget']['measurements'][field]
            with self.subTest(field=field), self.assertRaises(ValueError): self.derive()
            self.first = original
        self.first['resource_budget']['measurements']['measured_peak_additional']['docker'] = 0
        with self.assertRaises(ValueError): self.derive()

    def test_first_build_reserve_breach_blocks_second_even_after_cleanup(self):
        self.commands[0]['observed_minimum_free']['docker_free'] = GIB
        self.first['resource_budget']['measurements'] = summarize_measurements(self.initial, self.commands, self.final)
        with self.assertRaises(ValueError): self.derive()

    def builder_fixture(self, free_gib=30, plan=None, existing=False):
        base = self.root / 'candidate'; (base / 'builds/one').mkdir(parents=True)
        first_path = base / 'builds/one/manifest.json'; first_path.write_text(json.dumps(self.first))
        self.candidate['builds']['one']['sha256'] = hashlib.sha256(first_path.read_bytes()).hexdigest()
        if existing: (base / 'builds/two').mkdir()
        plan_path = None
        if plan is not None:
            plan_path = self.root / 'explicit-plan.json'; plan_path.write_text(json.dumps(plan))
        args = SimpleNamespace(candidate=base/'candidate.json', build='two', resource_plan=plan_path,
                               second_admission_policy=self.path)
        with patch.object(compiler, 'load', return_value=(self.candidate,base,self.source)), \
             patch.object(compiler.subprocess, 'check_output', return_value=json.dumps(self.docker)) as docker, \
             patch.object(compiler.shutil, 'disk_usage', return_value=SimpleNamespace(free=free_gib*GIB)):
            try:
                return compiler.Builder(args)
            finally:
                if existing: docker.assert_not_called()
                else: self.assertEqual(docker.call_count, 1, 'Only read-only docker info is permitted before admission')

    def test_second_builder_blocks_insufficient_actual_free_before_compilation(self):
        with self.assertRaisesRegex(ValueError, 'resource admission failed'):
            self.builder_fixture(free_gib=13)
        record = json.loads((self.root/'candidate/builds/two/manifest.json').read_text())
        self.assertEqual(record['status'], 'blocked')
        self.assertEqual(record['resource_budget']['docker_minimum_free'], 14*GIB)
        self.assertEqual(record['commands'], [])

    def test_second_builder_refuses_existing_outputs_without_daemon_call(self):
        with self.assertRaisesRegex(ValueError, 'already exists'):
            self.builder_fixture(existing=True)

    def test_explicit_second_plan_cannot_lower_derived_peak_or_floor(self):
        plan = {'schema_version': 1, 'strategy': 'pinned-containers-bind-outputs',
                'source_input_sha256': 'a'*64, 'docker_driver': 'vfs', 'lead_review': 'approved',
                'docker_minimum_free': 10*GIB, 'docker_estimated_peak_additional': 8*GIB,
                'temporary_minimum_free': 10*GIB, 'temporary_estimated_peak_additional': 8*GIB}
        with self.assertRaisesRegex(ValueError, 'cannot lower'):
            self.builder_fixture(plan=plan)

    def test_explicit_more_conservative_plan_retains_measured_derivation(self):
        plan = {'schema_version': 1, 'strategy': 'pinned-containers-bind-outputs',
                'source_input_sha256': 'a'*64, 'docker_driver': 'vfs', 'lead_review': 'approved',
                'docker_minimum_free': 15*GIB, 'docker_estimated_peak_additional': 13*GIB,
                'temporary_minimum_free': 11*GIB, 'temporary_estimated_peak_additional': 9*GIB}
        builder = self.builder_fixture(plan=plan)
        budget = builder.record['resource_budget']
        self.assertEqual(budget['docker_minimum_free'], 15*GIB)
        self.assertEqual(budget['second_admission']['minimum_free']['docker'], 14*GIB)
        self.assertEqual(budget['second_admission_policy'], self.bound)


if __name__ == '__main__': unittest.main()
