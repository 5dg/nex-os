"""Actual artifact substitution against local comparison; no Docker or Git."""
import argparse
import contextlib
import hashlib
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import candidate
import image_record
import source_record
spec = importlib.util.spec_from_file_location('candidate_evidence', SCRIPTS / 'candidate-evidence.py')
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class ReleaseEvidenceBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / 'source'
        self.source.mkdir()
        (self.source / 'go.mod').write_text('module example.invalid/comparison\n')
        source_record.atomic_json(self.source / source_record.COMPANION, {
            'schema_version': 1, 'revision': 'a' * 40, 'source_epoch': 1700000000,
            'inputs': source_record.inputs(self.source, canonical=True)})
        identity = source_record.identity(self.source, canonical=True)
        archive = self.base / 'source.tar'
        with tarfile.open(archive, 'w') as saved:
            for path in sorted(self.source.iterdir()):
                saved.add(path, arcname=path.name, recursive=False)
        self.manifest = self.base / 'candidate.json'
        self.record = {'schema_version': 1, 'run_id': '123456abcdef', 'source_directory': 'source',
            'source': identity, 'archive': {'path': 'source.tar', 'sha256': source_record.sha256(archive)}, 'builds': {}}
        self.builds = {}
        for name in ('one', 'two'):
            directory = self.base / 'builds' / name
            (directory / 'bin').mkdir(parents=True)
            binaries = {}
            for binary in ('guard-kernel', 'evidence', 'qualification-pki'):
                path = directory / 'bin' / binary
                path.write_bytes(('synthetic ' + binary).encode())
                path.chmod(0o755)
                binaries[binary] = source_record.sha256(path)
            images = {role: self.make_image(directory, role, b'A') for role in candidate.IMAGE_ENV}
            self.builds[name] = {'source': identity, 'status': 'built', 'build_mode': 'canonical-container',
                'binaries': binaries, 'images': images}
            self.save_build(name)
        source_record.atomic_json(self.manifest, self.record)

    def make_image(self, directory, name, content):
        layer_bytes = io.BytesIO()
        with tarfile.open(fileobj=layer_bytes, mode='w') as layer:
            member = tarfile.TarInfo('usr/bin/synthetic')
            member.mode = 0o755
            member.size = len(content)
            layer.addfile(member, io.BytesIO(content))
        layer = layer_bytes.getvalue()
        config = json.dumps({'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + hashlib.sha256(layer).hexdigest()]}}).encode()
        blobs = {'manifest.json': json.dumps([{'Config': 'config.json', 'Layers': ['layer.tar']}]).encode(),
            'config.json': config, 'layer.tar': layer}
        images = directory / 'images'
        images.mkdir(exist_ok=True)
        archive = images / (name + '.tar')
        with tarfile.open(archive, 'w') as saved:
            for path, value in blobs.items():
                member = tarfile.TarInfo(path)
                member.size = len(value)
                saved.addfile(member, io.BytesIO(value))
        payload = image_record.payload(archive, directory / (name + '-payload.json'))
        return {'id': 'sha256:' + hashlib.sha256(config).hexdigest(),
            'layers': ['sha256:' + hashlib.sha256(layer).hexdigest()],
            'archive': {'path': 'images/' + name + '.tar', 'sha256': source_record.sha256(archive)}, 'payload': payload}

    def save_build(self, name):
        path = self.base / 'builds' / name / 'manifest.json'
        source_record.atomic_json(path, self.builds[name])
        self.record['builds'][name] = {'path': str(path.relative_to(self.base)), 'sha256': source_record.sha256(path)}
        source_record.atomic_json(self.manifest, self.record)

    def compare(self):
        with contextlib.redirect_stdout(io.StringIO()):
            return evidence.compare(argparse.Namespace(candidate=self.manifest))

    def test_matching_actual_artifacts_compare_successfully(self):
        self.assertEqual(self.compare(), 0)

    def test_host_diagnostic_record_cannot_be_canonical_comparison(self):
        self.builds['one']['build_mode'] = 'local-host-development'
        self.save_build('one')
        with self.assertRaises(ValueError):
            self.compare()

    def test_exported_binary_substitution_is_rejected(self):
        (self.base / 'builds/two/bin/guard-kernel').write_bytes(b'changed after build')
        with self.assertRaises(ValueError):
            self.compare()

    def test_payload_report_substitution_is_rejected(self):
        path = self.base / 'builds/two/control-payload.json'
        data = json.loads(path.read_text())
        data['files']['usr/bin/synthetic']['sha256'] = '0' * 64
        source_record.atomic_json(path, data)
        with self.assertRaises(ValueError):
            self.compare()

    def test_archive_content_cannot_reuse_stale_recorded_payload_identity(self):
        original = self.builds['two']['images']['control']['payload']
        changed = self.make_image(self.base / 'builds/two', 'control', b'B')
        changed['payload'] = original
        self.builds['two']['images']['control'] = changed
        self.save_build('two')
        with self.assertRaises(ValueError):
            self.compare()

    def test_seal_records_missing_candidate_history_gate_as_unrun(self):
        names = ('qualification', 'proof-parity', 'shutdown', 'packaged-shutdown',
                 'dom-browser', 'vulnerability-scans', 'hosted-ci',
                 'durable-retention', 'provenance-attestation')
        self.record['results'] = [{'name': name, 'status': 'passed'} for name in names]
        source_record.atomic_json(self.manifest, self.record)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(evidence.seal(argparse.Namespace(candidate=self.manifest)), 1)
        release = json.loads((self.base / 'release-manifest.json').read_text())
        self.assertEqual(release['checks']['history-pagination'], 'unrun')
        self.assertEqual(release['release_gate'], 'blocked')

    def check_command(self, name, command):
        return [sys.executable, str(SCRIPTS / 'candidate-evidence.py'), 'run',
                '--candidate', str(self.manifest), '--name', name, '--', *command]

    def run_outer(self, command):
        return subprocess.run(self.check_command('outer', command), capture_output=True, text=True,
                              env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, timeout=20)

    def test_actual_nested_cli_retains_all_native_gates_and_prior_results(self):
        prior = {'name': 'prior', 'status': 'failed', 'reason': 'retain previous attempted work'}
        self.record['results'] = [prior]
        source_record.atomic_json(self.manifest, self.record)
        commands = [self.check_command(name, [sys.executable, '-c', 'print("checked")'])
                    for name in ('proof-parity', 'shutdown', 'history-pagination')]
        driver = 'import subprocess\n' + '\n'.join('subprocess.run(' + repr(command) + ',check=True)' for command in commands)
        outcome = self.run_outer([sys.executable, '-c', driver])
        self.assertEqual(outcome.returncode, 0, outcome.stderr + outcome.stdout)
        records = json.loads(self.manifest.read_text())['results']
        self.assertEqual(records[0], prior)
        self.assertEqual([row['name'] for row in records], ['prior', 'proof-parity', 'shutdown', 'history-pagination', 'outer'])
        self.assertTrue(all(row['status'] == 'passed' for row in records[1:]))
        self.assertEqual(len(list((self.base / 'evidence').glob('*.json'))), 4)

    def test_actual_nested_cli_retains_child_and_parent_failures(self):
        child = self.check_command('dom-browser', [sys.executable, '-c', 'print("attempted browser check");raise SystemExit(7)'])
        outcome = self.run_outer(child)
        self.assertEqual(outcome.returncode, 1, outcome.stderr)
        records = json.loads(self.manifest.read_text())['results']
        self.assertEqual([row['name'] for row in records], ['dom-browser', 'outer'])
        self.assertEqual([row['status'] for row in records], ['failed', 'failed'])
        self.assertEqual([row['exit_code'] for row in records], [7, 1])

    def test_child_pass_survives_later_parent_failure(self):
        child = self.check_command('dom-browser', [sys.executable, '-c', 'print("checked")'])
        driver = 'import subprocess\nsubprocess.run(' + repr(child) + ',check=True)\nraise SystemExit(9)'
        outcome = self.run_outer([sys.executable, '-c', driver])
        self.assertEqual(outcome.returncode, 1, outcome.stderr)
        records = json.loads(self.manifest.read_text())['results']
        self.assertEqual([row['status'] for row in records], ['passed', 'failed'])
        self.assertEqual(records[-1]['exit_code'], 9)

    def mutate_during_check(self, mutation):
        driver = ('import json\nfrom pathlib import Path\np=Path(' + repr(str(self.manifest)) + ')\n'
                  'data=json.loads(p.read_text())\n' + mutation + '\np.write_text(json.dumps(data))\nprint("attempt retained")')
        outcome = self.run_outer([sys.executable, '-c', driver])
        self.assertEqual(outcome.returncode, 1, outcome.stderr)
        check = json.loads(outcome.stdout)
        self.assertEqual(check['status'], 'failed')
        self.assertIn('post-check candidate validation failed', check['reason'])
        self.assertEqual(check['run_id'], '123456abcdef')
        self.assertEqual(check['build_manifest'], self.record['builds']['one'])
        log = self.base / check['output']['path']
        self.assertIn('attempt retained', log.read_text())
        self.assertEqual(json.loads(log.with_suffix('.json').read_text()), check)
        self.assertNotIn('outer', [row['name'] for row in json.loads(self.manifest.read_text()).get('results', [])])
        return json.loads(self.manifest.read_text())

    def test_mutated_run_binding_is_rejected_without_stale_overwrite(self):
        changed = self.mutate_during_check("data['run_id']='abcdef123456'")
        self.assertEqual(changed['run_id'], 'abcdef123456')

    def test_mutated_build_binding_is_rejected_without_stale_overwrite(self):
        changed = self.mutate_during_check("data['builds']['one']['sha256']='0'*64")
        self.assertEqual(changed['builds']['one']['sha256'], '0' * 64)

    def test_mutated_source_binding_is_rejected_without_stale_overwrite(self):
        changed = self.mutate_during_check("data['source']['revision']='b'*40")
        self.assertEqual(changed['source']['revision'], 'b' * 40)

    def test_changed_physical_build_is_rejected(self):
        binary = self.base / 'builds/one/bin/guard-kernel'
        self.mutate_during_check('Path(' + repr(str(binary)) + ').write_bytes(b"substituted")')
        self.assertEqual(binary.read_bytes(), b'substituted')

    def test_changed_physical_source_is_rejected(self):
        path = self.source / 'go.mod'
        self.mutate_during_check('Path(' + repr(str(path)) + ').write_text("changed source")')
        self.assertEqual(path.read_text(), 'changed source')

    def test_erased_or_replaced_prior_results_are_rejected(self):
        self.record['results'] = [{'name': 'prior', 'status': 'failed'}]
        for mutation in ("data['results']=[]", "data['results'][0]['status']='passed'"):
            with self.subTest(mutation=mutation):
                source_record.atomic_json(self.manifest, self.record)
                changed = self.mutate_during_check(mutation)
                self.assertNotEqual(changed['results'], self.record['results'])

    def sealed_bundle(self, free=100 * 1024 ** 3):
        with patch('phase_admission.shutil.disk_usage', return_value=shutil._ntuple_diskusage(free * 2, 0, free)), contextlib.redirect_stdout(io.StringIO()):
            return evidence.bundle(argparse.Namespace(candidate=self.manifest, output=self.base / 'bundle.tar.gz'))

    def seal_for_bundle(self):
        with contextlib.redirect_stdout(io.StringIO()):
            evidence.seal(argparse.Namespace(candidate=self.manifest))

    def test_bundle_bound_covers_exact_pax_padding_and_sparse_logical_bytes(self):
        directory = self.base / 'evidence'; directory.mkdir()
        sparse = directory / ('long-' + 'x' * 115 + '-é.log')
        with sparse.open('wb') as stream:
            stream.truncate(1024 ** 2)
        (directory / 'incompressible.bin').write_bytes(os.urandom(256 * 1024))
        self.seal_for_bundle()
        self.assertEqual(self.sealed_bundle(), 0)
        record = json.loads(next(self.base.glob('bundle-admission-*.json')).read_text())
        output = self.base / 'bundle.tar.gz'
        self.assertGreaterEqual(record['details']['logical_file_bytes'], 1024 ** 2)
        self.assertEqual(len(gzip.decompress(output.read_bytes())), record['details']['tar_bytes_including_headers_padding'])
        self.assertLess(output.stat().st_size, record['details']['gzip_upper_bound_bytes'])
        with tarfile.open(output, 'r:gz') as saved:
            self.assertEqual(saved.getmember(str(sparse.relative_to(self.base))).size, 1024 ** 2)

    def test_bundle_denial_preserves_raw_seal_and_never_creates_archive(self):
        self.seal_for_bundle()
        before = (self.base / 'release-manifest.json').read_bytes()
        with self.assertRaisesRegex(ValueError, 'resource admission failed'):
            self.sealed_bundle(free=2 * 1024 ** 3)
        self.assertFalse((self.base / 'bundle.tar.gz').exists())
        self.assertEqual((self.base / 'release-manifest.json').read_bytes(), before)
        self.assertEqual(json.loads(next(self.base.glob('bundle-admission-*.json')).read_text())['status'], 'blocked')

    def test_broken_bundle_output_symlink_is_rejected_without_target_creation(self):
        self.seal_for_bundle()
        target = self.base / 'absent-target.tar.gz'
        output = self.base / 'bundle.tar.gz'
        output.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'already exists'):
            self.sealed_bundle()
        self.assertTrue(output.is_symlink())
        self.assertEqual(output.readlink(), target)
        self.assertFalse(target.exists())
        self.assertFalse(list(self.base.glob('bundle-admission-*.json')))

    def test_exclusive_bundle_create_rejects_symlink_added_after_admission(self):
        self.seal_for_bundle()
        target = self.base / 'preserve-target.tar.gz'
        target.write_bytes(b'preserve existing bytes')
        original = evidence.admit
        def substitute_output(*args, **kwargs):
            record = original(*args, **kwargs)
            (self.base / 'bundle.tar.gz').symlink_to(target)
            return record
        with patch.object(evidence, 'admit', side_effect=substitute_output):
            with self.assertRaises(FileExistsError):
                self.sealed_bundle()
        self.assertEqual(target.read_bytes(), b'preserve existing bytes')
        self.assertTrue((self.base / 'bundle.tar.gz').is_symlink())

    def test_bundle_calculated_capacity_boundary_is_enforced(self):
        self.seal_for_bundle()
        with self.assertRaises(ValueError):
            self.sealed_bundle(free=2 * 1024 ** 3)
        report = json.loads(next(self.base.glob('bundle-admission-*.json')).read_text())
        minimum = report['details']['gzip_upper_bound_bytes'] + 2 * 1024 ** 3
        with self.assertRaisesRegex(ValueError, 'resource admission failed'):
            self.sealed_bundle(free=minimum - 1)
        self.assertFalse((self.base / 'bundle.tar.gz').exists())
        self.assertEqual(self.sealed_bundle(free=minimum), 0)

    def test_sealed_file_mutation_is_rejected_before_bundle_creation(self):
        self.seal_for_bundle()
        (self.base / 'builds/one/control-payload.json').write_bytes(b'changed sealed payload report')
        with self.assertRaisesRegex(ValueError, 'substituted'):
            self.sealed_bundle()
        self.assertFalse((self.base / 'bundle.tar.gz').exists())

    def test_sealed_nonregular_input_is_rejected(self):
        self.seal_for_bundle()
        archive = self.base / 'builds/one/control-payload.json'; archive.unlink(); archive.mkdir()
        with self.assertRaisesRegex(ValueError, 'substituted'):
            self.sealed_bundle()
        self.assertFalse((self.base / 'bundle.tar.gz').exists())

    def test_duplicate_reserved_bundle_member_is_rejected(self):
        self.seal_for_bundle()
        path = self.base / 'release-manifest.json'
        record = json.loads(path.read_text())
        record['artifacts']['release-manifest.json'] = source_record.sha256(path)
        source_record.atomic_json(path, record)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.sealed_bundle()
        self.assertFalse((self.base / 'bundle.tar.gz').exists())

    def test_repeated_json_artifact_key_is_rejected(self):
        self.seal_for_bundle()
        path = self.base / 'release-manifest.json'
        path.write_text(path.read_text().replace('"artifacts": {', '"artifacts": {"duplicate":"one","duplicate":"two",', 1))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.sealed_bundle()

    def test_mutation_after_admission_is_rejected_and_partial_output_retained(self):
        self.seal_for_bundle()
        original = evidence.admit
        def mutate(*args, **kwargs):
            record = original(*args, **kwargs)
            (self.base / 'source.tar').write_bytes(b'changed after admission')
            return record
        with patch.object(evidence, 'admit', side_effect=mutate):
            with self.assertRaisesRegex(ValueError, 'changed after resource admission'):
                self.sealed_bundle()
        self.assertTrue((self.base / 'bundle.tar.gz').exists(), 'partial attempted output must not be deleted')

    def test_qualification_admission_binds_actual_fixed_socket_filesystem(self):
        probe = json.dumps({'driver': 'vfs', 'data_root': str(self.base)})
        with patch.object(evidence.subprocess, 'check_output', return_value=probe) as command, \
                patch('phase_admission.shutil.disk_usage', return_value=shutil._ntuple_diskusage(20 * 1024 ** 3, 0, 8 * 1024 ** 3)), \
                patch.dict(os.environ, {'DOCKER_HOST':'tcp://unrelated', 'DOCKER_CONTEXT':'unrelated'}), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(evidence.admit_qualification(argparse.Namespace(candidate=self.manifest)), 0)
        self.assertEqual(command.call_args.args[0][:3], ['docker', '--host=unix:///var/run/docker.sock', 'info'])
        self.assertNotIn('DOCKER_HOST', command.call_args.kwargs['env'])
        self.assertNotIn('DOCKER_CONTEXT', command.call_args.kwargs['env'])
        record = json.loads(next((self.base / 'evidence').glob('qualification-admission-*.json')).read_text())
        self.assertEqual(record['status'], 'admitted')
        self.assertEqual(record['details']['docker']['data_root'], str(self.base))
        self.assertTrue(any(group['minimum_free_bytes'] == 8 * 1024 ** 3 for group in record['filesystems'].values()))

    def test_failed_docker_filesystem_probe_retains_source_bound_denial(self):
        with patch.object(evidence.subprocess, 'check_output', side_effect=OSError('probe failed')):
            with self.assertRaisesRegex(ValueError, 'admission blocked'):
                evidence.admit_qualification(argparse.Namespace(candidate=self.manifest))
        record = json.loads(next((self.base / 'evidence').glob('qualification-admission-*.json')).read_text())
        self.assertEqual(record['status'], 'blocked')
        self.assertEqual(record['source_input_sha256'], self.record['source']['inputs']['sha256'])

    def test_seal_prunes_exact_unretained_scratch_before_symlink_inspection(self):
        scratch=self.base/'builds/one/work/gosu';scratch.mkdir(parents=True)
        (scratch/'.gitignore').write_text('upstream gosu source')
        (scratch/'.dockerignore').symlink_to('.gitignore')
        package=self.base/'builds/one/package/node_modules';package.mkdir(parents=True)
        (package/'module-link').symlink_to(scratch,target_is_directory=True)
        self.seal_for_bundle()
        record=json.loads((self.base/'release-manifest.json').read_text())
        self.assertFalse(any(name.startswith(('builds/one/work/','builds/one/package/')) for name in record['artifacts']))
        self.assertIn('builds/one/bin/evidence',record['artifacts'])
        self.assertTrue((scratch/'.dockerignore').is_symlink())
        self.assertEqual(self.sealed_bundle(),0)
        with tarfile.open(self.base/'bundle.tar.gz','r:gz') as saved:
            self.assertFalse(any(name.startswith(('builds/one/work/','builds/one/package/')) for name in saved.getnames()))

    def test_seal_prunes_excluded_root_links_without_following_them(self):
        (self.base/'builds/one/work').symlink_to(self.source,target_is_directory=True)
        (self.base/'builds/one/package').symlink_to(self.base/'absent-package',target_is_directory=True)
        self.seal_for_bundle()
        record=json.loads((self.base/'release-manifest.json').read_text())
        self.assertNotIn('builds/one/work',record['artifacts'])
        self.assertNotIn('builds/one/package',record['artifacts'])

    def test_seal_still_rejects_retained_file_and_directory_links(self):
        directory=self.base/'evidence';directory.mkdir()
        for name,target in (('file-link',self.base/'source.tar'),('dir-link',self.source)):
            with self.subTest(name=name):
                link=directory/name;link.symlink_to(target)
                with self.assertRaisesRegex(ValueError,'symlinks'):self.seal_for_bundle()
                link.unlink()

    def test_seal_rejects_optional_top_level_artifact_symlink(self):
        for target in (self.base/'source.tar',self.base/'missing-target'):
            with self.subTest(target=target.name):
                link=self.base/'pipeline.log';link.symlink_to(target)
                with self.assertRaisesRegex(ValueError,'symlinks'):
                    self.seal_for_bundle()
                self.assertFalse((self.base/'release-manifest.json').exists())
                link.unlink()

    def test_seal_does_not_hide_other_artifacts_named_work_or_package(self):
        directory=self.base/'evidence/work/package';directory.mkdir(parents=True)
        (directory/'retain.json').write_text('{}')
        self.seal_for_bundle()
        record=json.loads((self.base/'release-manifest.json').read_text())
        self.assertIn('evidence/work/package/retain.json',record['artifacts'])

    def test_seal_propagates_retained_tree_traversal_failure(self):
        def denied(*args,**kwargs):
            kwargs['onerror'](PermissionError('cannot inspect retained artifacts'))
            return iter(())
        with patch.object(evidence.os,'walk',side_effect=denied):
            with self.assertRaisesRegex(PermissionError,'cannot inspect'):
                self.seal_for_bundle()
        self.assertFalse((self.base/'release-manifest.json').exists())


if __name__ == '__main__':
    unittest.main()
