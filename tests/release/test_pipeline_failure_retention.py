"""Actual shell early-failure retention from a gitless source; no Docker calls."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import source_record


class PipelineFailureRetentionTests(unittest.TestCase):
    def run_preflight(self, extra_env=None, expected_error=b'Pinned verification prerequisite missing: go'):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / 'source'
            (root / 'scripts').mkdir(parents=True)
            for name in ('candidate-pipeline.sh', 'candidate.py', 'candidate-evidence.py', 'source_record.py', 'image_record.py', 'phase_admission.py'):
                shutil.copy2(SCRIPTS / name, root / 'scripts' / name)
            (root / 'go.mod').write_text('module example.invalid/early-failure\n')
            source_record.atomic_json(root / source_record.COMPANION, {
                'schema_version':1,'revision':'a'*40,'source_epoch':1700000000,
                'inputs':source_record.inputs(root,canonical=True)})
            identity=source_record.identity(root,canonical=True)
            archive=base/'source.tar'
            with tarfile.open(archive,'w') as saved:
                for path in sorted(root.rglob('*')):
                    if path.is_file():saved.add(path,arcname=path.relative_to(root),recursive=False)
            manifest=base/'candidate.json'
            source_record.atomic_json(manifest,{'schema_version':1,'run_id':'123456abcdef',
                'source_directory':'source','source':identity,
                'primary_project':'nex-alpha04-123456abcdef','restore_project':'nex-alpha04-123456abcdef-restore',
                'archive':{'path':'source.tar','sha256':source_record.sha256(archive)},'builds':{}})
            tools=base/'test-tools';tools.mkdir()
            for name in ('tee','dirname','mkdir'):
                (tools/name).symlink_to(shutil.which(name))
            (tools/'python3').symlink_to(sys.executable)
            docker=tools/'docker'
            docker.write_text('#!/bin/sh\n: > "$NEX_DOCKER_MARKER"\nexit 99\n')
            docker.chmod(0o755)
            marker=base/'unexpected-docker-call'
            env=os.environ.copy()
            env.update(PATH=str(tools),NEX_TOOLS_DIR=str(base/'absent-tools'),
                CARGO_HOME=str(base/'absent-cargo'),RUSTUP_HOME=str(base/'absent-rustup'),
                NEX_DOCKER_MARKER=str(marker))
            for key in ('NEX_QUAL_BUILD','NEX_QUAL_RUN_ID','NEX_QUAL_PROJECT','NEX_QUAL_PRIMARY_PROJECT','NEX_QUAL_RESTORE_PROJECT',
                        'NEX_QUAL_STATE_DIR','NEX_QUAL_PRIMARY_STATE_DIR','NEX_QUAL_RESTORE_STATE_DIR'):
                env.pop(key,None)
            env.update(extra_env or {})
            result=subprocess.run(['/bin/bash',str(root/'scripts/candidate-pipeline.sh'),str(manifest),'10.231.0.0/20'],
                env=env,cwd=base,capture_output=True,timeout=20)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(marker.exists(),'failure preflight unexpectedly invoked runtime admission')
            log=base/'pipeline.log'
            self.assertIn(expected_error,log.read_bytes())
            release=json.loads((base/'release-manifest.json').read_text())
            self.assertEqual(release['release_gate'],'blocked')
            self.assertEqual(release['tested_images'],{})
            self.assertEqual(release['artifacts']['pipeline.log'],hashlib.sha256(log.read_bytes()).hexdigest())
            bundle=base/'candidate-bundle.tar.gz'
            self.assertTrue(bundle.is_file())
            with tarfile.open(bundle,'r:gz') as saved:
                self.assertEqual(saved.getmembers()[0].name,'release-manifest.json')
                retained=json.load(saved.extractfile('release-manifest.json'))
                self.assertEqual(retained,release)
                self.assertEqual(saved.extractfile('pipeline.log').read(),log.read_bytes())
            self.assertEqual(identity,source_record.identity(root,canonical=True))
            self.assertFalse(any(root.rglob('__pycache__')))

    def test_missing_prerequisite_retains_blocked_bundle_without_tested_images(self):
        self.run_preflight()

    def test_matching_primary_build_context_reaches_normal_prerequisite_check(self):
        self.run_preflight({'NEX_QUAL_BUILD':'one','NEX_QUAL_PROJECT':'nex-alpha04-123456abcdef'})

    def test_inherited_second_build_is_rejected_before_runtime(self):
        self.run_preflight({'NEX_QUAL_BUILD':'two'},b'Contradictory inherited candidate context: NEX_QUAL_BUILD')

    def test_inherited_restore_project_is_rejected_before_runtime(self):
        self.run_preflight({'NEX_QUAL_PROJECT':'nex-alpha04-123456abcdef-restore'},
                           b'Contradictory inherited candidate context: NEX_QUAL_PROJECT')

    def test_inherited_foreign_state_is_rejected_before_runtime(self):
        for key in ('NEX_QUAL_STATE_DIR','NEX_QUAL_PRIMARY_STATE_DIR','NEX_QUAL_RESTORE_STATE_DIR'):
            with self.subTest(key=key):
                self.run_preflight({key:'/foreign-state'},('Contradictory inherited candidate context: '+key).encode())

    def test_inherited_foreign_run_and_project_identities_are_rejected(self):
        for key in ('NEX_QUAL_RUN_ID','NEX_QUAL_PRIMARY_PROJECT','NEX_QUAL_RESTORE_PROJECT'):
            with self.subTest(key=key):
                self.run_preflight({key:'foreign'},('Contradictory inherited candidate context: '+key).encode())


if __name__=='__main__':
    unittest.main()
