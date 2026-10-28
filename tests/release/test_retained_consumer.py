"""Remote binding contract tests with synthetic metadata; no network/crypto proof."""
import argparse
import copy
import hashlib
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tarfile
import textwrap
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.request
import zipfile

SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('retained_consumer', SCRIPTS / 'verify-retained-candidate.py')
consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(consumer)


class RetainedConsumerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.release = {'source': {'revision': 'a'*40}, 'checks': {name:'passed' for name in ('qualification','proof-parity','shutdown','packaged-shutdown','history-pagination','dom-browser','vulnerability-scans','reproducibility')}}
        self.set_subject(self.release)
        self.args = argparse.Namespace(run_id=17, artifact_id=29, source_revision='a'*40,
            subject_sha256=hashlib.sha256(self.subject).hexdigest(), output=self.root/'receipt', tool_root=self.root/'tools')
        self.run = {'id':17,'head_sha':'a'*40,'head_branch':'main','event':'workflow_dispatch',
            'path':'.github/workflows/ci.yml','repository':{'full_name':'5dg/nex-os'},
            'head_repository':{'full_name':'5dg/nex-os'},'status':'completed','conclusion':'success'}
        self.artifact = {'id':29,'name':'alpha04-candidate-subject','expired':False,
            'workflow_run':{'id':17,'head_sha':'a'*40,'head_branch':'main'},
            'digest':'sha256:'+hashlib.sha256(self.archive).hexdigest()}

    def set_subject(self, release, name='release-manifest.json'):
        bundle = io.BytesIO()
        data = json.dumps(release).encode()
        with tarfile.open(fileobj=bundle, mode='w:gz') as archive:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        self.subject = bundle.getvalue()
        zipped_bytes = io.BytesIO()
        with zipfile.ZipFile(zipped_bytes, 'w') as zipped:
            zipped.writestr('candidate-bundle.tar.gz', self.subject)
        self.archive = zipped_bytes.getvalue()
        if hasattr(self, 'args'):
            self.args.subject_sha256 = hashlib.sha256(self.subject).hexdigest()
            self.artifact['digest'] = 'sha256:' + hashlib.sha256(self.archive).hexdigest()

    def verify_mock_origin(self):
        module=SimpleNamespace(verify=lambda args:0)  # Logic fixture only, no crypto verification claim.
        fake_spec=SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module:None))
        with patch.object(consumer,'metadata',side_effect=[self.run,self.artifact]),patch.object(consumer,'request',return_value=io.BytesIO(self.archive)),patch.object(consumer.importlib.util,'spec_from_file_location',return_value=fake_spec),patch.object(consumer.importlib.util,'module_from_spec',return_value=module):
            return consumer.verify(self.args)

    def test_expected_completed_metadata_binds_exact_retained_digest(self):
        self.assertEqual(consumer.validate_metadata(self.run,self.artifact,self.args),hashlib.sha256(self.archive).hexdigest())

    def test_repository_workflow_source_branch_run_and_artifact_substitutions_reject(self):
        cases = [('run','repository',{'full_name':'other/repo'}),('run','head_repository',{'full_name':'other/repo'}),
            ('run','path','.github/workflows/other.yml'),('run','head_sha','b'*40),('run','head_branch','feature'),
            ('run','id',18),('run','status','in_progress'),('run','event','pull_request'),
            ('artifact','id',30),('artifact','name','other-subject'),('artifact','expired',True),
            ('artifact','workflow_run',{'id':18,'head_sha':'a'*40,'head_branch':'main'}),
            ('artifact','workflow_run',{'id':17,'head_sha':'b'*40,'head_branch':'main'}),
            ('artifact','workflow_run',{'id':17,'head_sha':'a'*40,'head_branch':'feature'}),
            ('artifact','digest','sha256:not-a-digest')]
        for target,key,value in cases:
            run,artifact=copy.deepcopy(self.run),copy.deepcopy(self.artifact)
            (run if target=='run' else artifact)[key]=value
            with self.subTest(target=target,key=key,value=value),self.assertRaises(ValueError):
                consumer.validate_metadata(run,artifact,self.args)

    def test_downloaded_archive_digest_substitution_is_rejected_before_origin(self):
        with patch.object(consumer,'metadata',side_effect=[self.run,self.artifact]),patch.object(consumer,'request',return_value=io.BytesIO(b'changed download')):
            with self.assertRaisesRegex(ValueError,'retained digest'):
                consumer.verify(self.args)

    def test_subject_substitution_is_rejected_after_matching_archive_digest(self):
        self.args.subject_sha256='0'*64
        with patch.object(consumer,'metadata',side_effect=[self.run,self.artifact]),patch.object(consumer,'request',return_value=io.BytesIO(self.archive)):
            with self.assertRaisesRegex(ValueError,'expected candidate bundle'):
                consumer.verify(self.args)

    def test_failed_hosted_run_is_not_upgraded_by_mock_origin_success(self):
        self.run['conclusion']='failure'
        self.assertEqual(self.verify_mock_origin(),1)
        receipt=json.loads((self.args.output/'completed-run-receipt.json').read_text())
        self.assertEqual(receipt['hosted_ci'],'failed')
        self.assertEqual(receipt['durable_retention'],'passed')
        self.assertFalse(receipt['release_approval'])

    def test_missing_or_stale_release_manifest_is_rejected(self):
        for kind in ('missing','stale'):
            release=copy.deepcopy(self.release)
            if kind=='stale':release['source']['revision']='b'*40
            self.set_subject(release, 'other.json' if kind=='missing' else 'release-manifest.json')
            self.args.output=self.root/kind
            with self.subTest(kind=kind),self.assertRaises(ValueError):
                self.verify_mock_origin()

    def test_failed_local_gate_blocks_even_mock_origin_and_hosted_success(self):
        self.release['checks']['vulnerability-scans']='blocked'
        self.set_subject(self.release)
        self.assertEqual(self.verify_mock_origin(),1)
        receipt=json.loads((self.args.output/'completed-run-receipt.json').read_text())
        self.assertEqual(receipt['hosted_ci'],'passed')
        self.assertEqual(receipt['synthetic_qualification_gate'],'blocked')
        self.assertFalse(receipt['release_approval'])

    def test_native_shutdown_cannot_substitute_missing_packaged_lifecycle(self):
        del self.release['checks']['packaged-shutdown']
        self.set_subject(self.release)
        self.assertEqual(self.verify_mock_origin(),1)
        receipt=json.loads((self.args.output/'completed-run-receipt.json').read_text())
        self.assertEqual(receipt['synthetic_qualification_gate'],'blocked')

    def test_manual_history_evidence_cannot_substitute_missing_candidate_gate(self):
        del self.release['checks']['history-pagination']
        self.set_subject(self.release)
        self.assertEqual(self.verify_mock_origin(),1)
        receipt=json.loads((self.args.output/'completed-run-receipt.json').read_text())
        self.assertEqual(receipt['synthetic_qualification_gate'],'blocked')

    def test_consumer_never_scans_compressed_nonmanifest_payload(self):
        bundle=io.BytesIO()
        with tarfile.open(fileobj=bundle,mode='w:gz') as archive:
            for name,data in [('padding.bin',b'0'*8192),('release-manifest.json',json.dumps(self.release).encode())]:
                member=tarfile.TarInfo(name);member.size=len(data);archive.addfile(member,io.BytesIO(data))
        self.subject=bundle.getvalue()
        zipped_bytes=io.BytesIO()
        with zipfile.ZipFile(zipped_bytes,'w') as zipped:zipped.writestr('candidate-bundle.tar.gz',self.subject)
        self.archive=zipped_bytes.getvalue()
        self.args.subject_sha256=hashlib.sha256(self.subject).hexdigest()
        self.artifact['digest']='sha256:'+hashlib.sha256(self.archive).hexdigest()
        self.assertLess(len(self.archive),4096)
        with self.assertRaisesRegex(ValueError,'first subject member'):
            self.verify_mock_origin()

    def test_oversized_first_manifest_header_rejects_before_payload_read(self):
        member=tarfile.TarInfo('release-manifest.json');member.size=4*1024**2+1
        # Only a header and terminators are present: no large allocation or scan.
        self.subject=gzip.compress(member.tobuf()+b'\0'*1024)
        zipped_bytes=io.BytesIO()
        with zipfile.ZipFile(zipped_bytes,'w') as zipped:zipped.writestr('candidate-bundle.tar.gz',self.subject)
        self.archive=zipped_bytes.getvalue()
        self.args.subject_sha256=hashlib.sha256(self.subject).hexdigest()
        self.artifact['digest']='sha256:'+hashlib.sha256(self.archive).hexdigest()
        with self.assertRaisesRegex(ValueError,'bounded regular release manifest'):
            self.verify_mock_origin()

    def test_redirects_strip_api_authorization_and_reject_http(self):
        redirect=consumer.SafeRedirect()
        for destination in ('https://storage.invalid/artifact','https://api.github.com/artifact'):
            request=urllib.request.Request('https://api.github.com/original',headers={'Authorization':'Bearer fixture-only'})
            request.add_unredirected_header('Authorization','Bearer fixture-only')
            redirected=redirect.redirect_request(request,None,302,'',{},destination)
            self.assertFalse(any(name.lower()=='authorization' for name,_ in redirected.header_items()))
        with self.assertRaises(ValueError):
            redirect.redirect_request(request,None,302,'',{},'http://storage.invalid/artifact')


class WorkflowSubjectOutputTests(unittest.TestCase):
    def test_exact_workflow_heredoc_emits_64_hex_and_real_newline(self):
        workflow=(SCRIPTS.parent/'.github/workflows/ci.yml').read_text()
        step=workflow.split('- name: Record the immutable attestation subject',1)[1]
        shell=textwrap.dedent(step.split('run: |',1)[1].split('      - name:',1)[0]).strip()
        lines=shell.splitlines()
        self.assertEqual(lines[0],"python3 - <<'PY'")
        self.assertEqual(lines[-1],'PY')
        code='\n'.join(lines[1:-1])
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);subject=root/'candidate-bundle.tar.gz';subject.write_bytes(b'fixture bundle')
            output=root/'github-output';env=os.environ.copy();env['GITHUB_OUTPUT']=str(output)
            # Map only the fixture path; execute the exact authored Python output expression.
            code=code.replace("'/tmp/nex-ci-candidate/candidate-bundle.tar.gz'",repr(str(subject)))
            result=subprocess.run([sys.executable,'-c',code],env=env,capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            self.assertRegex(output.read_bytes(),rb'^sha256=[a-f0-9]{64}\n$')


if __name__=='__main__':
    unittest.main()
