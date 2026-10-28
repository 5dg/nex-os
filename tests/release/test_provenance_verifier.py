"""Verifier command-contract tests; mocked CLI is not cryptographic evidence."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPTS=Path(__file__).resolve().parents[2]/'scripts'
sys.path.insert(0,str(SCRIPTS))
spec=importlib.util.spec_from_file_location('verify_provenance',SCRIPTS/'verify-provenance.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class ProvenanceContractTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name);subject=self.root/'candidate.tar';subject.write_bytes(b'candidate')
  tool=self.root/'tools/bin/gh-attestation';tool.parent.mkdir(parents=True);tool.write_bytes(b'fixture-only-not-real-gh')
  record={'version':module.GH_VERSION,'archive_sha256':module.GH_ARCHIVE_SHA256,'binary_sha256':hashlib.sha256(tool.read_bytes()).hexdigest()}
  (tool.parent/'gh-attestation.json').write_text(json.dumps(record))
  self.args=SimpleNamespace(source_revision='a'*40,subject_sha256=hashlib.sha256(subject.read_bytes()).hexdigest(),subject=subject,tool_root=self.root/'tools',attestation_bundle=None,output=self.root/'result.json')
 def test_mock_command_binds_source_workflow_main_and_oidc(self):
  with patch.object(module,'GH_BINARY_SHA256',hashlib.sha256((self.args.tool_root/'bin/gh-attestation').read_bytes()).hexdigest()), patch.object(module.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=b'[{"fixture":"mock-only"}]',stderr=b'')) as run:
   self.assertEqual(module.verify(self.args),0)
  command=run.call_args.args[0]
  for flag,value in [('--repo','5dg/nex-os'),('--signer-workflow','5dg/nex-os/.github/workflows/ci.yml'),('--signer-digest','a'*40),('--source-digest','a'*40),('--source-ref','refs/heads/main'),('--cert-oidc-issuer','https://token.actions.githubusercontent.com'),('--predicate-type','https://slsa.dev/provenance/v1')]:
   self.assertEqual(command[command.index(flag)+1],value)
  self.assertIn('--deny-self-hosted-runners',command)
  self.assertFalse(json.loads(self.args.output.read_text())['release_approval'])
 def test_failed_verifier_never_produces_passed_receipt(self):
  with patch.object(module,'GH_BINARY_SHA256',hashlib.sha256((self.args.tool_root/'bin/gh-attestation').read_bytes()).hexdigest()), patch.object(module.subprocess,'run',return_value=SimpleNamespace(returncode=1,stdout=b'',stderr=b'fixture rejection')):
   self.assertEqual(module.verify(self.args),1)
  self.assertEqual(json.loads(self.args.output.read_text())['origin_verification'],'failed')
 def test_subject_substitution_rejected_before_mock_verification(self):
  self.args.subject.write_bytes(b'changed')
  with patch.object(module.subprocess,'run') as run:
   with self.assertRaises(ValueError):module.verify(self.args)
  run.assert_not_called()

 def test_arbitrary_verifier_and_matching_mutable_record_rejected(self):
  # A claimed archive/version plus a matching local tool hash is not proof
  # that these bytes came from the pinned official archive.
  with patch.object(module.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=b'[{"fixture":"untrusted-tool"}]',stderr=b'')) as run:
   with self.assertRaises(ValueError):module.verify(self.args)
  run.assert_not_called()
