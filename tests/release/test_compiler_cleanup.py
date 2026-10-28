"""Compiler cleanup lifecycle with a mocked daemon; no containers are run."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SCRIPTS=Path(__file__).resolve().parents[2]/'scripts'
sys.path.insert(0,str(SCRIPTS))
spec=importlib.util.spec_from_file_location('canonical_builder_cleanup',SCRIPTS/'canonical-build.py')
compiler=importlib.util.module_from_spec(spec);spec.loader.exec_module(compiler)


class CompilerCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        b=compiler.Builder.__new__(compiler.Builder)
        b.path=self.root;b.manifest=self.root/'manifest.json';b.record={'commands':[],'builders':{}}
        b.prefix=['docker','--host=unix:///var/run/docker.sock'];b.env={};b.reserve=2*1024**3;b.docker_fs=self.root
        b.args=argparse.Namespace(build='one',ca=self.root/'public-ca.crt')
        b.candidate={'run_id':'123456abcdef','source':{'inputs':{'sha256':'a'*64},'source_epoch':1700000000}}
        b.source=self.root/'source';b.work=self.root/'work';b.bin=self.root/'bin';b.package=self.root/'package'
        self.builder=b;self.name='owned-compiler';self.image='sha256:'+'1'*64
        self.owner={'org.nex.compiler.run':'123456abcdef','org.nex.compiler.nonce':'abcdef'}
        self.calls=[]

    def daemon(self,command,**kwargs):
        arguments=command[2:];self.calls.append(arguments)
        if arguments[:2]==['container','inspect']:
            if arguments[-1]=='{{.State.Running}}':return SimpleNamespace(returncode=0,stdout='false\n',stderr='')
            return SimpleNamespace(returncode=0,stdout=json.dumps({'id':'container-id','name':'/'+self.name,'image':self.image,'labels':self.owner,'running':True}),stderr='')
        return SimpleNamespace(returncode=0,stdout='',stderr='')

    def test_cleanup_bypasses_normal_resource_admission_and_logging(self):
        self.builder.run=Mock(side_effect=AssertionError('cleanup must not use admission/logging-gated run'))
        with patch.object(compiler.subprocess,'run',side_effect=self.daemon),patch.object(compiler.shutil,'disk_usage',side_effect=AssertionError('cleanup must not require free-space admission')):
            self.builder.stop_owned_compiler('rust',self.name,self.owner,self.image)
        self.assertIn(['stop','--time','20','container-id'],self.calls)
        self.assertIn(['rm','container-id'],self.calls)
        self.builder.run.assert_not_called()

    def test_manifest_write_failure_does_not_prevent_owned_stop(self):
        with patch.object(compiler.subprocess,'run',side_effect=self.daemon),patch.object(compiler,'atomic_json',side_effect=OSError('fixture disk full')):
            with self.assertRaises((OSError,ValueError)):
                self.builder.stop_owned_compiler('rust',self.name,self.owner,self.image)
        self.assertIn(['stop','--time','20','container-id'],self.calls)
        self.assertIn(['rm','container-id'],self.calls)

    def test_ownership_mismatch_never_stops_container(self):
        with patch.object(compiler.subprocess,'run',side_effect=self.daemon):
            with self.assertRaises(ValueError):
                self.builder.stop_owned_compiler('rust',self.name,{'different':'owner'},self.image)
        self.assertFalse(any(arguments[0] in ('stop','rm') for arguments in self.calls))

    def test_cid_substitution_never_stops_container(self):
        (self.root/'rust.cid').write_text('other-container-id')
        with patch.object(compiler.subprocess,'run',side_effect=self.daemon):
            with self.assertRaises(ValueError):
                self.builder.stop_owned_compiler('rust',self.name,self.owner,self.image)
        self.assertFalse(any(arguments[0] in ('stop','rm') for arguments in self.calls))

    def test_unknown_daemon_state_is_not_recorded_as_removed(self):
        with patch.object(compiler.subprocess,'run',return_value=SimpleNamespace(returncode=1,stdout='',stderr='fixture daemon unavailable')):
            with self.assertRaises(ValueError):
                self.builder.stop_owned_compiler('rust',self.name,self.owner,self.image)
        self.assertNotEqual(self.builder.record['compiler_cleanup'][-1].get('status'),'already-removed')

    def test_definitive_absence_needs_no_stop(self):
        with patch.object(compiler.subprocess,'run',return_value=SimpleNamespace(returncode=1,stdout='',stderr='No such container: fixture')) as run:
            self.builder.stop_owned_compiler('rust',self.name,self.owner,self.image)
        self.assertEqual(run.call_count,1)
        self.assertEqual(self.builder.record['compiler_cleanup'][-1]['status'],'already-removed')

    def test_compile_failure_always_enters_owned_cleanup(self):
        def run(name,*args,**kwargs):
            if name=='rust-identity':return json.dumps({'id':self.image,'os':'linux','architecture':'amd64','repo_digests':[]})
            if name=='rust-compile':raise ValueError('fixture compiler timeout')
        self.builder.run=run;self.builder.stop_owned_compiler=Mock()
        with self.assertRaisesRegex(ValueError,'fixture compiler timeout'):
            self.builder.compiler('rust')
        self.builder.stop_owned_compiler.assert_called_once()
        role,name,owner,image=self.builder.stop_owned_compiler.call_args.args
        self.assertEqual(role,'rust');self.assertIn('123456abcdef',name)
        self.assertEqual(owner['org.nex.source.inputs'],'a'*64);self.assertEqual(image,self.image)


if __name__=='__main__':unittest.main()
