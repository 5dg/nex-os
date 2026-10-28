"""Compiler cleanup lifecycle with a mocked daemon; no containers are run."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
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

    def prepare_work(self):
        self.builder.work.mkdir()
        info=self.builder.work.stat()
        self.builder.work_identity=(info.st_dev,info.st_ino)

    def test_readonly_go_cache_and_final_scratch_cleanup_as_actual_nonroot_user(self):
        # When the test coordinator is root, run this fixture as an unprivileged
        # uid. A plain rmtree must reproduce the hosted permission error first.
        source=self.root/'fixture-scripts';source.mkdir(mode=0o755)
        for name in ('canonical-build.py','candidate.py','source_record.py','image_record.py','resource_admission.py'):
            shutil.copy2(SCRIPTS/name,source/name)
            (source/name).chmod(0o644)
        script=self.root/'nonroot.py'
        script.write_text('''import importlib.util,json,os,shutil,sys
from pathlib import Path
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'fixture-scripts'))
spec=importlib.util.spec_from_file_location('builder',root/'fixture-scripts/canonical-build.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
assert os.getuid()!=0, 'fixture must actually run unprivileged'
b=module.Builder.__new__(module.Builder);b.path=root/'build';b.path.mkdir();b.work=b.path/'work';b.work.mkdir()
s=b.work.stat();b.work_identity=(s.st_dev,s.st_ino)
cache=b.work/'gopath/pkg/mod/example@v1';cache.mkdir(parents=True)
(cache/'stackoverflow.go').write_text('readonly module source');(cache/'stackoverflow.go').chmod(0o444)
outside=root/'outside';outside.mkdir();original=outside/'export';original.write_text('preserve external bytes');original.chmod(0o444)
os.link(original,cache/'hardlinked-export')
(cache/'external-link').symlink_to(outside,target_is_directory=True)
for directory in (cache,cache.parent,cache.parent.parent,b.work/'gopath',outside):directory.chmod(0o555)
try:shutil.rmtree(b.work/'gopath')
except PermissionError:pass
else:raise AssertionError('baseline did not reproduce nonroot readonly-cache failure')
assert b.discard_owned_scratch('gopath')
assert not (b.work/'gopath').exists()
assert original.read_text()=='preserve external bytes' and original.stat().st_mode&0o777==0o444
assert outside.stat().st_mode&0o777==0o555
cache=b.work/'workspace/node_modules/cache';cache.mkdir(parents=True)
(cache/'input').write_text('node scratch');cache.chmod(0o555)
(b.work/'workspace/external-link').symlink_to(outside,target_is_directory=True)
assert b.discard_owned_scratch()
assert not b.work.exists()
assert original.read_text()=='preserve external bytes' and original.stat().st_mode&0o777==0o444
assert outside.stat().st_mode&0o777==0o555
outside.chmod(0o755)
print(json.dumps({'uid':os.getuid(),'readonly_baseline':'PermissionError','phase_cleanup':'passed','final_cleanup':'passed','outside_and_hardlink_modes':'unchanged'}))
''')
        script.chmod(0o644)
        options={}
        if os.getuid()==0:
            os.chown(self.root,65534,65534)
            options={'user':65534,'group':65534,'extra_groups':[]}
        result=subprocess.run([sys.executable,'-B',str(script),str(self.root)],capture_output=True,text=True,timeout=20,**options)
        self.assertEqual(result.returncode,0,result.stderr)
        report=json.loads(result.stdout)
        self.assertNotEqual(report['uid'],0)
        self.assertEqual(report['readonly_baseline'],'PermissionError')

    def test_cleanup_rejects_substituted_work_inode_before_chmod_or_removal(self):
        self.prepare_work()
        old=self.root/'original-work';self.builder.work.rename(old);self.builder.work.mkdir()
        sentinel=self.builder.work/'preserve';sentinel.write_text('unchanged')
        with self.assertRaisesRegex(ValueError,'original inode changed'):
            self.builder.discard_owned_scratch()
        self.assertTrue(old.is_dir());self.assertEqual(sentinel.read_text(),'unchanged')

    def test_cleanup_rejects_symlinked_root_and_phase_root(self):
        self.prepare_work()
        outside=self.root/'outside';outside.mkdir();sentinel=outside/'preserve';sentinel.write_text('unchanged')
        (self.builder.work/'gopath').symlink_to(outside,target_is_directory=True)
        with self.assertRaises(OSError):self.builder.discard_owned_scratch('gopath')
        self.assertTrue((self.builder.work/'gopath').is_symlink())
        self.builder.work.rename(self.root/'original-work');self.builder.work.symlink_to(outside,target_is_directory=True)
        with self.assertRaises(OSError):self.builder.discard_owned_scratch()
        self.assertEqual(sentinel.read_text(),'unchanged')

    def test_cleanup_rejects_unapproved_path_and_foreign_owner(self):
        self.prepare_work()
        with self.assertRaisesRegex(ValueError,'exact owned'):
            self.builder.discard_owned_scratch('../outside')
        actual=self.builder.work.stat()
        foreign=SimpleNamespace(st_dev=actual.st_dev,st_ino=actual.st_ino,st_uid=os.getuid()+1)
        with patch.object(compiler.os,'fstat',return_value=foreign),patch.object(compiler.os,'fchmod') as chmod:
            with self.assertRaisesRegex(ValueError,'ownership'):
                self.builder.discard_owned_scratch()
        chmod.assert_not_called();self.assertTrue(self.builder.work.is_dir())


if __name__=='__main__':unittest.main()
