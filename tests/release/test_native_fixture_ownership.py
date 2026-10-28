"""Embedded wrapper cleanup ownership checks with mocked daemon; no Docker."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock

SCRIPTS=Path(__file__).resolve().parents[2]/'scripts'
sys.path.insert(0,str(SCRIPTS))
text=(SCRIPTS/'qualification-native-fixtures.sh').read_text()
body=text.split("<<'PY'\n",1)[1].rsplit('\nPY',1)[0]
body=body.rsplit('\ntry:\n    raise SystemExit(main())',1)[0]
namespace={'__name__':'native_fixture_ownership_test'}
exec(compile(body,str(SCRIPTS/'qualification-native-fixtures.sh'),'exec'),namespace)
Runtime,FixtureError=namespace['Runtime'],namespace['FixtureError']


class NativeFixtureOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        runtime=Runtime.__new__(Runtime)
        runtime.names={'postgres':'owned-pg','opa':'owned-opa'}
        runtime.ids={}
        runtime.labels={'org.nex.run-id':'123456abcdef','org.nex.source.inputs':'a'*64}
        runtime.environment={'NEX_POSTGRES_IMAGE':'sha256:'+'1'*64,'NEX_OPA_IMAGE':'sha256:'+'2'*64}
        runtime.record={'status':'ready'}
        runtime.record_path=Path(self.temp.name)/'evidence/native-fixtures.json'
        self.runtime=runtime

    def owned(self,role,running=False):
        return {'Id':role+'-id','Name':'/'+self.runtime.names[role],
            'Config':{'Labels':dict(self.runtime.labels)},
            'Image':self.runtime.environment['NEX_'+role.upper()+'_IMAGE'],
            'State':{'Running':running,'ExitCode':0}}

    def test_verified_absence_before_create_is_safe(self):
        self.runtime.docker=Mock(return_value='')
        self.runtime.inspect=Mock()
        self.assertTrue(self.runtime.stop())
        self.runtime.inspect.assert_not_called()

    def test_unknown_daemon_state_is_not_proven_absence(self):
        self.runtime.docker=Mock(side_effect=FixtureError('fixture daemon unavailable'))
        self.assertFalse(self.runtime.stop())
        self.assertEqual(self.runtime.record['cleanup']['status'],'failed')
        self.assertEqual(self.runtime.record['status'],'failed')

    def test_listed_but_uninspectable_name_fails_and_other_owned_container_stops(self):
        calls=[]
        def docker(*args,**kwargs):
            calls.append(args)
            if args[:2]==('container','ls'):return 'owned-pg\nowned-opa'
            return ''
        def inspect(kind,name):
            if name=='owned-pg':raise FixtureError('fixture inspect unavailable')
            return self.owned('opa')
        self.runtime.docker=docker;self.runtime.inspect=inspect
        self.assertFalse(self.runtime.stop())
        self.assertIn(('container','stop','--time','75','opa-id'),calls)
        self.assertEqual(self.runtime.record['status'],'failed')

    def test_foreign_name_match_is_never_stopped(self):
        self.runtime.docker=Mock(return_value='owned-pg')
        foreign=self.owned('postgres');foreign['Config']['Labels']['org.nex.run-id']='different'
        self.runtime.inspect=Mock(return_value=foreign)
        self.assertFalse(self.runtime.stop())
        self.assertFalse(any(call.args[:2]==('container','stop') for call in self.runtime.docker.call_args_list))

    def test_recorded_container_disappearance_stays_unknown(self):
        self.runtime.ids={'postgres':'previously-observed-id'}
        self.runtime.docker=Mock(return_value='')
        self.assertFalse(self.runtime.stop())
        self.assertIn('postgres-missing',self.runtime.record['cleanup']['failures'])


if __name__=='__main__':
    unittest.main()
