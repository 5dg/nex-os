import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
sys.path.insert(0, '/workspace/nex-os/scripts')  # Ignored in hosted checkout when its scripts path exists.
spec=importlib.util.spec_from_file_location('image_diagnostic', HERE/'image_diagnostic.py')
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class ImageDiagnosticTests(unittest.TestCase):
    def test_frozen_inputs_match_expected(self):
        for role in m.ROLES:
            self.assertEqual(m.sha(HERE/(role+'.Dockerfile')),m.EXPECTED[role])

    def test_forecasts_and_reserve_fail_closed(self):
        for role in m.ROLES:
            floor=m.FORECAST[role]+m.RESERVE
            with patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=floor-1)):
                with self.assertRaisesRegex(ValueError,'insufficient'):m.admit('/tmp','/tmp',role)
            with patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=floor)):
                self.assertEqual(m.admit('/tmp','/tmp',role)['docker_free'],floor)

    def test_summary_rejects_invalid_and_preserves_actual_severity(self):
        self.assertEqual(m.report(b'not json','postgres')['status'],'unavailable')
        raw=json.dumps({'SchemaVersion':2,'ArtifactType':'container_image','Results':[{'Vulnerabilities':[{'VulnerabilityID':'CVE-2026-1234','PkgName':'example','Severity':'CRITICAL','Status':'affected'}]}]}).encode()
        result=m.report(raw,'postgres')
        self.assertEqual(result['status'],'available')
        self.assertEqual(result['rows'][0]['severity'],'CRITICAL')
        self.assertEqual(result['total_findings'],1)

    def test_no_findings_and_both_checks_required_for_completed(self):
        clean={'status':'available','total_findings':0}
        self.assertEqual(m.outcome(0,0,clean),'completed')
        self.assertNotEqual(m.outcome(1,0,clean),'completed')
        self.assertNotEqual(m.outcome(0,1,clean),'completed')
        self.assertNotEqual(m.outcome(0,0,{'status':'available','total_findings':1}),'completed')
        self.assertNotEqual(m.outcome(0,0,{'status':'unavailable'}),'completed')

    def test_guard_probe_uses_nonroot_override_and_stops_own_container(self):
        smoke_spec=importlib.util.spec_from_file_location('image_diagnostic_smoke',HERE/'smoke.py')
        smoke=importlib.util.module_from_spec(smoke_spec)
        smoke_spec.loader.exec_module(smoke)
        calls=[]
        def fake_docker(*args, **kwargs):
            calls.append(args)
            return SimpleNamespace(returncode=0,stdout='Nex.Guard started; profile=development; synthetic data only')
        with patch.dict(smoke.os.environ, {'GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'1'}), \
             patch.object(smoke,'docker',side_effect=fake_docker), \
             patch.object(smoke,'wait_for',side_effect=lambda name,predicate: self.assertTrue(predicate())), \
             patch.object(smoke,'reconcile') as cleanup:
            smoke.smoke('guard','sha256:'+'a'*64,'0'*32,'1000')
        self.assertIn('--user', calls[0])
        self.assertIn('1000:1000', calls[0])
        self.assertIn('--network', calls[0])
        self.assertIn('none', calls[0])
        cleanup.assert_called_once_with('nex-image-probe-123-1-guard-1000','sha256:'+'a'*64,'0'*32,'guard')

    def test_container_cleanup_refuses_foreign_owner(self):
        smoke=m.owned_smoke
        ident='b'*64
        obj=[{'Id':ident,'Name':'/probe','Image':'sha256:'+'a'*64,
              'Config':{'Labels':{'org.nex.diagnostic.owner':'f'*32,'org.nex.diagnostic.role':'guard'}},
              'State':{'Running':True}}]
        def fake(*args,**kwargs):
            if args[0]=='container':return SimpleNamespace(returncode=0,stdout=ident+'\n')
            if args[0]=='inspect':return SimpleNamespace(returncode=0,stdout=json.dumps(obj))
            self.fail('foreign container was touched')
        with patch.object(smoke,'docker',side_effect=fake):
            with self.assertRaisesRegex(RuntimeError,'foreign container'):
                smoke.reconcile('probe','sha256:'+'a'*64,'0'*32,'guard')

    def test_start_timeout_still_attempts_owner_reconciliation(self):
        smoke=m.owned_smoke
        with patch.dict(smoke.os.environ,{'GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'1'}), \
             patch.object(smoke,'docker',side_effect=subprocess.TimeoutExpired('docker',1)), \
             patch.object(smoke,'reconcile') as cleanup:
            with self.assertRaises(subprocess.TimeoutExpired):
                smoke.smoke('guard','sha256:'+'a'*64,'0'*32)
        cleanup.assert_called_once_with('nex-image-probe-123-1-guard','sha256:'+'a'*64,'0'*32,'guard')

    def test_output_overflow_is_bounded_and_fails(self):
        with tempfile.TemporaryDirectory() as d:
            output=Path(d)/'out'
            with patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=100*m.RESERVE)):
                with self.assertRaises(m.OutputLimit):
                    m.invoke([sys.executable,'-u','-c',"import time;print('x'*10000);time.sleep(60)"],output,d,d,10,stdout_limit=128)
            self.assertEqual(output.stat().st_size,128)

    def test_build_failure_halts_without_another_docker_operation(self):
        with tempfile.TemporaryDirectory() as d:
            envfile=Path(d)/'env';envfile.touch()
            env={'GITHUB_REPOSITORY':'5dg/nex-os','GITHUB_REF':'refs/heads/main',
                 'GITHUB_EVENT_NAME':'push','GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'1',
                 'GITHUB_SHA':'a'*40,'RUNNER_TEMP':d,'GITHUB_ENV':str(envfile)}
            def output(argv,*args,**kwargs):
                if argv[0]=='git':return ('a'*40+'\n').encode()
                if 'info' in argv:return (d+'\n').encode()
                return b'{}'
            def file_hash(path):
                name=Path(path).name.split('.')[0]
                return m.EXPECTED.get(name,'b'*64)
            with patch.dict(m.os.environ,env), patch.object(m,'probe',side_effect=output),patch.object(m,'validate_scanner'),patch.object(m,'validate_scanner_identity'), \
                 patch.object(m.shutil,'which',return_value=sys.executable), patch.object(m,'sha',side_effect=file_hash), \
                 patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=100*m.RESERVE)), \
                 patch.object(m,'invoke',return_value=1) as command:
                self.assertEqual(m.main(),1)
            self.assertEqual(command.call_count,1)
            report=json.loads((Path(d)/'nex-image-diagnostic-1-1/result.json').read_text())
            self.assertIn('unproven',report['images']['postgres']['halt_reason'])
            self.assertEqual(list(report['images']),['postgres'])

    def test_reject_untrusted_repository_before_output_creation(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.dict(m.os.environ,{'GITHUB_REPOSITORY':'foreign/repo','GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'push','RUNNER_TEMP':d},clear=True):
                with self.assertRaisesRegex(ValueError,'trusted repository'):m.main()
            self.assertEqual(list(Path(d).iterdir()),[])

    def test_owned_cleanup_stops_exact_inspected_container_only(self):
        smoke=m.owned_smoke;ident='b'*64;owner='0'*32;image='sha256:'+'a'*64
        obj=[{'Id':ident,'Name':'/probe','Image':image,
              'Config':{'Labels':{'org.nex.diagnostic.owner':owner,'org.nex.diagnostic.role':'guard'}},
              'State':{'Running':True}}]
        calls=[];listings=iter([ident+'\n',''])
        def fake(*args,**kwargs):
            calls.append(args)
            if args[0]=='container':return SimpleNamespace(returncode=0,stdout=next(listings))
            if args[0]=='inspect':return SimpleNamespace(returncode=0,stdout=json.dumps(obj))
            if args[0]=='stop':return SimpleNamespace(returncode=0,stdout=ident)
            self.fail('unexpected action')
        with patch.object(smoke,'docker',side_effect=fake):smoke.reconcile('probe',image,owner,'guard')
        self.assertIn(('stop','--time','10',ident),calls)

    def test_parent_smoke_interrupt_reconciles_then_halts(self):
        with tempfile.TemporaryDirectory() as d:
            envfile=Path(d)/'env';envfile.touch()
            env={'GITHUB_REPOSITORY':'5dg/nex-os','GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'push',
                 'GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'1','GITHUB_SHA':'a'*40,'RUNNER_TEMP':d,'GITHUB_ENV':str(envfile)}
            image='sha256:'+'b'*64
            def output(argv,*args,**kwargs):
                if argv[0]=='git':return ('a'*40+'\n').encode()
                if 'info' in argv:return (d+'\n').encode()
                if 'inspect' in argv:return json.dumps([{'Id':image,'RootFS':{'Layers':[]},'Os':'linux','Architecture':'amd64','Config':{'User':'','Entrypoint':[],'Cmd':[]}}]).encode()
                return b'{}'
            def file_hash(path):return m.EXPECTED.get(Path(path).name.split('.')[0],'b'*64)
            with patch.dict(m.os.environ,env),patch.object(m,'probe',side_effect=output),patch.object(m,'validate_scanner'),patch.object(m,'validate_scanner_identity'), \
                 patch.object(m.shutil,'which',return_value=sys.executable),patch.object(m,'sha',side_effect=file_hash), \
                 patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=100*m.RESERVE)), \
                 patch.object(m,'invoke',side_effect=[0,m.DiagnosticInterrupted('test interruption')]) as command, \
                 patch.object(m.owned_smoke,'reconcile') as cleanup:
                self.assertEqual(m.main(),1)
            self.assertEqual(command.call_count,2)
            cleanup.assert_called_once()
            report=json.loads((Path(d)/'nex-image-diagnostic-1-1/result.json').read_text())
            self.assertIn('late daemon create',report['images']['postgres']['halt_reason'])

    def test_scanner_identity_and_version_mismatch_fail_closed(self):
        import hashlib
        with tempfile.TemporaryDirectory() as d:
            scanner=Path(d)/'trivy';scanner.write_bytes(b'reviewed scanner')
            with patch.object(m,'SCANNER_SHA256',hashlib.sha256(b'reviewed scanner').hexdigest()):
                m.validate_scanner(scanner,scanner,b'{"Version":"0.76.1"}')
                with self.assertRaisesRegex(ValueError,'version mismatch'):
                    m.validate_scanner(scanner,scanner,b'{"Version":"0.75.0"}')
                with self.assertRaisesRegex(ValueError,'outside reviewed'):
                    m.validate_scanner(scanner,Path(d)/'different',b'{"Version":"0.76.1"}')
                scanner.write_bytes(b'replaced')
                with self.assertRaisesRegex(ValueError,'SHA mismatch'):
                    m.validate_scanner(scanner,scanner,b'{"Version":"0.76.1"}')

    def test_driver_sigterm_unwinds_and_kills_owned_process_group(self):
        import os,signal,threading
        oldterm=signal.getsignal(signal.SIGTERM);oldint=signal.getsignal(signal.SIGINT)
        self.addCleanup(signal.signal,signal.SIGTERM,oldterm)
        self.addCleanup(signal.signal,signal.SIGINT,oldint)
        m.install_handlers()
        with tempfile.TemporaryDirectory() as d:
            log=Path(d)/'out'
            timer=threading.Timer(0.3,lambda:os.kill(os.getpid(),signal.SIGTERM));timer.start()
            try:
                with patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=100*m.RESERVE)):
                    with self.assertRaises(m.DiagnosticInterrupted):
                        m.invoke([sys.executable,'-u','-c',"import os,time;print(os.getpid());time.sleep(60)"],log,d,d,10)
            finally:timer.cancel();timer.join()
            pid=int(log.read_text().strip())
            with self.assertRaises(ProcessLookupError):os.kill(pid,0)

    def test_metadata_read_is_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'data';p.write_bytes(b'x'*101)
            with self.assertRaisesRegex(ValueError,'exceeds reviewed bound'):m.small_file(p,100)

    def test_wrong_scanner_path_or_hash_never_executes_a_probe(self):
        with tempfile.TemporaryDirectory() as d:
            temp=Path(d);envfile=temp/'env';envfile.touch()
            scanner=temp/'nex-diagnostic-tools'/'trivy';scanner.parent.mkdir();scanner.write_bytes(b'wrong')
            env={'GITHUB_REPOSITORY':'5dg/nex-os','GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'push',
                 'GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'1','RUNNER_TEMP':d,'GITHUB_ENV':str(envfile)}
            def file_hash(path):return m.EXPECTED.get(Path(path).name.split('.')[0],'b'*64)
            for idx,path in enumerate((str(temp/'unexpected-trivy'),str(scanner)),1):
                env['GITHUB_RUN_ID']=str(idx)
                with patch.dict(m.os.environ,env),patch.object(m,'sha',side_effect=file_hash), \
                     patch.object(m.shutil,'which',return_value=path),patch.object(m,'probe') as command:
                    with self.assertRaises(ValueError):m.main()
                command.assert_not_called()

    def test_real_sigterm_halts_all_phases_and_smoke_cleanup_survives_sigint(self):
        import os,signal
        oldterm=signal.getsignal(signal.SIGTERM);oldint=signal.getsignal(signal.SIGINT)
        self.addCleanup(signal.signal,signal.SIGTERM,oldterm)
        self.addCleanup(signal.signal,signal.SIGINT,oldint)
        for phase in ('build','metadata','smoke','scan','summary'):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as d:
                envfile=Path(d)/'env';envfile.touch()
                env={'GITHUB_REPOSITORY':'5dg/nex-os','GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'push',
                     'GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'1','GITHUB_SHA':'a'*40,'RUNNER_TEMP':d,'GITHUB_ENV':str(envfile)}
                image='sha256:'+'b'*64
                def output(argv,*args,**kwargs):
                    if argv[0]=='git':return ('a'*40+'\n').encode()
                    if 'info' in argv:return (d+'\n').encode()
                    if 'inspect' in argv:
                        if phase=='metadata':os.kill(os.getpid(),signal.SIGTERM)
                        return json.dumps([{'Id':image,'RootFS':{'Layers':[]},'Os':'linux','Architecture':'amd64','Config':{'User':'','Entrypoint':[],'Cmd':[]}}]).encode()
                    return b'{}'
                def invoke(argv,*args,**kwargs):
                    what=('build' if 'build' in argv else 'scan' if 'image' in argv else 'smoke')
                    if what==phase:os.kill(os.getpid(),signal.SIGTERM)
                    if what=='scan':Path(args[0]).write_text('{}')
                    return 0
                def summarize(*args):
                    if phase=='summary':os.kill(os.getpid(),signal.SIGTERM)
                    return {'status':'available','total_findings':0}
                def cleanup(*args):
                    if phase=='smoke':os.kill(os.getpid(),signal.SIGINT)
                def file_hash(path):return m.EXPECTED.get(Path(path).name.split('.')[0],'b'*64)
                with patch.dict(m.os.environ,env),patch.object(m,'probe',side_effect=output), \
                     patch.object(m,'validate_scanner'),patch.object(m,'validate_scanner_identity'), \
                     patch.object(m.shutil,'which',return_value=sys.executable),patch.object(m,'sha',side_effect=file_hash), \
                     patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=100*m.RESERVE)), \
                     patch.object(m,'invoke',side_effect=invoke),patch.object(m,'summarize_image_report',side_effect=summarize), \
                     patch.object(m.owned_smoke,'reconcile',side_effect=cleanup):
                    self.assertEqual(m.main(),1)
                report=json.loads((Path(d)/'nex-image-diagnostic-1-1/result.json').read_text())
                self.assertEqual(list(report['images']),['postgres'])
                self.assertEqual(report['images']['postgres']['status'],'incomplete')
                self.assertIn('halt_reason',report['images']['postgres'])

    def test_signal_after_spawn_is_deferred_until_cleanup_owns_child(self):
        import os,signal
        oldterm=signal.getsignal(signal.SIGTERM);oldint=signal.getsignal(signal.SIGINT)
        self.addCleanup(signal.signal,signal.SIGTERM,oldterm)
        self.addCleanup(signal.signal,signal.SIGINT,oldint)
        m.install_handlers();real=m.subprocess.Popen;children=[]
        def spawn(*args,**kwargs):
            child=real(*args,**kwargs);children.append(child)
            os.kill(os.getpid(),signal.SIGTERM)
            return child
        with tempfile.TemporaryDirectory() as d, \
             patch.object(m.subprocess,'Popen',side_effect=spawn), \
             patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=100*m.RESERVE)):
            with self.assertRaises(m.DiagnosticInterrupted):
                m.invoke([sys.executable,'-u','-c','import time; time.sleep(60)'],Path(d)/'log',d,d,10)
        self.assertEqual(len(children),1)
        self.assertEqual(children[0].returncode,-signal.SIGTERM)

    def test_database_metadata_is_retained_per_role_or_marked_unknown(self):
        import hashlib
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source=root/'metadata.json';source.write_text('{"Version":2}')
            a=m.capture_db_metadata(source,root/'postgres-db.json')
            self.assertEqual(a['status'],'captured-not-freshness-verified')
            self.assertEqual(a['sha256'],hashlib.sha256(source.read_bytes()).hexdigest())
            source.write_text('{"Version":3}')
            b=m.capture_db_metadata(source,root/'guard-db.json')
            self.assertNotEqual(a['sha256'],b['sha256'])
            self.assertEqual((root/'postgres-db.json').read_text(),'{"Version":2}')
            self.assertEqual(m.capture_db_metadata(root/'missing',root/'workspace-db.json')['status'],'unknown')

    def test_real_signal_inside_actual_summary_parser_stops_later_roles(self):
        import os,signal
        oldterm=signal.getsignal(signal.SIGTERM);oldint=signal.getsignal(signal.SIGINT)
        self.addCleanup(signal.signal,signal.SIGTERM,oldterm)
        self.addCleanup(signal.signal,signal.SIGINT,oldint)
        with tempfile.TemporaryDirectory() as d:
            envfile=Path(d)/'env';envfile.touch()
            env={'GITHUB_REPOSITORY':'5dg/nex-os','GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'push',
                 'GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'1','GITHUB_SHA':'a'*40,'RUNNER_TEMP':d,'GITHUB_ENV':str(envfile)}
            image='sha256:'+'b'*64
            raw=b'{"SchemaVersion":2,"ArtifactType":"container_image","Results":[]}'
            real_loads=json.loads
            def interrupted_loads(value,*args,**kwargs):
                if value==raw:os.kill(os.getpid(),signal.SIGTERM)
                return real_loads(value,*args,**kwargs)
            def output(argv,*args,**kwargs):
                if argv[0]=='git':return ('a'*40+'\n').encode()
                if 'info' in argv:return (d+'\n').encode()
                if 'inspect' in argv:return json.dumps([{'Id':image,'RootFS':{'Layers':[]},'Os':'linux','Architecture':'amd64','Config':{'User':'','Entrypoint':[],'Cmd':[]}}]).encode()
                return b'{}'
            def invoke(argv,*args,**kwargs):
                if 'image' in argv:Path(args[0]).write_bytes(raw)
                return 0
            def file_hash(path):return m.EXPECTED.get(Path(path).name.split('.')[0],'b'*64)
            with patch.dict(m.os.environ,env),patch.object(m,'probe',side_effect=output), \
                 patch.object(m,'validate_scanner'),patch.object(m,'validate_scanner_identity'), \
                 patch.object(m.shutil,'which',return_value=sys.executable),patch.object(m,'sha',side_effect=file_hash), \
                 patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=100*m.RESERVE)), \
                 patch.object(m,'invoke',side_effect=invoke) as commands,patch.object(m.owned_smoke,'reconcile'), \
                 patch.object(json,'loads',side_effect=interrupted_loads):
                self.assertEqual(m.main(),1)
            self.assertEqual(commands.call_count,3)
            result=json.loads((Path(d)/'nex-image-diagnostic-1-1/result.json').read_text())
            self.assertEqual(list(result['images']),['postgres'])
            self.assertEqual(result['images']['postgres']['status'],'incomplete')
            self.assertIn('interrupted',result['images']['postgres']['halt_reason'])

    def test_phase_status_uses_allowlisted_fields_and_never_echoes_tool_text(self):
        import hashlib
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);secret='SECRETSHOULDNEVERAPPEAR'
            raw=b'{bad-json-'+secret.encode();err=b'fatal scanner failure '+secret.encode()
            (root/'postgres-trivy.json').write_bytes(raw);(root/'postgres-trivy.stderr').write_bytes(err)
            item={'status':'findings-or-incomplete','build_exit':0,'smoke_exit':0,'scan_exit':1,
                  'summary_status':'unavailable','scan_error':secret,'scan_error_category':secret,
                  'database_metadata':{'status':'captured-not-freshness-verified','sha256':'a'*64}}
            summary=m.phase_summary('postgres',item,root);encoded=json.dumps(summary)
            self.assertNotIn(secret,encoded)
            self.assertEqual(summary['report']['parse_category'],'invalid_json')
            self.assertEqual(summary['report']['bytes'],len(raw))
            self.assertEqual(summary['report']['sha256'],hashlib.sha256(raw).hexdigest())
            self.assertEqual(summary['stderr']['hint'],'unclassified_fatal')
            self.assertEqual(summary['scan']['exit_code'],1)
            self.assertEqual(summary['scan_error_category'],'none')
            self.assertEqual(summary['database_metadata']['sha256'],'a'*64)

    def test_phase_status_distinguishes_empty_invalid_schema_and_missing(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);item={'status':'incomplete','scan_exit':1,'summary_status':'unavailable'}
            self.assertEqual(m.phase_summary('postgres',item,root)['report']['parse_category'],'unavailable')
            (root/'postgres-trivy.json').write_bytes(b'')
            self.assertEqual(m.phase_summary('postgres',item,root)['report']['parse_category'],'empty')
            (root/'postgres-trivy.json').write_bytes(b'{}')
            self.assertEqual(m.phase_summary('postgres',item,root)['report']['parse_category'],'invalid_schema_or_summary_error')

    def test_phase_reporting_failure_cannot_change_gate_or_leak_exception(self):
        with patch.object(m,'phase_summary',side_effect=RuntimeError('SECRET')), \
             patch('builtins.print') as log:
            m.emit_phase_summary('postgres',{},'/tmp')
        self.assertEqual(log.call_args.args[0],'diagnostic-only phase-status {"status":"unavailable"}')

    def test_phase_reporting_propagates_interruption(self):
        with patch.object(m,'phase_summary',side_effect=m.DiagnosticInterrupted('interrupted')):
            with self.assertRaises(m.DiagnosticInterrupted):m.emit_phase_summary('postgres',{},'/tmp')

    def test_structured_scan_categories_are_explicit_and_allowlisted(self):
        with tempfile.TemporaryDirectory() as d:
            item={'status':'incomplete','scan_exit':None}
            for category in ('timeout','output_limit','reserve','forecast','scanner_identity','other','process_error','interrupted'):
                item['scan_error_category']=category
                self.assertEqual(m.phase_summary('postgres',item,d)['scan_error_category'],category)
            item['scan_error_category']='unexpected diagnostic text'
            self.assertEqual(m.phase_summary('postgres',item,d)['scan_error_category'],'none')
            self.assertEqual(m.stderr_hint(b'HTTP 429 rate limit; secret-value',1),'possible_rate_limit')
            self.assertEqual(m.stderr_hint(b'',1),'nonzero_without_stderr')

    def test_typed_scan_error_categories_do_not_echo_exception_text(self):
        mapping=[(TimeoutError('secret'),'timeout'),(m.OutputLimit('secret'),'output_limit'),
                 (m.ReserveReached('secret'),'reserve'),(m.ForecastExceeded('secret'),'forecast'),
                 (m.ScannerIdentityError('secret'),'scanner_identity'),(ValueError('secret'),'other')]
        for error,expected in mapping:self.assertEqual(m.scan_exception_category(error),expected)

    def test_supervisor_distinguishes_reserve_from_forecast(self):
        cases=[(m.RESERVE-1,m.ReserveReached,'reserve'),
               (5*1024**3-1024**3-1,m.ForecastExceeded,'forecast')]
        for free,error_type,category in cases:
            with self.subTest(category=category),tempfile.TemporaryDirectory() as d:
                with patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=free)):
                    with self.assertRaises(error_type) as raised:
                        m.invoke([sys.executable,'-u','-c','import time; time.sleep(60)'],
                                 Path(d)/'out',d,d,10,{'output_free':5*1024**3,'docker_free':5*1024**3},1024**3)
                self.assertEqual(m.scan_exception_category(raised.exception),category)

    def test_scanner_identity_errors_are_typed(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'scanner';p.write_bytes(b'not the pinned scanner')
            with self.assertRaises(m.ScannerIdentityError) as bad_path:
                m.validate_scanner_identity(p,Path(d)/'other')
            self.assertEqual(m.scan_exception_category(bad_path.exception),'scanner_identity')
            with self.assertRaises(m.ScannerIdentityError) as bad_hash:
                m.validate_scanner_identity(p,p)
            self.assertEqual(m.scan_exception_category(bad_hash.exception),'scanner_identity')

    def test_role_scan_admission_keeps_reserve_and_uses_exact_budgets(self):
        self.assertEqual(m.SCAN_FORECAST,{'postgres':2*1024**3,'workspace':1024**3,'guard':1024**3})
        for role,budget in m.SCAN_FORECAST.items():
            floor=budget+m.RESERVE
            with self.subTest(role=role),patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=floor-1)):
                with self.assertRaisesRegex(ValueError,'scan forecast'):m.admit_scan('/tmp','/tmp',role)
            with patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=floor)):
                self.assertEqual(m.admit_scan('/tmp','/tmp',role)['output_free'],floor)

    def test_postgres_budget_still_stops_on_actual_growth(self):
        initial={'output_free':8*1024**3,'docker_free':8*1024**3}
        with tempfile.TemporaryDirectory() as d:
            with patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=8*1024**3-1024**3-1)):
                self.assertEqual(m.invoke([sys.executable,'-c','pass'],Path(d)/'allowed',d,d,10,initial,m.SCAN_FORECAST['postgres']),0)
            with patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=8*1024**3-2*1024**3-1)):
                with self.assertRaises(m.ForecastExceeded):
                    m.invoke([sys.executable,'-c','import time;time.sleep(60)'],Path(d)/'stopped',d,d,10,initial,m.SCAN_FORECAST['postgres'])

    def test_main_passes_correct_scan_budgets_to_supervisor(self):
        with tempfile.TemporaryDirectory() as d:
            envfile=Path(d)/'env';envfile.touch()
            env={'GITHUB_REPOSITORY':'5dg/nex-os','GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'push',
                 'GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'1','GITHUB_SHA':'a'*40,'RUNNER_TEMP':d,'GITHUB_ENV':str(envfile)}
            image='sha256:'+'b'*64;budgets=[]
            def output(argv,*args,**kwargs):
                if argv[0]=='git':return ('a'*40+'\n').encode()
                if 'info' in argv:return (d+'\n').encode()
                if 'inspect' in argv:return json.dumps([{'Id':image,'RootFS':{'Layers':[]},'Os':'linux','Architecture':'amd64','Config':{'User':'','Entrypoint':[],'Cmd':[]}}]).encode()
                return b'{}'
            def invoke(argv,log,output_path,docker_root,timeout,initial=None,forecast=None,*args,**kwargs):
                if 'image' in argv:
                    budgets.append(forecast)
                    Path(log).write_bytes(b'{"SchemaVersion":2,"ArtifactType":"container_image","Results":[]}')
                return 0
            def file_hash(path):return m.EXPECTED.get(Path(path).name.split('.')[0],'b'*64)
            with patch.dict(m.os.environ,env),patch.object(m,'probe',side_effect=output), \
                 patch.object(m,'validate_scanner'),patch.object(m,'validate_scanner_identity'), \
                 patch.object(m.shutil,'which',return_value=sys.executable),patch.object(m,'sha',side_effect=file_hash), \
                 patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=100*m.RESERVE)), \
                 patch.object(m,'invoke',side_effect=invoke),patch.object(m.owned_smoke,'reconcile'):
                self.assertEqual(m.main(),0)
            self.assertEqual(budgets,[2*1024**3,1024**3,1024**3])

    def test_telemetry_reports_only_recognized_files_and_ignores_links(self):
        import os
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);scratch=root/'scratch';scratch.mkdir();cache=root/'cache';(cache/'db').mkdir(parents=True);(cache/'fanal').mkdir()
            proc=scratch/'trivy-secret-process-name';proc.mkdir()
            export=proc/'docker-export-secret-filename';export.write_bytes(b'x'*12345)
            (proc/'unrecognized-secret').write_bytes(b'y'*54321)
            (cache/'db'/'trivy.db').write_bytes(b'z'*222)
            (cache/'fanal'/'fanal.db').write_bytes(b'a'*333)
            initial={'output_free':10**12,'docker_free':10**12}
            with patch.object(m.disk_telemetry.shutil,'disk_usage',return_value=SimpleNamespace(free=10**12-9)):
                data=m.disk_telemetry.measure(scratch,cache,root,root,initial)
            self.assertEqual(data['export_logical_bytes'],12345)
            self.assertEqual(data['db_logical_bytes'],222)
            self.assertEqual(data['fanal_logical_bytes'],333)
            self.assertEqual(data['output_free_decrease_bytes'],9)
            export.unlink();export.symlink_to(proc/'unrecognized-secret')
            logical,allocated,partial=m.disk_telemetry.export_counts(scratch)
            self.assertTrue(partial);self.assertEqual((logical,allocated),(0,0))

    def test_telemetry_scans_only_bounded_directory_entries(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for i in range(m.disk_telemetry.MAX_ENTRIES+1):(root/('trivy-'+str(i))).mkdir()
            _,_,partial=m.disk_telemetry.export_counts(root)
            self.assertTrue(partial)

    def test_disk_telemetry_logging_never_echoes_paths_or_arbitrary_fields(self):
        secret='DO_NOT_LOG_SECRET_PATH'
        data={'status':'sampled','samples':1,'partial_samples':0,'sample_errors':0,
              'peaks':{'export_logical_bytes':123,'secret_path':secret},'extra':secret}
        with patch('builtins.print') as log:m.emit_disk_telemetry('postgres',data,1234)
        text=log.call_args.args[0]
        self.assertNotIn(secret,text)
        self.assertIn('"export_logical_bytes":123',text)
        self.assertIn('"image_size_bytes":1234',text)

    def test_live_scanner_only_tmpdir_records_export_without_changing_parent_environment(self):
        import os
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);scratch=root/'scratch';scratch.mkdir();cache=root/'cache';cache.mkdir()
            initial={'output_free':100*m.RESERVE,'docker_free':100*m.RESERVE}
            sampler=m.disk_telemetry.Sampler(scratch,cache,root,root,initial,interval=0.02)
            code="import os,time; p=os.path.join(os.environ['TMPDIR'],'trivy-fixture');os.mkdir(p);open(os.path.join(p,'docker-export-fixture'),'wb').write(b'x'*65536);time.sleep(.2)"
            before=os.environ.get('TMPDIR')
            with patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=100*m.RESERVE)):
                self.assertEqual(m.invoke([sys.executable,'-c',code],root/'out',root,root,10,initial,1024**3,
                                          telemetry=sampler,scanner_tmp=scratch),0)
            self.assertEqual(os.environ.get('TMPDIR'),before)
            self.assertEqual(sampler.finished['status'],'sampled')
            self.assertGreaterEqual(sampler.finished['peaks']['export_logical_bytes'],65536)

    def test_unquiesced_sampler_halts_before_later_roles(self):
        with tempfile.TemporaryDirectory() as d:
            envfile=Path(d)/'env';envfile.touch()
            env={'GITHUB_REPOSITORY':'5dg/nex-os','GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'push',
                 'GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'1','GITHUB_SHA':'a'*40,'RUNNER_TEMP':d,'GITHUB_ENV':str(envfile),
                 'TRIVY_CACHE_DIR':'/tmp/nex-diagnostic-trivy-cache'}
            image='sha256:'+'b'*64
            def output(argv,*args,**kwargs):
                if argv[0]=='git':return ('a'*40+'\n').encode()
                if 'info' in argv:return (d+'\n').encode()
                if 'inspect' in argv:return json.dumps([{'Id':image,'RootFS':{'Layers':[]},'Os':'linux','Architecture':'amd64','Config':{'User':'','Entrypoint':[],'Cmd':[]}}]).encode()
                return b'{}'
            def invoke(argv,*args,**kwargs):
                if 'image' in argv:kwargs['telemetry'].finished={'status':'sampler-unquiesced','samples':0,'partial_samples':0,'sample_errors':0,'peaks':{}}
                return 0
            def file_hash(path):return m.EXPECTED.get(Path(path).name.split('.')[0],'b'*64)
            with patch.dict(m.os.environ,env),patch.object(m,'probe',side_effect=output), \
                 patch.object(m,'validate_scanner'),patch.object(m,'validate_scanner_identity'), \
                 patch.object(m.shutil,'which',return_value=sys.executable),patch.object(m,'sha',side_effect=file_hash), \
                 patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=100*m.RESERVE)), \
                 patch.object(m,'invoke',side_effect=invoke) as commands,patch.object(m.owned_smoke,'reconcile'):
                self.assertEqual(m.main(),1)
            self.assertEqual(commands.call_count,3)
            result=json.loads((Path(d)/'nex-image-diagnostic-1-1/result.json').read_text())
            self.assertEqual(list(result['images']),['postgres'])
            self.assertIn('sampler did not stop',result['images']['postgres']['halt_reason'])

    def test_cache_must_be_on_monitored_filesystem_and_not_symlink(self):
        import os
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);output=root/'output';output.mkdir();docker=root/'docker';docker.mkdir();cache=root/'cache'
            m.validate_cache_filesystem(cache,output,docker)
            cache.symlink_to(output,target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'symlink'):m.validate_cache_filesystem(cache,output,docker)
            cache.unlink()
            real_stat=os.stat
            def fake(path,*args,**kwargs):
                if Path(path)==root:return SimpleNamespace(st_dev=999999)
                return real_stat(path,*args,**kwargs)
            with patch.object(m.os,'stat',side_effect=fake):
                with self.assertRaisesRegex(ValueError,'outside monitored'):m.validate_cache_filesystem(cache,output,docker)

    def test_command_captures_stdout_and_stderr_separately(self):
        with tempfile.TemporaryDirectory() as d:
            stdout=Path(d)/'out'; stderr=Path(d)/'err'
            with patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=100*m.RESERVE)):
                code=m.invoke([sys.executable,'-c',"import sys;print('report');print('error',file=sys.stderr)"],stdout,d,d,10,stderr_path=stderr)
            self.assertEqual(code,0)
            self.assertEqual(stdout.read_text(),'report\n')
            self.assertEqual(stderr.read_text(),'error\n')

    def test_timed_out_process_is_stopped_and_output_retained(self):
        with tempfile.TemporaryDirectory() as d:
            logfile=Path(d)/'out'
            with patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=100*m.RESERVE)):
                with self.assertRaises(TimeoutError):
                    m.invoke([sys.executable,'-u','-c',"import time;print('started');time.sleep(60)"],logfile,d,d,0.1)
            self.assertIn('started',logfile.read_text())

if __name__=='__main__': unittest.main()
