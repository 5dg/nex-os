#!/usr/bin/env python3
"""Opt-in hosted image experiment. Never a release or vulnerability gate."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import smoke as owned_smoke
from image_vulnerability_summary import summarize_image_report

SCANNER_SHA256 = 'd1dfca6ae10a1ad4540bb94e64f0510077c47008920a9b554986b39dca573d83'
RESERVE = 2 * 1024**3
FORECAST = {'postgres': 8 * 1024**3, 'workspace': 4 * 1024**3, 'guard': 4 * 1024**3}
EXPECTED = {'postgres': '959c545c9531f8664dd6f4c63bdcc44a695e8ea149e81a8c99fc047e74b9f1d0',
            'workspace': 'bc5d88c9357c27d6cffdfda1c80e8eb4640b3012c4d81de16e2b2f9ca47c39c7',
            'guard': '212b67881653b89c3182d6e481a5f819613009bfd88c2a61b08cb521fa21d0d6'}
ROLES = ('postgres', 'workspace', 'guard')


def admit(output, docker_root, role):
    floor = FORECAST[role] + RESERVE
    values = {'output_free': shutil.disk_usage(output).free,
              'docker_free': shutil.disk_usage(docker_root).free}
    if min(values.values()) < floor:
        raise ValueError('insufficient free space for role forecast and 2 GiB reserve')
    return values


def sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


class OutputLimit(ValueError):
    pass


class DiagnosticInterrupted(BaseException):
    pass


def interrupted(signum, _frame):
    # Prevent a second termination signal from interrupting owned cleanup.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    raise DiagnosticInterrupted('diagnostic interrupted by signal ' + str(signum))


def install_handlers():
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)


def invoke(argv, log, output, docker_root, timeout, initial=None, forecast=None,
           stderr_path=None, stdout_limit=32*1024**2, stderr_limit=2*1024**2):
    """Cap bytes before writing; monitor floors while supervising the client.

    A killed build client does not prove daemon quiescence; callers must halt.
    """
    started = time.monotonic()
    with contextlib.ExitStack() as stack:
        stream = stack.enter_context(Path(log).open('xb'))
        error_stream = stack.enter_context(Path(stderr_path).open('xb')) if stderr_path else None
        selector = stack.enter_context(selectors.DefaultSelector())
        saved_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM,signal.SIGINT})
        try:
            # Children must not inherit the parent's temporary signal block.
            def child_unblock(): signal.pthread_sigmask(signal.SIG_SETMASK,saved_mask)
            process = subprocess.Popen(argv, cwd=ROOT, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE if error_stream else subprocess.STDOUT,
                                       start_new_session=True, preexec_fn=child_unblock)
            try:
                assert process.stdout is not None
                os.set_blocking(process.stdout.fileno(),False)
                selector.register(process.stdout,selectors.EVENT_READ,('stdout',stream,stdout_limit))
                if error_stream:
                    assert process.stderr is not None
                    os.set_blocking(process.stderr.fileno(),False)
                    selector.register(process.stderr,selectors.EVENT_READ,('stderr',error_stream,stderr_limit))
                counts={'stdout':0,'stderr':0}
                # Pending signals are delivered only after cleanup owns process.
                signal.pthread_sigmask(signal.SIG_SETMASK,saved_mask)
                while selector.get_map() or process.poll() is None:
                    now = {'output_free': shutil.disk_usage(output).free,
                           'docker_free': shutil.disk_usage(docker_root).free}
                    if min(now.values()) < RESERVE: raise ValueError('filesystem reserve reached')
                    if initial is not None and any(initial[k] - now[k] > forecast for k in now):
                        raise ValueError('reviewed role forecast exceeded')
                    if time.monotonic() - started > timeout: raise TimeoutError('bounded diagnostic command timed out')
                    for key, _ in selector.select(timeout=0.1):
                        kind, target, limit = key.data
                        try: data = os.read(key.fd,65536)
                        except BlockingIOError: continue
                        if not data:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        allowed = max(0,limit-counts[kind])
                        target.write(data[:allowed])
                        counts[kind] += min(len(data),allowed)
                        if len(data)>allowed:
                            target.flush()
                            raise OutputLimit('command output exceeded reviewed bound; partial retained')
                return process.wait(timeout=5)
            except BaseException:
                try: os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError: pass
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    try: os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    process.wait(timeout=5)
                raise
            finally:
                for key in list(selector.get_map().values()):
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                if process.stdout and not process.stdout.closed: process.stdout.close()
                if process.stderr and not process.stderr.closed: process.stderr.close()
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK,saved_mask)


def small_file(path, limit):
    path = Path(path)
    if path.is_symlink() or not path.is_file(): raise ValueError('regular bounded metadata file required')
    with path.open('rb') as f: data = f.read(limit + 1)
    if len(data) > limit: raise ValueError('metadata exceeds reviewed bound')
    return data


def probe(argv, path, output, docker_root, limit=65536):
    code=invoke(argv,path,output,docker_root,30,stdout_limit=limit)
    if code: raise ValueError('diagnostic metadata probe failed')
    return small_file(path,limit)


def validate_scanner_identity(path, expected_path):
    if path.is_symlink() or path.resolve() != expected_path.resolve() or not path.is_file():
        raise ValueError('scanner resolved outside reviewed installation')
    if sha(path) != SCANNER_SHA256: raise ValueError('scanner binary SHA mismatch')


def validate_scanner(path, expected_path, version_bytes):
    validate_scanner_identity(path, expected_path)
    try: version=json.loads(version_bytes)
    except (ValueError,UnicodeDecodeError): raise ValueError('invalid scanner version metadata')
    if not isinstance(version,dict) or version.get('Version')!='0.76.1':
        raise ValueError('scanner version mismatch')


def capture_db_metadata(source, destination):
    try:
        data=small_file(source,65536)
        if not isinstance(json.loads(data),dict): raise ValueError('invalid metadata')
        Path(destination).write_bytes(data)
        return {'status':'captured-not-freshness-verified','sha256':hashlib.sha256(data).hexdigest()}
    except DiagnosticInterrupted:
        raise
    except (OSError,ValueError,TypeError,UnicodeDecodeError):
        return {'status':'unknown'}


def report(raw, role):
    try:
        result = summarize_image_report(raw, role, 'synthetic-qualification', '0.76.1')
        return result
    except DiagnosticInterrupted:
        raise
    except Exception:
        return {'status': 'unavailable', 'reason': 'summary-error'}


def outcome(scan_exit, smoke_exit, summary):
    return ('completed' if scan_exit == 0 and smoke_exit == 0 and
            summary.get('status') == 'available' and summary.get('total_findings') == 0
            else 'findings-or-incomplete')


def phase_exit(value):
    if type(value) is not int or value < -255 or value > 255:
        return {'status':'unavailable','exit_code':None}
    return {'status':'zero_exit' if value == 0 else 'nonzero_exit','exit_code':value}


def stderr_hint(data, exit_code):
    text=data.lower()
    if b'toomanyrequests' in text or b'rate limit' in text: return 'possible_rate_limit'
    if b'failed to download vulnerability db' in text or b'unable to initialize a scanner' in text: return 'possible_scanner_or_db_initialization'
    if b'permission denied' in text: return 'possible_permission_denied'
    if b'no such image' in text or b'image not found' in text: return 'possible_image_not_found'
    if b'context deadline exceeded' in text: return 'possible_deadline'
    if b'fatal' in text: return 'unclassified_fatal'
    if exit_code not in (None,0) and not data: return 'nonzero_without_stderr'
    return 'unclassified' if data else 'none'


def phase_summary(role, item, output):
    """Expose only bounded controlled categories, counts and hashes, not tool text."""
    if role not in ROLES: raise ValueError('invalid role')
    result={'role':role,'scope':'diagnostic-only','build':phase_exit(item.get('build_exit')),
            'smoke':phase_exit(item.get('smoke_exit')),'scan':phase_exit(item.get('scan_exit'))}
    status=item.get('status')
    result['status']=status if status in ('completed','findings-or-incomplete','incomplete','not-run') else 'unknown'
    category=item.get('scan_error_category')
    result['scan_error_category']=category if category in ('timeout','output_limit','resource_or_other','process_error','interrupted') else 'none'
    raw_path=Path(output)/(role+'-trivy.json')
    err_path=Path(output)/(role+'-trivy.stderr')
    def details(path,maximum):
        try:
            value=small_file(path,maximum)
            return value,{'status':'available','bytes':len(value),'sha256':hashlib.sha256(value).hexdigest()}
        except DiagnosticInterrupted:raise
        except (OSError,ValueError):return None,{'status':'unavailable','bytes':None,'sha256':None}
    raw,raw_details=details(raw_path,16*1024**2)
    err,err_details=details(err_path,2*1024**2)
    if raw is None: raw_details['parse_category']='unavailable'
    elif not raw: raw_details['parse_category']='empty'
    elif len(raw)>8*1024**2: raw_details['parse_category']='oversize_for_summary'
    elif item.get('summary_status')=='available': raw_details['parse_category']='summary_available'
    else:
        try: json.loads(raw)
        except DiagnosticInterrupted:raise
        except (ValueError,UnicodeDecodeError,RecursionError): raw_details['parse_category']='invalid_json'
        else: raw_details['parse_category']='invalid_schema_or_summary_error'
    err_details['hint']=stderr_hint(err,item.get('scan_exit')) if err is not None else 'unavailable'
    result['report']=raw_details;result['stderr']=err_details
    db=item.get('database_metadata') or {}
    db_status=db.get('status') if isinstance(db,dict) else None
    db_sha=db.get('sha256') if isinstance(db,dict) else None
    if db_status!='captured-not-freshness-verified' or not isinstance(db_sha,str) or not re.fullmatch(r'[0-9a-f]{64}',db_sha):
        db_status='unknown';db_sha=None
    result['database_metadata']={'status':db_status,'sha256':db_sha}
    return result


def emit_phase_summary(role,item,output):
    try:
        payload=json.dumps(phase_summary(role,item,output),ensure_ascii=True,separators=(',',':'))
        if len(payload)>4096: raise ValueError('phase summary unexpectedly oversized')
        print('diagnostic-only phase-status '+payload,flush=True)
    except DiagnosticInterrupted:
        raise
    except Exception:
        # Reporting problems must never change scanner or diagnostic outcomes.
        try: print('diagnostic-only phase-status {"status":"unavailable"}',flush=True)
        except (OSError,ValueError): pass


def main():
    install_handlers()
    if (os.environ.get('GITHUB_REPOSITORY') != '5dg/nex-os' or os.environ.get('GITHUB_REF') != 'refs/heads/main' or
        os.environ.get('GITHUB_EVENT_NAME') not in ('push','workflow_dispatch')):
        raise ValueError('trusted repository, main and supported event required')
    for key in ('DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'):
        os.environ.pop(key,None)
    os.environ['DOCKER_HOST'] = 'unix:///var/run/docker.sock'
    output = Path(os.environ['RUNNER_TEMP']) / ('nex-image-diagnostic-' + os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT'])
    if not re.fullmatch(r'[0-9]+', os.environ['GITHUB_RUN_ID']) or not re.fullmatch(r'[0-9]+', os.environ['GITHUB_RUN_ATTEMPT']):
        raise ValueError('invalid hosted run identity')
    output.mkdir(mode=0o700)
    env_path = Path(os.environ['GITHUB_ENV'])
    with env_path.open('a') as f: f.write('NEX_DIAGNOSTIC_OUTPUT=' + str(output) + '\n')
    base = ROOT / 'diagnostics' / 'image-bases'
    for role in ROLES:
        if sha(base / (role + '.Dockerfile')) != EXPECTED[role]: raise ValueError('diagnostic Dockerfile changed: ' + role)
    expected_scanner = Path(os.environ['RUNNER_TEMP'])/'nex-diagnostic-tools'/'trivy'
    scanner = Path(shutil.which('trivy') or '')
    validate_scanner_identity(scanner,expected_scanner)
    head = probe(['git','rev-parse','HEAD'],output/'source-sha.txt',output,output,4096).decode('ascii').strip()
    if head != os.environ['GITHUB_SHA']: raise ValueError('checkout SHA differs from hosted event')
    docker_root = Path(probe(['docker','--host=unix:///var/run/docker.sock','info','--format','{{.DockerRootDir}}'],
                             output/'docker-root.txt',output,output,4096).decode('utf-8').strip())
    scanner_version = probe([str(scanner),'version','--format','json'],output/'scanner-version.json',output,docker_root)
    validate_scanner(scanner,expected_scanner,scanner_version)
    probe(['docker','--host=unix:///var/run/docker.sock','version','--format','{{json .}}'],output/'docker-version.json',output,docker_root)
    probe(['docker','--host=unix:///var/run/docker.sock','buildx','version'],output/'buildx-version.txt',output,docker_root)
    result = {'schema': 1, 'scope': 'Diagnostic only; no release, production or vulnerability clearance',
              'scanner_binary_sha256': sha(scanner),
              'source_sha': head, 'run_id': os.environ['GITHUB_RUN_ID'], 'attempt': os.environ['GITHUB_RUN_ATTEMPT'],
              'dockerfiles_sha256': EXPECTED, 'images': {}}
    def save(): (output/'result.json').write_text(json.dumps(result, indent=2, sort_keys=True)+'\n')
    save()
    for role in ROLES:
        building = False
        item = result['images'][role] = {'status': 'not-run'}
        save()
        tag = 'nex-diagnostic-' + os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT'] + '-' + role + ':probe'
        try:
            initial = admit(output, docker_root, role)
            item['admission'] = initial
            args = ['docker', '--host=unix:///var/run/docker.sock', 'build', '--no-cache', '--platform', 'linux/amd64',
                    '--secret', 'id=proxy_ca,src=/etc/ssl/certs/ca-certificates.crt',
                    '--label', 'org.nex.diagnostic.scope=non-release', '--label', 'org.nex.diagnostic.source='+head,
                    '-f', str(base/(role+'.Dockerfile')), '-t', tag, str(ROOT)]
            building = True
            code = invoke(args, output/(role+'-build.log'), output, docker_root, 1200, initial, FORECAST[role])
            item['build_exit'] = code
            if code: raise ValueError('image build failed; daemon quiescence unproven')
            building = False
            image = json.loads(probe(['docker','--host=unix:///var/run/docker.sock','image','inspect',tag],
                                     output/(role+'-image-inspect.json'),output,docker_root,1024**2))[0]
            item['image'] = {'id': image['Id'], 'layers': image['RootFS']['Layers'], 'os': image['Os'],
                             'architecture': image['Architecture'], 'user': image['Config']['User'],
                             'entrypoint': image['Config']['Entrypoint'], 'cmd': image['Config']['Cmd']}
            if item['image']['architecture'] != 'amd64': raise ValueError('wrong diagnostic architecture')
            owner = secrets.token_hex(16)
            item['smoke_owner'] = owner
            smoke_initial = {'output_free': shutil.disk_usage(output).free,
                             'docker_free': shutil.disk_usage(docker_root).free}
            if min(smoke_initial.values()) < RESERVE + 1024**3:
                raise ValueError('insufficient reserve for bounded synthetic smoke')
            smoke_error = None
            try:
                smoke_exit = invoke([sys.executable, '-I', str(ROOT/'diagnostics/image-bases/smoke.py'),
                                     role, image['Id'], owner], output/(role+'-smoke.log'), output, docker_root,
                                    180, smoke_initial, 1024**3, stdout_limit=1024**2)
            except DiagnosticInterrupted as error:
                smoke_exit = None
                smoke_error = type(error).__name__ + ': ' + str(error)
            except (OSError,ValueError,TimeoutError,subprocess.SubprocessError) as error:
                smoke_exit = None
                smoke_error = type(error).__name__ + ': ' + str(error)
            reconciliation = []
            for name in owned_smoke.names(role,os.environ['GITHUB_RUN_ID'],os.environ['GITHUB_RUN_ATTEMPT']):
                try: owned_smoke.reconcile(name,image['Id'],owner,role)
                except DiagnosticInterrupted as error:
                    reconciliation.append(type(error).__name__ + ': ' + str(error))
                except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as error:
                    reconciliation.append(type(error).__name__ + ': ' + str(error))
            item['smoke_exit'] = smoke_exit
            item['smoke_reconciliation_errors'] = reconciliation
            if smoke_error: item['smoke_error'] = smoke_error
            if smoke_exit != 0 or reconciliation:
                item['status'] = 'incomplete'
                item['halt_reason'] = 'smoke failed or interrupted; late daemon create cannot be ruled out'
                save()
                emit_phase_summary(role,item,output)
                break
            # Scan actual immutable image identity, even when smoke fails.
            report_file = output/(role+'-trivy.json')
            scan_log = output/(role+'-trivy.stderr')
            scan_initial = {'output_free': shutil.disk_usage(output).free,
                            'docker_free': shutil.disk_usage(docker_root).free}
            if min(scan_initial.values()) < RESERVE + 1024**3:
                raise ValueError('insufficient reserve for bounded scan')
            try:
                validate_scanner_identity(scanner,expected_scanner)
                item['scan_exit'] = invoke([str(scanner),'image','--db-repository','ghcr.io/aquasecurity/trivy-db:2',
                                            '--format','json','--list-all-pkgs','--exit-code','1',
                                            '--severity','UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL','--image-src','docker',image['Id']],
                                           report_file, output, docker_root, 300, scan_initial, 1024**3, scan_log,
                                           stdout_limit=16*1024**2, stderr_limit=2*1024**2)
            except DiagnosticInterrupted as error:
                item['scan_exit'] = None
                item['scan_error'] = str(error) + '; raw partial output retained'
                item['scan_error_category'] = 'interrupted'
                item['status'] = 'incomplete'
                item['halt_reason'] = 'interrupted during scan; no later phases started'
                save()
                emit_phase_summary(role,item,output)
                break
            except (TimeoutError,ValueError) as error:
                item['scan_exit'] = None
                item['scan_error'] = str(error) + '; raw partial output retained'
                item['scan_error_category'] = ('timeout' if isinstance(error,TimeoutError) else
                                               'output_limit' if isinstance(error,OutputLimit) else 'resource_or_other')
            except (OSError,subprocess.SubprocessError):
                item['scan_error_category'] = 'process_error'
                raise
            item['scan_sha256'] = sha(report_file)
            if report_file.stat().st_size > 8*1024**2:
                summary = {'status':'unavailable','reason':'oversized-report','truncated':True}
            else:
                summary = report(report_file.read_bytes(),role)
            print('diagnostic-only image-vulnerability-summary '+json.dumps(summary,ensure_ascii=True),flush=True)
            metadata = Path(os.environ.get('TRIVY_CACHE_DIR','/tmp/nex-diagnostic-trivy-cache'))/'db/metadata.json'
            item['database_metadata'] = capture_db_metadata(metadata, output/(role+'-trivy-db-metadata.json'))
            item['summary_status'] = summary.get('status')
            item['status'] = outcome(item['scan_exit'], smoke_exit, summary)
        except DiagnosticInterrupted as error:
            item['status'] = 'incomplete'
            item['error'] = type(error).__name__ + ': ' + str(error)
            item['halt_reason'] = ('interrupted build; daemon quiescence unproven' if building else
                                   'interrupted diagnostic; no later phases started')
            save()
            emit_phase_summary(role,item,output)
            break
        except (OSError,ValueError,TimeoutError,subprocess.SubprocessError) as error:
            item['status'] = 'incomplete'
            item['error'] = type(error).__name__ + ': ' + str(error)
            if building:
                item['halt_reason'] = 'build daemon cancellation/quiescence unproven; do not continue on this runner'
                save()
                emit_phase_summary(role,item,output)
                break
        save()
        emit_phase_summary(role,item,output)
    # Any finding, missing result or smoke failure keeps this diagnostic job red.
    return 0 if all(v['status']=='completed' for v in result['images'].values()) else 1

if __name__ == '__main__':
    try: sys.exit(main())
    except (DiagnosticInterrupted, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('Diagnostic incomplete: '+str(error),file=sys.stderr)
        sys.exit(1)
