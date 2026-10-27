#!/usr/bin/env python3
"""Run release vulnerability gates, preserving every result, including failures.

Install the pinned scanner versions used by CI. Missing tools or advisory DB
failures are incomplete checks and return nonzero; they never count as clean.
"""
import datetime
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parent.parent
output = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else root / '.local/release-evidence')
output.mkdir(parents=True, exist_ok=True)
checks = []

def executable_digest(command):
    with pathlib.Path(shutil.which(command)).open('rb') as executable:
        return hashlib.file_digest(executable, 'sha256').hexdigest()

def run(name, command, cwd=root):
    record = {'name': name, 'command': command, 'status': 'not_run', 'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    if shutil.which(command[0]) is None:
        record['reason'] = 'Required scanner not installed.'
    else:
        try:
            environment = os.environ.copy()
            if command[0] == 'trivy':
                # A saved remote Docker context must not redirect release scans.
                for key in ('DOCKER_CONTEXT', 'DOCKER_TLS', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'):
                    environment.pop(key, None)
                environment['DOCKER_HOST'] = 'unix:///var/run/docker.sock'
                environment.setdefault('TRIVY_CACHE_DIR', '/tmp/nex-trivy-cache')
            result = subprocess.run(command, cwd=cwd, capture_output=True, timeout=300, env=environment)
            (output / (name + '.stdout')).write_bytes(result.stdout)
            (output / (name + '.stderr')).write_bytes(result.stderr)
            record['exit_code'] = result.returncode
            record['status'] = 'passed' if result.returncode == 0 else 'failed'
            if result.returncode:
                record['reason'] = 'Findings or scanner failure; inspect the retained scanner output.'
        except subprocess.TimeoutExpired as error:
            (output / (name + '.stdout')).write_bytes(error.stdout or b'')
            (output / (name + '.stderr')).write_bytes(error.stderr or b'')
            record['status'] = 'failed'
            record['reason'] = 'Scanner timed out; no clean result established.'
        except OSError as error:
            (output / (name + '.stderr')).write_text(str(error) + '\n')
            record['status'] = 'failed'
            record['reason'] = 'Scanner could not launch; no clean result established.'
    record['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    checks.append(record)
    (output / 'vulnerability-status.json').write_text(json.dumps({'schema_version': 1, 'checks': checks}, indent=2) + '\n')
    print(f'{name}: {record["status"]}', flush=True)

run('source-inventory', [sys.executable, str(root / 'scripts/release-inventory.py'), str(output)])
versions = {}
for tool, arguments in {'govulncheck': ['-version'], 'cargo-audit': ['--version'], 'trivy': ['--version'], 'npm': ['--version']}.items():
    if shutil.which(tool):
        try:
            version = subprocess.run([tool] + arguments, capture_output=True, text=True, timeout=15)
            versions[tool] = {'exit_code': version.returncode, 'output': (version.stdout + version.stderr).strip(), 'executable_sha256': executable_digest(tool)}
        except (subprocess.TimeoutExpired, OSError) as error:
            versions[tool] = {'status': 'version_unavailable', 'reason': str(error)}
    else:
        versions[tool] = {'status': 'not_installed'}
(output / 'scanner-versions.json').write_text(json.dumps({'schema_version': 1, 'scope': 'Tool version queries only; scan outcomes are in vulnerability-status.json.', 'tools': versions}, indent=2) + '\n')

run('go-vulnerabilities', ['govulncheck', '-json', './...'])
run('rust-vulnerabilities', ['cargo-audit', 'audit', '--file', 'services/guard-kernel/Cargo.lock', '--json'])
run('npm-vulnerabilities', ['npm', 'audit', '--json', '--audit-level=low'], root / 'apps/workspace')
# Built-image scans include OS packages; never silently substitute a source-only scan.
for name in ('control', 'guard', 'workspace'):
    run(name + '-image-vulnerabilities', ['trivy', 'image', '--db-repository', 'ghcr.io/aquasecurity/trivy-db:2', '--format', 'json', '--exit-code', '1', '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL', '--image-src', 'docker', 'nex-' + name + ':local'])

complete = all(check['status'] == 'passed' for check in checks)
(output / 'vulnerability-status.json').write_text(json.dumps({'schema_version': 1, 'gate': 'passed' if complete else 'blocked', 'checks': checks}, indent=2) + '\n')
sys.exit(0 if complete else 1)
