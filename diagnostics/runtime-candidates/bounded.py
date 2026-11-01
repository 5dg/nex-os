#!/usr/bin/env python3
"""Run one source-bound nonrelease image phase under existing disk limits."""
import os
from pathlib import Path
import re
import secrets
import shutil
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'diagnostics/image-bases'))
import image_diagnostic as diagnostic


def main(role, phase):
    if role not in ('guard', 'workspace') or phase not in ('build', 'database', 'smoke', 'scan'):
        raise ValueError('unsupported diagnostic phase')
    revision = os.environ['GITHUB_SHA']
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('exact source revision required')
    output = Path(os.environ['RUNNER_TEMP']) / ('nex-runtime-' + role)
    if output.is_symlink() or not output.is_dir():
        raise ValueError('existing owned output directory required')
    docker = ['docker', '--host=unix:///var/run/docker.sock']
    root = Path(diagnostic.probe(docker + ['info', '--format', '{{.DockerRootDir}}'],
                                 output / (phase + '-docker-root.txt'), output, output, 4096).decode().strip())
    if not root.is_absolute() or not root.is_dir():
        raise ValueError('actual Docker root required')
    if phase == 'build':
        initial = diagnostic.admit(output, root, role)
        command = docker + ['build', '--pull', '--platform', 'linux/amd64',
                   '--secret', 'id=proxy_ca,src=/etc/ssl/certs/ca-certificates.crt',
                   '--label', 'org.nex.diagnostic.scope=non-release',
                   '--label', 'org.nex.diagnostic.source=' + revision,
                   '--iidfile', str(output / 'image-id.txt'),
                   '-f', str(ROOT / ('diagnostics/runtime-candidates/' + role + '.Dockerfile')), str(ROOT)]
        return diagnostic.invoke(command, output / 'build.log', output, root, 1200,
                                 initial, diagnostic.FORECAST[role])
    if phase == 'smoke':
        image = (output / 'image-id.txt').read_text().strip()
        run, attempt = os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT']
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', image) or not all(
                re.fullmatch(r'[0-9]+', value) for value in (run, attempt)):
            raise ValueError('immutable image and numeric run identity required')
        initial = {'output_free': shutil.disk_usage(output).free, 'docker_free': shutil.disk_usage(root).free}
        if min(initial.values()) < diagnostic.RESERVE + 1024**3:
            raise ValueError('insufficient reserve for synthetic smoke')
        owner = secrets.token_hex(16)
        try:
            command = [sys.executable, '-I', str(ROOT / 'diagnostics/image-bases/smoke.py'), role, image, owner]
            return diagnostic.invoke(command, output / 'smoke.log', output, root, 180,
                                     initial, 1024**3, stdout_limit=1024**2)
        finally:
            for name in diagnostic.owned_smoke.names(role, run, attempt):
                diagnostic.owned_smoke.reconcile(name, image, owner, role)
    scanner = Path(os.environ['RUNNER_TEMP']) / 'nex-runtime-trivy/trivy'
    if scanner.is_symlink() or diagnostic.sha(scanner) != diagnostic.SCANNER_SHA256:
        raise ValueError('pinned scanner identity required')
    cache = Path(os.environ['TRIVY_CACHE_DIR'])
    diagnostic.validate_cache_filesystem(cache, output, root)
    if phase == 'database':
        initial = diagnostic.admit(output, root, role)
        scratch = output / 'database-tmp'
        scratch.mkdir(mode=0o700)
        command = [str(scanner), 'image', '--db-repository', 'ghcr.io/aquasecurity/trivy-db:2',
                   '--download-db-only']
        return diagnostic.invoke(command, output / 'database.log', output, root, 600, initial,
                                 diagnostic.FORECAST[role], scanner_tmp=scratch)
    image = (output / 'image-id.txt').read_text().strip()
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
        raise ValueError('immutable built image required')
    initial = diagnostic.admit_scan(output, root, role)
    scratch = output / 'scanner-tmp'
    scratch.mkdir(mode=0o700)
    command = [str(scanner), 'image', '--db-repository', 'ghcr.io/aquasecurity/trivy-db:2',
               '--format', 'json', '--list-all-pkgs', '--exit-code', '1',
               '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL', '--image-src', 'docker', image]
    return diagnostic.invoke(command, output / 'trivy.json', output, root, 600, initial,
                             diagnostic.SCAN_FORECAST[role], output / 'trivy.stderr',
                             stdout_limit=16*1024**2, stderr_limit=2*1024**2, scanner_tmp=scratch)


if __name__ == '__main__':
    diagnostic.install_handlers()
    if len(sys.argv) != 3:
        raise SystemExit('Usage: bounded.py guard|workspace build|database|smoke|scan')
    try:
        raise SystemExit(main(*sys.argv[1:]))
    except (OSError, ValueError, TimeoutError) as error:
        raise SystemExit('Nonrelease diagnostic incomplete: ' + str(error))
