#!/usr/bin/env python3
"""Build the downstream OPA for synthetic foundation checks.

This is a single-build CI diagnostic, not a reproducible canonical candidate or
an attestation. A failure never falls back to the older vendor executable.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from opa_image import BASE_LAYER, VENDOR_CONFIG, VENDOR_EXEC_LAYER, VENDOR_IMAGE, reconstruct, verify_reconstruction
from source_record import atomic_json, identity, sha256

GO_IMAGE = 'golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5'
ROOT = Path(__file__).resolve().parent.parent


def build(output, ca):
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise ValueError('fresh absolute diagnostic output directory required')
    if not ca.is_absolute() or ca.is_symlink() or not ca.is_file():
        raise ValueError('regular absolute build CA bundle required')
    source = identity(ROOT)
    if not source['revision']:
        raise ValueError('source checkout revision required')
    epoch = int(subprocess.check_output(['git', 'show', '-s', '--format=%ct', source['revision']], cwd=ROOT, text=True).strip())
    output.mkdir(mode=0o700)
    for name in ('work', 'bin', 'package'):
        (output / name).mkdir(mode=0o700)
    env = {key: value for key, value in os.environ.items() if key not in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH')}
    docker = ['docker', '--host=unix:///var/run/docker.sock']

    def run(*args, capture=False):
        return subprocess.run([*docker, *args], env=env, text=True, check=True,
                              stdout=subprocess.PIPE if capture else sys.stderr).stdout

    run('pull', GO_IMAGE)
    compiler = json.loads(run('image', 'inspect', GO_IMAGE, '--format',
        '{"Id":{{json .Id}},"RepoDigests":{{json .RepoDigests}},"Os":{{json .Os}},"Architecture":{{json .Architecture}}}', capture=True))
    if GO_IMAGE not in (compiler.get('RepoDigests') or []) or compiler.get('Os') != 'linux' or compiler.get('Architecture') != 'amd64':
        raise ValueError('pinned compiler image identity differs')
    command = ['run', '--rm', '--init', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges:true',
               '--user', f'{os.getuid()}:{os.getgid()}', '--cpus=2', '--memory=4g', '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m']
    for src, dst, readonly in ((ROOT, '/src', True), (output / 'work', '/work', False),
                                (output / 'bin', '/out', False), (output / 'package', '/package', False), (ca, '/run/ca.crt', True)):
        command.extend(['--mount', f'type=bind,src={src},dst={dst}' + (',readonly' if readonly else '')])
    for key, value in {'SSL_CERT_FILE': '/run/ca.crt', 'SOURCE_DATE_EPOCH': str(epoch), 'GOTOOLCHAIN': 'local', 'CGO_ENABLED': '0'}.items():
        command.extend(['-e', key + '=' + value])
    for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy'):
        if key in env:
            command.extend(['-e', key])
    run(*command, GO_IMAGE, 'sh', '/src/scripts/canonical-opa.sh')
    binary = output / 'bin/opa'
    if binary.is_symlink() or not binary.is_file():
        raise ValueError('compiler did not export a regular OPA binary')
    run('pull', VENDOR_IMAGE)
    inspected = json.loads(run('image', 'inspect', VENDOR_IMAGE, '--format',
        '{"Id":{{json .Id}},"RepoDigests":{{json .RepoDigests}},"Os":{{json .Os}},"Architecture":{{json .Architecture}},"RootFS":{{json .RootFS}}}', capture=True))
    vendor_archive = output / 'vendor.tar'
    run('image', 'save', '-o', str(vendor_archive), VENDOR_CONFIG)
    archive = output / 'opa.tar'
    receipt = reconstruct(vendor_archive, inspected, binary, ROOT / 'deploy/qualification/opa/LICENSE', archive, epoch, source['revision'], source['inputs']['sha256'])
    verify_reconstruction(archive, receipt, sha256(binary), source['revision'], source['inputs']['sha256'], epoch)
    if identity(ROOT) != source:
        raise ValueError('source changed during diagnostic OPA build')
    run('image', 'load', '--input', str(archive))
    loaded = json.loads(run('image', 'inspect', receipt['id'], '--format',
        '{"Id":{{json .Id}},"RootFS":{{json .RootFS}},"Labels":{{json .Config.Labels}}}', capture=True))
    labels = loaded.get('Labels') or {}
    if (loaded.get('Id') != receipt['id'] or loaded.get('RootFS', {}).get('Layers') != receipt['layers'] or
            receipt['layers'][0] != BASE_LAYER or VENDOR_EXEC_LAYER in receipt['layers'] or
            labels.get('org.nex.source.inputs') != source['inputs']['sha256'] or
            labels.get('org.opencontainers.image.revision') != source['revision']):
        raise ValueError('loaded image differs from verified source-bound archive')
    atomic_json(output / 'receipt.json', {'scope': 'single foundation diagnostic; not release attestation', 'source': source,
                'compiler': compiler, 'vendor': inspected, 'reconstruction': receipt, 'loaded': loaded})
    return receipt['id']


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('Usage: foundation-opa.py /absolute/new-output-directory /absolute/public-ca.crt')
    try:
        print(build(Path(sys.argv[1]), Path(sys.argv[2])))
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        raise SystemExit('Foundation OPA build failed: ' + str(error))
