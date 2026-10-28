#!/usr/bin/env python3
"""Record local compiler inputs/ABI and binary hashes without claiming attestation.

The fast development build intentionally runs on the host. This record makes
that boundary explicit; qualification builds must use the pinned builder path.
"""
import hashlib
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile
sys.dont_write_bytecode = True
from source_record import identity, verify_artifacts

root = pathlib.Path(__file__).resolve().parent.parent

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def inputs():
    return identity(root)['inputs']

def command(*arguments):
    return subprocess.run(arguments, cwd=root, capture_output=True, text=True, check=True).stdout.strip()

def executable(name):
    path = shutil.which(name)
    if not path:
        raise SystemExit(f'Required build tool missing: {name}')
    # rustc/cargo are commonly rustup shims; identify the actual selected tool.
    if name in ('rustc', 'cargo') and shutil.which('rustup'):
        path = command('rustup', 'which', name)
    path = pathlib.Path(path).resolve()
    return {'version': command(name, 'version' if name == 'go' else '--version'), 'sha256': digest(path)}

def write(path, value):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.build-record-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

if len(sys.argv) != 3 or sys.argv[1] not in ('begin', 'finish', 'verify-tools'):
    raise SystemExit('Usage: scripts/build-record.py begin SNAPSHOT | finish SNAPSHOT | verify-tools RECORD')
path = pathlib.Path(sys.argv[2])
if sys.argv[1] == 'verify-tools':
    verify_artifacts(path, root, ('evidence', 'qualification-pki'))
    print('Fresh source-bound qualification tools verified')
elif sys.argv[1] == 'begin':
    source_identity = identity(root)
    os_release = {}
    for line in pathlib.Path('/etc/os-release').read_text().splitlines():
        key, separator, value = line.partition('=')
        if separator and key in ('ID', 'VERSION_ID', 'PRETTY_NAME'):
            os_release[key] = value.strip('"')
    record = {'schema_version': 2, 'build_mode': 'local-host-development', 'production_attestation': False, 'source_revision': source_identity['revision'], 'inputs': source_identity['inputs'], 'builder': {'os': os_release, 'machine': platform.machine(), 'go': executable('go'), 'rustc': executable('rustc'), 'cargo': executable('cargo'), 'go_target': command('go', 'env', 'GOOS', 'GOARCH', 'CGO_ENABLED'), 'libc': subprocess.run(['ldd', '--version'], capture_output=True, text=True).stdout.splitlines()[0]}}
    (root / 'bin/build-inputs.json').unlink(missing_ok=True)
    write(path, record)
else:
    record = json.loads(path.read_text())
    if record['inputs'] != inputs():
        raise SystemExit('Build inputs changed during compilation; freeze source and rebuild.')
    names = ['control', 'dev-issuer', 'model', 'executor', 'worker', 'evidence', 'guard-kernel']
    if os.environ.get('NEX_BUILD_QUALIFICATION_FIXTURES') == '1':
        names += ['qualification-edge', 'qualification-policy-edge', 'qualification-pki', 'qualification-issuer']
        record['build_mode'] = 'local-host-synthetic-qualification'
    record['binaries'] = {name: digest(root / 'bin' / name) for name in names}
    record['rust_dynamic_dependencies'] = command('ldd', str(root / 'bin/guard-kernel')).splitlines()
    write(root / 'bin/build-inputs.json', record)
    print('Recorded host development inputs, compiler/ABI identity and binary hashes; no production attestation claimed.')
