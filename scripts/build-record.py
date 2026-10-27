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

root = pathlib.Path(__file__).resolve().parent.parent

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def inputs():
    listed = subprocess.run(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=root, capture_output=True, check=True).stdout.split(b'\0')
    paths = [root / os.fsdecode(p) for p in listed if p and pathlib.Path(os.fsdecode(p)).parts[0] in ('services', 'packages', 'policies') and not os.fsdecode(p).endswith('_test.go')]
    paths = [p for p in paths if p.is_file()]
    paths.extend(root / p for p in ('go.mod', 'go.sum', '.tool-versions', 'rust-toolchain.toml'))
    files = {str(p.relative_to(root)): digest(p) for p in sorted(set(paths))}
    encoded = json.dumps(files, sort_keys=True, separators=(',', ':')).encode()
    return {'algorithm': 'sha256 of sorted compact JSON path-to-sha256 map', 'sha256': hashlib.sha256(encoded).hexdigest(), 'files': files}

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

if len(sys.argv) != 3 or sys.argv[1] not in ('begin', 'finish'):
    raise SystemExit('Usage: scripts/build-record.py begin SNAPSHOT | finish SNAPSHOT')
path = pathlib.Path(sys.argv[2])
if sys.argv[1] == 'begin':
    revision = subprocess.run(['git', 'rev-parse', '--verify', 'HEAD'], cwd=root, capture_output=True, text=True)
    os_release = {}
    for line in pathlib.Path('/etc/os-release').read_text().splitlines():
        key, separator, value = line.partition('=')
        if separator and key in ('ID', 'VERSION_ID', 'PRETTY_NAME'):
            os_release[key] = value.strip('"')
    record = {'schema_version': 1, 'build_mode': 'local-host-development', 'production_attestation': False, 'source_revision': revision.stdout.strip() if revision.returncode == 0 else None, 'inputs': inputs(), 'builder': {'os': os_release, 'machine': platform.machine(), 'go': executable('go'), 'rustc': executable('rustc'), 'cargo': executable('cargo'), 'go_target': command('go', 'env', 'GOOS', 'GOARCH', 'CGO_ENABLED'), 'libc': subprocess.run(['ldd', '--version'], capture_output=True, text=True).stdout.splitlines()[0]}}
    (root / 'bin/build-inputs.json').unlink(missing_ok=True)
    write(path, record)
else:
    record = json.loads(path.read_text())
    if record['inputs'] != inputs():
        raise SystemExit('Build inputs changed during compilation; freeze source and rebuild.')
    record['binaries'] = {name: digest(root / 'bin' / name) for name in ('control', 'dev-issuer', 'model', 'executor', 'worker', 'evidence', 'guard-kernel')}
    record['rust_dynamic_dependencies'] = command('ldd', str(root / 'bin/guard-kernel')).splitlines()
    write(root / 'bin/build-inputs.json', record)
    print('Recorded host development inputs, compiler/ABI identity and binary hashes; no production attestation claimed.')
