#!/usr/bin/env python3
"""Create an isolated synthetic state/PKI generation without replacing history."""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import secrets
import ssl
import subprocess

root = pathlib.Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser()
parser.add_argument('--state', type=pathlib.Path, default=root / '.local/qualification')
parser.add_argument('--rotate-pki', action='store_true', help='new generation; preserve prior keys/data, then recreate every client/server')
parser.add_argument('--pki-tool', type=pathlib.Path, default=root / 'bin/qualification-pki')
args = parser.parse_args()
state = args.state.absolute()
if state in (root, root / '.local'):
    raise SystemExit('A separate qualification state directory is required.')
marker = state / 'synthetic-qualification.state'
if state.exists() and any(state.iterdir()) and not marker.exists():
    raise SystemExit('Refusing unknown/non-qualification state directory.')
state.mkdir(mode=0o700, parents=True, exist_ok=True)
if state.stat().st_mode & 0o077:
    raise SystemExit('Qualification state must be private (mode0700).')
if marker.exists() and marker.read_text() != 'synthetic-qualification\n':
    raise SystemExit('Qualification marker mismatch.')
if not marker.exists():
    marker.write_text('synthetic-qualification\n');marker.chmod(0o600)
for directory in ('secrets', 'model-receipts', 'export-receipts', 'evidence', 'pki'):
    (state / directory).mkdir(mode=0o700, exist_ok=True)

secrets_directory = state / 'secrets'
def create(name, data, expected_length):
    path = secrets_directory / name
    if path.exists():
        if path.is_symlink() or len(path.read_bytes()) != expected_length or path.stat().st_mode & 0o077:
            raise SystemExit('Invalid existing qualification secret: ' + name)
        return path
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
    return path
for name in ('model-key','export-key','worker-key','evidence-key','kernel-evidence-key','signing-seed','control-database-password','guard-database-password'):
    create(name, secrets.token_bytes(32), 32)
create('admin-database-password', secrets.token_hex(32).encode(), 64)
create('oidc-client-secret', secrets.token_hex(32).encode(), 64)
for name, username, password in [('control','nex_control',(secrets_directory/'control-database-password').read_bytes().hex()),('guard','nex_guard',(secrets_directory/'guard-database-password').read_bytes().hex()),('admin','nex',(secrets_directory/'admin-database-password').read_text())]:
    encoded=('postgres://'+username+':'+password+'@postgres:5432/nex?sslmode=verify-full').encode()
    path=secrets_directory/(name+'-database-url')
    if path.exists():
        if path.read_bytes()!=encoded or path.stat().st_mode&0o077:
            raise SystemExit('Existing qualification database identity differs: '+name)
    else:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(encoded)

spec=root/'deploy/qualification/pki.json'
spec_hash=hashlib.sha256(spec.read_bytes()).hexdigest()
active=state/'current-pki'
if args.rotate_pki or not active.exists():
    binary=args.pki_tool
    if not binary.exists():raise SystemExit('Build qualification fixtures before initializing PKI.')
    generation=state/'pki'/('generation-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(4))
    subprocess.run([str(binary),'--config',str(spec),'--directory',str(generation)],check=True)
    (generation/'spec-sha256').write_text(spec_hash+'\n')
    replacement=state/('pki-link-'+secrets.token_hex(4))
    replacement.symlink_to(generation.relative_to(state))
    os.replace(replacement,active)
    print('Synthetic PKI generation created; previous generations/data preserved. Recreate all qualification peers before using a rotated generation.')
else:
    generation=active.resolve()
    if not generation.is_relative_to(state/'pki') or (generation/'spec-sha256').read_text().strip()!=spec_hash:
        raise SystemExit('Existing PKI spec changed; explicit new-generation rotation is required.')
    manifest=json.loads((generation/'manifest.json').read_text())
    for identity in manifest['identities']:
        path=generation/identity['certificate']
        decoded=ssl._ssl._test_decode_cert(str(path))
        if ssl.cert_time_to_seconds(decoded['notAfter']) <= datetime.datetime.now(datetime.timezone.utc).timestamp()+60:
            raise SystemExit('Qualification certificate expires soon; explicitly rotate PKI and recreate peers.')
    print('Existing private qualification state and active test PKI preserved.')
