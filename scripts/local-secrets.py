#!/usr/bin/env python3
"""Provision local service identities; never print or replace their values."""
import os,pathlib,secrets
root=pathlib.Path(__file__).resolve().parent.parent/'.local'
root.mkdir(mode=0o700,exist_ok=True)
for name in ['model-key','export-key','worker-key','guard-key','model-guard-key','export-guard-key','evidence-key','kernel-evidence-key','signing-seed','control-database-password','guard-database-password']:
    path=root/name
    if path.exists():
        if len(path.read_bytes())!=32:raise SystemExit(f'Invalid existing local key: {name}')
        continue
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(descriptor,'wb') as stream:stream.write(secrets.token_bytes(32))
for name in ['model-receipts','export-receipts','evidence']:(root/name).mkdir(mode=0o700,exist_ok=True)
print('Local service keys and private receipt directories prepared.')

for role in ['control','guard']:
    password=(root/(role+'-database-password')).read_bytes().hex()
    path=root/(role+'-database-url')
    data=('postgres://nex_'+role+':'+password+'@postgres:5432/nex?sslmode=disable').encode()
    if path.exists() and path.read_bytes()!=data:raise SystemExit('Existing database identity file differs')
    if not path.exists():
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(data)
