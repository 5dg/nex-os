#!/usr/bin/env python3
"""Emit a CycloneDX 1.6 dependency inventory from resolved, frozen inputs.

Includes development/optional dependencies and pinned base images. This is a
source/dependency SBOM, not a claim about OS files inside a built image. Record
built image identities separately and scan those images before release.
"""
import base64
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tomllib
import urllib.parse
import uuid
sys.dont_write_bytecode = True
from source_record import identity as source_identity, resolve_image

root = pathlib.Path(__file__).resolve().parent.parent
output = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else root / '.local/release-evidence')
output.mkdir(parents=True, exist_ok=True)
profile = os.environ.get('NEX_RELEASE_PROFILE', 'development')
if profile not in ('development', 'synthetic-qualification'):
    raise SystemExit('Unsupported release inventory profile')
components = {}

def component(ecosystem, name, version, properties=None, hashes=None):
    # '/' separates purl namespace segments; encode '@' in npm scope names.
    purl = f'pkg:{ecosystem}/{urllib.parse.quote(name, safe="/")}@{urllib.parse.quote(version, safe="")}'
    value = {'type': 'library', 'bom-ref': purl, 'name': name, 'version': version, 'purl': purl}
    if properties:
        value['properties'] = [{'name': key, 'value': str(val)} for key, val in sorted(properties.items())]
    if hashes:
        value['hashes'] = hashes
    components[purl] = value

result = subprocess.run(['go', 'list', '-mod=readonly', '-m', '-json', 'all'], cwd=root, capture_output=True, text=True, check=True)
decoder = json.JSONDecoder()
remaining = result.stdout
while remaining.strip():
    module, end = decoder.raw_decode(remaining.lstrip())
    remaining = remaining.lstrip()[end:]
    if module.get('Main'):
        continue
    if module.get('Replace'):
        raise SystemExit('Release inventory requires explicit handling of replaced Go modules.')
    component('golang', module['Path'], module['Version'], {'nex:go:module-sum': module.get('Sum', '')})

lock = json.loads((root / 'apps/workspace/package-lock.json').read_text())
for path, package in lock['packages'].items():
    if not path:
        continue
    name = package.get('name') or path.rsplit('node_modules/', 1)[-1]
    properties = {'nex:dependency-source': 'package-lock.json', 'nex:development': str(package.get('dev', False)).lower(), 'nex:optional': str(package.get('optional', False)).lower()}
    hashes = []
    for integrity in package.get('integrity', '').split():
        algorithm, _, encoded = integrity.partition('-')
        if algorithm in ('sha256', 'sha384', 'sha512'):
            hashes.append({'alg': 'SHA-' + algorithm[3:], 'content': base64.b64decode(encoded).hex()})
    component('npm', name, package['version'], properties, hashes)

lock = tomllib.loads((root / 'services/guard-kernel/Cargo.lock').read_text())
for package in lock['package']:
    if 'source' not in package:
        continue
    hashes = [{'alg': 'SHA-256', 'content': package['checksum']}] if 'checksum' in package else []
    component('cargo', package['name'], package['version'], {'nex:dependency-source': package['source']}, hashes)

inputs = ['go.mod', 'go.sum', 'apps/workspace/package.json', 'apps/workspace/package-lock.json', 'services/guard-kernel/Cargo.toml', 'services/guard-kernel/Cargo.lock', 'deploy/local/compose.yaml']
if profile == 'synthetic-qualification':
    inputs += ['deploy/qualification/compose.yaml', 'deploy/qualification/pki.json']
inputs += [str(path.relative_to(root)) for path in sorted((root / 'deploy').rglob('Dockerfile*'))]
input_hashes = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in inputs}
identity = hashlib.sha256(json.dumps(input_hashes, sort_keys=True).encode()).hexdigest()
bom = {
    'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
    'serialNumber': 'urn:uuid:' + str(uuid.uuid5(uuid.NAMESPACE_URL, 'nex.os/source-inventory/' + identity)),
    'metadata': {
        'component': {'type': 'application', 'name': 'Nex.os', 'version': 'alpha-0.4'},
        'properties': [{'name': 'nex:inventory-scope', 'value': 'Source dependencies including development and optional packages; no image OS-package inventory.'}, {'name': 'nex:runtime-profile', 'value': profile}],
    },
    'components': [components[key] for key in sorted(components)],
}
(output / 'source-sbom.cdx.json').write_text(json.dumps(bom, indent=2) + '\n')
if profile == 'synthetic-qualification':
    compose = json.loads((root / 'deploy/qualification/compose.yaml').read_text())
    images = sorted({resolve_image(service['image']) for service in compose['services'].values()})
else:
    images = sorted(set(re.findall(r'^\s+image:\s*([^\s#]+)', (root / 'deploy/local/compose.yaml').read_text(), re.MULTILINE)))
(output / 'inventory-inputs.json').write_text(json.dumps({'schema_version': 1, 'profile': profile, 'sha256': input_hashes, 'compose_images': images}, indent=2) + '\n')
# Source identity remains useful before a first commit, without including ignored
# local secrets, receipts, build outputs, .git internals or node_modules.
source = source_identity(root)
source_hashes = source['inputs']['files']
(output / 'source-sha256.json').write_text(json.dumps(source_hashes, indent=2) + '\n')
(output / 'source-identity.json').write_text(json.dumps(source, indent=2) + '\n')
print(f'Wrote source SBOM with {len(components)} resolved components to {output}.')
