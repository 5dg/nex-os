"""Reconstruct an OPA image from the verified vendor base and a new binary.

The vendor executable layer is deliberately excluded, not hidden under another
layer. This helper does not build, scan or qualify the image.
"""
import copy
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tarfile

from canonical_image import archive_identity
from source_record import sha256
from source_record import atomic_json

VENDOR_IMAGE = 'openpolicyagent/opa@sha256:02d31f4e34dcae04d87b542796aa0d089e42039fe6bbc5601587be44fb218963'
VENDOR_CONFIG = 'sha256:b4014616f8e378a07fc4acd3ea3cc169dcd9b80178ab0f0cfcf386163ea5030d'
BASE_LAYER = 'sha256:fb755f0d1135aa0c93f43ab8f7a4877f957290b2bef85224c41c3b0b09658eb7'
VENDOR_EXEC_LAYER = 'sha256:2ebcf72fa26638157a4787c58b5eb5d06caa59671cc56cbff326ca0839899300'
LICENSE_SHA256 = 'c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08'
NOTICE = b'Nex OS downstream OPA build; not an official OPA release.\n'


def tar_entry(name, size, mode, epoch, directory=False):
    item = tarfile.TarInfo(name)
    item.uid = item.gid = 0
    item.uname = item.gname = ''
    item.mtime = epoch
    item.mode = mode
    item.size = size
    if directory:
        item.type = tarfile.DIRTYPE
    return item


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def downstream_config(config, layers, revision, source_hash):
    result = copy.deepcopy(config)
    result['rootfs'] = {'type': 'layers', 'diff_ids': layers}
    for field in ('history', 'created', 'author'):
        result.pop(field, None)
    labels = result['config'].setdefault('Labels', {})
    if not isinstance(labels, dict):
        raise ValueError('vendor labels must be an object')
    for field in list(labels):
        if field.startswith('dev.chainguard.') or field in {
            'org.opencontainers.image.vendor', 'org.opencontainers.image.created',
            'org.opencontainers.image.url', 'org.opencontainers.image.title',
            'org.opencontainers.image.authors'}:
            del labels[field]
    labels.update({'org.nex.qualification.builder': 'canonical-container',
                   'org.opencontainers.image.source': 'https://github.com/5dg/nex-os',
                   'org.opencontainers.image.title': 'Nex OS downstream OPA',
                   'org.opencontainers.image.revision': revision,
                   'org.nex.source.inputs': source_hash,
                   'org.nex.opa.downstream': 'true',
                   'org.nex.opa.vendor-base': VENDOR_IMAGE})
    return result


def reconstruct(base_archive, inspected, binary, license_file, output, epoch, revision, source_hash):
    """Return a source-bound image ID after checking vendor and archive bytes."""
    if (not isinstance(inspected, dict) or not isinstance(inspected.get('RootFS'), dict) or inspected.get('Id') != VENDOR_CONFIG or
            VENDOR_IMAGE not in (inspected.get('RepoDigests') or []) or
            inspected.get('Os') != 'linux' or inspected.get('Architecture') != 'amd64' or
            inspected['RootFS'].get('Layers') != [BASE_LAYER, VENDOR_EXEC_LAYER]):
        raise ValueError('pinned vendor image identity or layer chain mismatch')
    if (type(epoch) is not int or not 0 <= epoch <= 0o77777777777 or
            not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', revision) or
            not re.fullmatch(r'[0-9a-f]{64}', source_hash)):
        raise ValueError('source revision, inputs and bounded epoch required')
    for path in (base_archive, binary, license_file):
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise ValueError('regular, nonempty verified input required')
    if output.exists() or output.is_symlink():
        raise ValueError('image archive must be fresh')
    if binary.stat().st_size > 256 * 1024 * 1024 or sha256(license_file) != LICENSE_SHA256:
        raise ValueError('bounded binary and pinned upstream license required')
    original_archive_hash = sha256(base_archive)
    # Docker can retain local repository tags in a save of the inspected vendor
    # image. Those labels are not part of the pinned image configuration or
    # layer identities, and are never copied into the generated archive.
    vendor = archive_identity(base_archive, allow_repo_tags=True)
    if vendor['id'] != VENDOR_CONFIG or vendor['layers'] != [BASE_LAYER, VENDOR_EXEC_LAYER]:
        raise ValueError('vendor archive does not match inspected image')
    with tarfile.open(base_archive, 'r:') as archive:
        manifest = json.load(archive.extractfile('manifest.json'))[0]
        raw_vendor_config = archive.extractfile(manifest['Config']).read()
        if 'sha256:' + hashlib.sha256(raw_vendor_config).hexdigest() != VENDOR_CONFIG:
            raise ValueError('vendor config bytes differ from pinned image')
        config = json.loads(raw_vendor_config)
        if config.get('os') != 'linux' or config.get('architecture') != 'amd64':
            raise ValueError('unexpected vendor platform')
        runtime = config.get('config')
        if not isinstance(runtime, dict) or runtime.get('User') != '1000:1000' or runtime.get('Entrypoint') != ['/opa'] or runtime.get('Cmd') != ['run']:
            raise ValueError('unexpected vendor runtime configuration')
        with archive.extractfile(manifest['Layers'][0]) as stream:
            base = stream.read(16 * 1024 * 1024 + 1)
        if len(base) > 16 * 1024 * 1024 or 'sha256:' + hashlib.sha256(base).hexdigest() != BASE_LAYER:
            raise ValueError('verified base layer required')
        with tarfile.open(fileobj=io.BytesIO(base), mode='r:') as layer:
            if any(member.name.lstrip('./') == 'opa' for member in layer):
                raise ValueError('vendor executable present in retained base')
        with tarfile.open(fileobj=archive.extractfile(manifest['Layers'][1]), mode='r:*') as layer:
            members = layer.getmembers()
            if len(members) != 1 or not members[0].isfile() or members[0].name.lstrip('./') != 'opa':
                raise ValueError('unexpected vendor executable layer')
            old = hashlib.file_digest(layer.extractfile(members[0]), 'sha256').hexdigest()
    binary_hash = sha256(binary)
    if binary_hash == old:
        raise ValueError('vendor executable must not be reused')
    license_bytes = license_file.read_bytes()
    if len(license_bytes) > 128 * 1024:
        raise ValueError('bounded license required')
    # The generated layer is bounded by the compiled binary, not an extracted
    # user archive; no vendor executable or vendor layer is copied into it.
    layer_buffer = io.BytesIO()
    with tarfile.open(fileobj=layer_buffer, mode='w', format=tarfile.USTAR_FORMAT) as layer:
        with binary.open('rb') as stream:
            layer.addfile(tar_entry('opa', binary.stat().st_size, 0o555, epoch), stream)
        for name in ('usr/', 'usr/share/', 'usr/share/licenses/', 'usr/share/licenses/nex-opa/'):
            layer.addfile(tar_entry(name, 0, 0o755, epoch, True))
        layer.addfile(tar_entry('usr/share/licenses/nex-opa/LICENSE', len(license_bytes), 0o444, epoch), io.BytesIO(license_bytes))
        layer.addfile(tar_entry('usr/share/licenses/nex-opa/DOWNSTREAM-NOTICE', len(NOTICE), 0o444, epoch), io.BytesIO(NOTICE))
    if sha256(binary) != binary_hash or sha256(base_archive) != original_archive_hash:
        raise ValueError('compiled binary or vendor archive changed during packaging')
    new_layer = layer_buffer.getvalue()
    new_digest = hashlib.sha256(new_layer).hexdigest()
    result_config = downstream_config(config, [BASE_LAYER, 'sha256:' + new_digest], revision, source_hash)
    raw_config = encoded(result_config)
    config_hash = hashlib.sha256(raw_config).hexdigest()
    base_name = BASE_LAYER.removeprefix('sha256:') + '/layer.tar'
    layer_name = new_digest + '/layer.tar'
    manifest_bytes = encoded([{'Config': config_hash + '.json', 'RepoTags': [], 'Layers': [base_name, layer_name]}])
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as raw:
        with tarfile.open(fileobj=raw, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, body in [('manifest.json', manifest_bytes), (config_hash + '.json', raw_config), (base_name, base), (layer_name, new_layer)]:
                archive.addfile(tar_entry(name, len(body), 0o644, epoch), io.BytesIO(body))
    actual = archive_identity(output)
    if actual['id'] != 'sha256:' + config_hash or actual['layers'] != [BASE_LAYER, 'sha256:' + new_digest]:
        raise ValueError('generated OPA image identity mismatch')
    return {'id': actual['id'], 'layers': actual['layers'], 'vendor_image': VENDOR_IMAGE,
            'vendor_id': VENDOR_CONFIG, 'retained_base': BASE_LAYER,
            'excluded_vendor_executable_layer': VENDOR_EXEC_LAYER,
            'compiled_binary_sha256': binary_hash, 'archive_sha256': sha256(output),
            'vendor_config_base64': base64.b64encode(raw_vendor_config).decode('ascii')}


def verify_reconstruction(archive_path, receipt, binary_hash, revision, source_hash, epoch):
    """Independently bind the loaded image's bytes to compiler and vendor."""
    try:
        original = base64.b64decode(receipt['vendor_config_base64'], validate=True)
        if 'sha256:' + hashlib.sha256(original).hexdigest() != VENDOR_CONFIG:
            raise ValueError('vendor configuration proof mismatch')
        expected = json.loads(original)
        actual = archive_identity(archive_path)
        if actual['id'] != receipt['id'] or actual['layers'] != receipt['layers'] or len(actual['layers']) != 2 or actual['layers'][0] != BASE_LAYER or VENDOR_EXEC_LAYER in actual['layers']:
            raise ValueError('reconstructed OPA image identity mismatch')
        with tarfile.open(archive_path, 'r:') as archive:
            manifest = json.load(archive.extractfile('manifest.json'))[0]
            config = json.load(archive.extractfile(manifest['Config']))
            expected = downstream_config(expected, actual['layers'], revision, source_hash)
            if config != expected:
                raise ValueError('vendor runtime configuration changed')
            with tarfile.open(fileobj=archive.extractfile(manifest['Layers'][1]), mode='r:*') as layer:
                members = layer.getmembers()
                names = ['opa', 'usr', 'usr/share', 'usr/share/licenses', 'usr/share/licenses/nex-opa',
                         'usr/share/licenses/nex-opa/LICENSE', 'usr/share/licenses/nex-opa/DOWNSTREAM-NOTICE']
                if [m.name for m in members] != names or any(m.mtime != epoch or m.uid != 0 or m.gid != 0 for m in members):
                    raise ValueError('unexpected reconstructed OPA layer entries')
                executable = [m for m in members if m.name == 'opa']
                if len(executable) != 1 or not executable[0].isfile() or executable[0].mode != 0o555 or executable[0].uid != 0 or executable[0].gid != 0:
                    raise ValueError('compiled OPA executable metadata differs')
                if hashlib.file_digest(layer.extractfile(executable[0]), 'sha256').hexdigest() != binary_hash:
                    raise ValueError('image OPA binary differs from compiler export')
                if any(not m.isdir() or m.mode != 0o755 for m in members[1:5]):
                    raise ValueError('invalid OPA license directories')
                if any(not m.isfile() or m.mode != 0o444 for m in members[5:]):
                    raise ValueError('invalid OPA license files')
                if hashlib.file_digest(layer.extractfile(members[5]), 'sha256').hexdigest() != LICENSE_SHA256 or layer.extractfile(members[6]).read(len(NOTICE)+1) != NOTICE:
                    raise ValueError('OPA license or downstream notice mismatch')
        return actual
    except (KeyError, TypeError, json.JSONDecodeError, tarfile.TarError) as error:
        raise ValueError('invalid reconstructed OPA proof') from error


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vendor-archive', type=Path, required=True)
    parser.add_argument('--vendor-inspect', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--license', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--epoch', type=int, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--source-hash', required=True)
    args = parser.parse_args()
    if args.receipt.exists() or args.receipt.is_symlink():
        parser.exit(1, 'receipt must be fresh\n')
    try:
        result = reconstruct(args.vendor_archive, json.loads(args.vendor_inspect.read_text()), args.binary,
                             args.license, args.output, args.epoch, args.revision, args.source_hash)
        atomic_json(args.receipt, result)
    except (OSError, ValueError, tarfile.TarError, json.JSONDecodeError) as error:
        parser.exit(1, str(error) + '\n')
