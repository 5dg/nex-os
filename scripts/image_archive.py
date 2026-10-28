"""Canonicalize outer Docker-save timestamps without rewriting any member bytes.

Only outer regular/directory header mtime and its derived checksum change.
Config/layer blobs, opaque non-time PAX records, ordering and padding stay intact.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tarfile

sys.dont_write_bytecode = True
from image_record import TIMESTAMP_PAX
from source_record import atomic_json, sha256


def inspect(path, image_id):
    entries = {}
    with tarfile.open(path, 'r:') as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            if name.is_absolute() or '..' in name.parts or name.as_posix() in ('', '.') or name.as_posix() in entries or member.name != name.as_posix():
                raise ValueError('noncanonical or duplicate outer archive path')
            if not (member.isfile() or member.isdir()) or member.sparse is not None:
                raise ValueError('unsupported outer archive member type')
            if member.pax_headers.keys() & TIMESTAMP_PAX:
                raise ValueError('outer PAX timestamp override is unsupported')
            if member.isdir() and member.size:
                raise ValueError('directory member must not contain payload bytes')
            entries[name.as_posix()] = {
                'header_offset': member.offset_data - tarfile.BLOCKSIZE,
                'name': member.name, 'type': member.type.decode('ascii'), 'size': member.size,
                'mode': member.mode, 'uid': member.uid, 'gid': member.gid,
                'uname': member.uname, 'gname': member.gname, 'linkname': member.linkname,
                'device_major': member.devmajor, 'device_minor': member.devminor,
                'pax_headers': dict(member.pax_headers), 'mtime': member.mtime,
                'sha256': hashlib.file_digest(archive.extractfile(member), 'sha256').hexdigest() if member.isfile() else None}
        if 'manifest.json' not in entries or entries['manifest.json']['sha256'] is None or entries['manifest.json']['size'] > 1024 ** 2:
            raise ValueError('bounded Docker manifest required')
        manifest = json.load(archive.extractfile('manifest.json'))
        if not isinstance(manifest, list) or len(manifest) != 1 or not isinstance(manifest[0], dict):
            raise ValueError('one exact saved image required')
        config = entries.get(manifest[0].get('Config'), {})
        if config.get('sha256') != image_id.removeprefix('sha256:'):
            raise ValueError('saved config does not match inspected image ID')
        layers = manifest[0].get('Layers')
        if not isinstance(layers, list) or any(not isinstance(name, str) or name not in entries or entries[name]['sha256'] is None for name in layers):
            raise ValueError('missing layer member')
    return entries


def canonicalize(source, output, epoch, image_id):
    if type(epoch) is not int or not 0 <= epoch <= 0o77777777777:
        raise ValueError('nonnegative source epoch fitting an outer tar header required')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', image_id):
        raise ValueError('inspected immutable image ID required')
    if source.is_symlink() or not source.is_file():
        raise ValueError('regular raw Docker archive required')
    if output.exists() or output.is_symlink():
        raise ValueError('canonical archive output must be new')
    before_stat = source.stat()
    before = inspect(source, image_id)
    raw_digest = sha256(source)
    changes = []
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as emitted, source.open('rb') as raw:
        shutil.copyfileobj(raw, emitted, length=1024 ** 2)
        for entry in before.values():
            offset = entry['header_offset']
            raw.seek(offset)
            header = bytearray(raw.read(tarfile.BLOCKSIZE))
            if len(header) != tarfile.BLOCKSIZE:
                raise ValueError('truncated outer archive header')
            decoded = tarfile.TarInfo.frombuf(bytes(header), 'utf-8', 'surrogateescape')
            if decoded.type.decode('ascii') != entry['type'] or decoded.mtime != entry['mtime']:
                raise ValueError('outer header differs from parsed member')
            if entry['mtime'] == epoch:
                continue
            original_header_sha256 = hashlib.sha256(header).hexdigest()
            header[136:148] = f'{epoch:011o}\0'.encode('ascii')
            header[148:156] = b' ' * 8
            header[148:156] = f'{sum(header):06o}\0 '.encode('ascii')
            emitted.seek(offset)
            emitted.write(header)
            if entry['mtime'] != epoch:
                changes.append({'path': entry['name'], 'header_offset': offset,
                                'mtime_before': entry['mtime'], 'mtime_after': epoch,
                                'raw_header_sha256': original_header_sha256,
                                'emitted_header_sha256': hashlib.sha256(header).hexdigest(),
                                'changed_fields': ['mtime', 'derived tar header checksum']})
    current = source.stat()
    if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns) != (
            before_stat.st_dev, before_stat.st_ino, before_stat.st_size, before_stat.st_mtime_ns, before_stat.st_ctime_ns):
        raise ValueError('raw archive changed during preparation')
    after = inspect(output, image_id)
    expected = {name: {**entry, 'mtime': epoch} for name, entry in before.items()}
    if after != expected or output.stat().st_size != before_stat.st_size:
        raise ValueError('archive member bytes or non-time metadata changed')
    return {'schema_version': 1, 'kind': 'outer-docker-tar-timestamps-v1',
            'source_epoch': epoch, 'image_id': image_id, 'raw_sha256': raw_digest,
            'emitted_sha256': sha256(output), 'archive_bytes': before_stat.st_size,
            'member_bytes_and_non_time_metadata_preserved': True,
            'changes': changes, 'members': before}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--epoch', type=int, required=True)
    parser.add_argument('--image-id', required=True)
    args = parser.parse_args()
    try:
        if args.report.exists() or args.report.is_symlink():
            raise ValueError('archive preparation report must be new')
        atomic_json(args.report, canonicalize(args.source, args.output, args.epoch, args.image_id))
    except (OSError, ValueError, tarfile.TarError, json.JSONDecodeError) as error:
        parser.exit(1, str(error) + '\n')
