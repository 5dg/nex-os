"""Verify and replace the pinned PostgreSQL Alpine image's gosu layer member.

This is a packaging primitive, not an image qualification or an admission gate.
Callers must independently bind the replacement to the canonical compiler and
verify the complete resulting image, including every other layer.
"""
import hashlib
import io
import tarfile

OLD_DIFF_ID = 'd95c4d3b017db828e63f54b9fbb24de0a074cfee6374d9dec52f0911a788a73d'
OLD_GOSU_SHA256 = '52c8749d0142edd234e9d6bd5237dff2d81e71f43537e2f4f66f75dd4b243dd0'
OLD_GOSU_SIZE = 1769900
TARGET = 'usr/local/bin/gosu'
MAX_REPLACEMENT = 32 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def _members(raw):
    result = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for item in archive:
            if item.name in result:
                raise ValueError('duplicate tar member')
            data = archive.extractfile(item).read() if item.isfile() else None
            result[item.name] = (item.type, item.mode, item.uid, item.gid,
                                 item.linkname, item.pax_headers, data)
    return result


def replace_gosu(raw, replacement, expected_replacement_sha256):
    """Replace exactly one member while preserving every other raw tar record.

    The inputs must be authenticated by the caller. This verifies the exact
    original uncompressed layer and its original binary, and checks the new
    binary against the caller's independent compiler export digest.
    """
    if not isinstance(raw, bytes) or digest(raw) != OLD_DIFF_ID:
        raise ValueError('vendor layer diffID mismatch')
    if (not isinstance(replacement, bytes) or not 0 < len(replacement) <= MAX_REPLACEMENT
            or digest(replacement) != expected_replacement_sha256
            or digest(replacement) == OLD_GOSU_SHA256):
        raise ValueError('compiled replacement mismatch')
    position, output, seen = 0, bytearray(), 0
    while position + 512 <= len(raw):
        header = raw[position:position + 512]
        if header == bytes(512):
            if any(raw[position:]):
                raise ValueError('nonzero tar trailer')
            output.extend(raw[position:])
            break
        try:
            size = int(header[124:136].rstrip(b'\0 ').lstrip(b' ') or b'0', 8)
            checksum = int(header[148:156].rstrip(b'\0 ').lstrip(b' ') or b'0', 8)
            name = header[:100].split(b'\0', 1)[0].decode('utf-8')
            prefix = header[345:500].split(b'\0', 1)[0].decode('utf-8')
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError('invalid vendor tar header') from error
        if sum(header[:148]) + 8 * 32 + sum(header[156:]) != checksum:
            raise ValueError('vendor tar header checksum mismatch')
        if prefix:
            name = prefix + '/' + name
        end = position + 512 + ((size + 511) // 512) * 512
        if size < 0 or end > len(raw):
            raise ValueError('truncated vendor tar member')
        if name == TARGET:
            content = raw[position + 512:position + 512 + size]
            if (seen or header[156:157] not in (b'0', b'\0') or size != OLD_GOSU_SIZE
                    or digest(content) != OLD_GOSU_SHA256):
                raise ValueError('unexpected original gosu member')
            new_header = bytearray(header)
            new_header[124:136] = ('%011o\0' % len(replacement)).encode('ascii')
            new_header[148:156] = b'        '
            new_header[148:156] = ('%06o\0 ' % sum(new_header)).encode('ascii')
            output.extend(new_header)
            output.extend(replacement)
            output.extend(bytes((-len(replacement)) % 512))
            seen += 1
        else:
            output.extend(raw[position:end])
        position = end
    else:
        raise ValueError('missing tar trailer')
    if seen != 1:
        raise ValueError('exactly one original gosu member required')
    new = bytes(output)
    try:
        original, rewritten = _members(raw), _members(new)
    except tarfile.TarError as error:
        raise ValueError('invalid layer tar') from error
    if original.keys() != rewritten.keys():
        raise ValueError('layer membership changed')
    for name in original:
        if name == TARGET:
            if original[name][:-1] != rewritten[name][:-1] or rewritten[name][-1] != replacement:
                raise ValueError('gosu metadata or replacement changed')
        elif original[name] != rewritten[name]:
            raise ValueError('non-target layer member changed')
    return new
