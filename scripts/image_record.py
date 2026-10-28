"""Digest a saved image's merged filesystem without extracting or running files."""
import hashlib
import json
from pathlib import PurePosixPath
import tarfile
import sys
sys.dont_write_bytecode = True
from source_record import atomic_json

TIMESTAMP_PAX = {"mtime", "atime", "ctime", "LIBARCHIVE.creationtime",
                 "SCHILY.atime", "SCHILY.ctime", "SCHILY.birthtime"}
# These standard fields are represented by normalized path, link resolution,
# content size and numeric ownership. All other opaque metadata remains bound.
STRUCTURAL_PAX = {"path", "linkpath", "size", "uid", "gid"}


def image_path(name):
    path = PurePosixPath(name.removeprefix("./"))
    if path.is_absolute() or ".." in path.parts or path.as_posix() in ("", "."):
        raise ValueError("invalid image path")
    return path


def check_ancestors(files, path):
    for parent in path.parents:
        entry = files.get(parent.as_posix())
        if entry is not None and entry["type"] != "directory":
            raise ValueError("image entry traverses a known non-directory ancestor")


def payload(archive_path, output):
    # Regular-file values are inode objects shared by all current hardlink paths.
    # Replacing a pathname installs a NEW object, never mutates older aliases.
    files = {}
    with tarfile.open(archive_path, "r:") as saved:
        manifests = json.load(saved.extractfile("manifest.json"))
        if len(manifests) != 1:
            raise ValueError("one exact image is required per archive")
        manifest = manifests[0]
        for name in manifest["Layers"]:
            entries, whiteouts, opaques = [], [], []
            with tarfile.open(fileobj=saved.extractfile(name), mode="r:*") as layer:
                for member in layer:
                    # OCI archives commonly include the root directory header.
                    path = PurePosixPath(".") if member.name in (".", "./", "") and member.isdir() else image_path(member.name)
                    if path.name == ".wh..wh..opq":
                        opaques.append(path.parent.as_posix())
                        continue
                    if path.name.startswith(".wh."):
                        whiteouts.append(image_path((path.parent / path.name[4:]).as_posix()).as_posix())
                        continue
                    value = {"mode": member.mode & 0o7777, "uid": member.uid, "gid": member.gid,
                             "pax_headers": {key: val for key, val in sorted(member.pax_headers.items())
                                             if key not in TIMESTAMP_PAX | STRUCTURAL_PAX}}
                    target = None
                    if member.islnk():
                        if member.size != 0:
                            raise ValueError("hardlink payload bytes are unsupported")
                        target = image_path(member.linkname)
                        value["type"] = "hardlink"
                    elif member.isfile():
                        value.update(type="file", size=member.size,
                                     sha256=hashlib.file_digest(layer.extractfile(member), "sha256").hexdigest())
                    elif member.isdir():
                        value["type"] = "directory"
                    elif member.issym():
                        value.update(type="symlink", target=member.linkname)
                    else:
                        value.update(type=member.type.decode("ascii", "backslashreplace"),
                                     device_major=member.devmajor, device_minor=member.devminor)
                    entries.append((path, value, target))
            # Whiteouts affect the lower layer, independent of their header order.
            for directory in opaques:
                prefix = "" if directory == "." else directory + "/"
                files = {p: v for p, v in files.items() if p == directory or not p.startswith(prefix)}
            for target in whiteouts:
                files = {p: v for p, v in files.items() if p != target and not p.startswith(target + "/")}
            # Keep tar header order: a link binds the inode existing RIGHT NOW.
            for path, entry, target in entries:
                check_ancestors(files, path)
                relative = path.as_posix()
                if target is not None:
                    if target == path or path in target.parents:
                        raise ValueError("hardlink replacement would detach its own source pathname")
                    check_ancestors(files, target)
                    inode = files.get(target.as_posix())
                    if inode is None or inode["type"] != "file":
                        raise ValueError("hardlink requires an existing regular inode; forward/nonregular targets unsupported")
                    if any(entry[key] != inode[key] for key in ("mode", "uid", "gid", "pax_headers")):
                        raise ValueError("hardlink metadata differs from target; inode mutation semantics unsupported")
                    entry = inode
                if entry["type"] != "directory":
                    files = {p: v for p, v in files.items() if not p.startswith(relative + "/")}
                files[relative] = entry
        aliases = {}
        for path, entry in files.items():
            if entry["type"] == "file":
                aliases.setdefault(id(entry), []).append(path)
        normalized = {}
        for path, entry in sorted(files.items()):
            value = dict(entry)
            if entry["type"] == "file" and len(aliases[id(entry)]) > 1:
                value["hardlink_aliases"] = sorted(aliases[id(entry)])
            normalized[path] = value
        encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
        record = {"algorithm": "sha256 merged paths/type/mode/uid/gid/content/link/device/PAX-xattrs-ACL-flags/hardlink-inode-aliases; timestamps excluded",
                  "sha256": hashlib.sha256(encoded).hexdigest(), "entries": len(normalized),
                  "config_path": manifest["Config"], "layer_paths": manifest["Layers"]}
        atomic_json(output, {"schema_version": 3, "payload": record, "files": normalized})
        return record
