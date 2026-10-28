"""Digest a saved image's merged filesystem without extracting or running files."""
import hashlib
import json
from pathlib import PurePosixPath
import tarfile
import sys
sys.dont_write_bytecode = True
from source_record import atomic_json

# Only timestamps are outside the declared merged-filesystem target. Retain
# opaque PAX values, including both common xattr encodings, ACLs and flags;
# silently dropping an unfamiliar key could hide a security capability change.
TIMESTAMP_PAX = {"mtime", "atime", "ctime", "LIBARCHIVE.creationtime",
                 "SCHILY.atime", "SCHILY.ctime", "SCHILY.birthtime"}

def payload(archive_path, output):
    files = {}
    with tarfile.open(archive_path, "r:") as saved:
        manifests = json.load(saved.extractfile("manifest.json"))
        if len(manifests) != 1:
            raise ValueError("one exact image is required per archive")
        manifest = manifests[0]
        for name in manifest["Layers"]:
            entries, whiteouts, opaques = {}, [], []
            with tarfile.open(fileobj=saved.extractfile(name), mode="r:*") as layer:
                for member in layer:
                    path = PurePosixPath(member.name.removeprefix("./"))
                    if path.is_absolute() or ".." in path.parts:
                        raise ValueError("invalid image path")
                    relative = path.as_posix()
                    if path.name == ".wh..wh..opq":
                        opaques.append(path.parent.as_posix())
                        continue
                    if path.name.startswith(".wh."):
                        whiteouts.append((path.parent / path.name[4:]).as_posix())
                        continue
                    value = {"mode": member.mode & 0o7777, "uid": member.uid, "gid": member.gid,
                             "pax_headers": {key: val for key, val in sorted(member.pax_headers.items())
                                             if key not in TIMESTAMP_PAX}}
                    if member.islnk():
                        # A later layer replacing the target pathname must not
                        # change this link's old inode. Path-only modelling can
                        # falsely equate different executable bytes. Until inode
                        # extraction semantics are modelled, refuse this image.
                        raise ValueError("hardlink image payload unsupported; cannot prove inode/content identity")
                    if member.isfile():
                        value.update(type="file", size=member.size, sha256=hashlib.file_digest(layer.extractfile(member), "sha256").hexdigest())
                    elif member.isdir():
                        value["type"] = "directory"
                    elif member.issym():
                        value.update(type="symlink", target=member.linkname)
                    else:
                        value.update(type=member.type.decode("ascii", "backslashreplace"), device_major=member.devmajor, device_minor=member.devminor)
                    entries[relative] = value
            for directory in opaques:
                prefix = "" if directory == "." else directory + "/"
                files = {p: v for p, v in files.items() if p == directory or not p.startswith(prefix)}
            for target in whiteouts:
                files = {p: v for p, v in files.items() if p != target and not p.startswith(target + "/")}
            for path, entry in entries.items():
                if entry["type"] != "directory":
                    files = {p: v for p, v in files.items() if not p.startswith(path + "/")}
            files.update(entries)
        encoded = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
        record = {"algorithm": "sha256 merged paths/type/mode/uid/gid/content/link/device/PAX-xattrs-ACL-flags; timestamps excluded", "sha256": hashlib.sha256(encoded).hexdigest(), "entries": len(files), "config_path": manifest["Config"], "layer_paths": manifest["Layers"]}
        atomic_json(output, {"schema_version": 2, "payload": record, "files": dict(sorted(files.items()))})
        return record
