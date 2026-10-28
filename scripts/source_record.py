"""Source-byte identity usable in a checkout or an extracted approved archive.

No credential file or generated tree is an input. Canonical callers require the
explicit companion written by the capture operation and verify every source byte.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

COMPANION = ".nex-source.json"
SOURCE_DIRS = {".github", "apps", "deploy", "docs", "packages", "policies", "scripts", "services", "tests"}
SOURCE_FILES = {".dockerignore", ".gitignore", ".tool-versions", "Makefile", "go.mod", "go.sum", "rust-toolchain.toml"}
# These are generated *locations*, never arbitrary nested directory names.
# In particular Cargo src/bin and an authored fixture named target are inputs.
IGNORED_ROOTS = {".git", ".local", "bin", "target", ".pytest_cache",
    "apps/workspace/.next", "apps/workspace/node_modules",
    "deploy/terraform/.terraform", "services/guard-kernel/target",
    "scripts/__pycache__", "tests/release/__pycache__"}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def resolve_image(value: str) -> str:
    variable = re.fullmatch(r"\$\{(NEX_(?:CONTROL|GUARD|WORKSPACE|FIXTURES|POSTGRES|OPA)_IMAGE):-(.+)\}", value)
    if variable:
        value = os.environ.get(variable.group(1), variable.group(2))
    if len(value) > 512 or "://" in value or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._/@:+-]*", value):
        raise ValueError("invalid credential-free image reference")
    return value


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def atomic_json(path: Path, value: object) -> None:
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".record-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def inputs(root: Path, *, canonical: bool = False) -> dict:
    root = root.resolve(strict=True)
    files = {}
    modes = {}
    omitted = []
    for item in sorted(root.iterdir()):
        if item.name in IGNORED_ROOTS or item.name == COMPANION:
            continue
        allowed = item.name in SOURCE_DIRS or item.name in SOURCE_FILES or item.name.endswith(".md") or item.name.startswith(("LICENSE", "NOTICE"))
        if not allowed:
            if canonical:
                raise ValueError(f"undeclared top-level source path: {item.name}")
            omitted.append(item.name)
            continue
        pending = [item]
        while pending:
            path = pending.pop()
            relative = path.relative_to(root).as_posix()
            if relative in IGNORED_ROOTS:
                continue
            if path.name.startswith(".env") and path.name != ".env.example":
                if canonical:
                    raise ValueError(f"local environment file is not a canonical source input: {relative}")
                omitted.append(relative)
                continue
            if path.is_symlink():
                raise ValueError(f"authored source symlink is not supported: {relative}")
            if path.is_dir():
                pending.extend(sorted(path.iterdir(), reverse=True))
            elif path.is_file():
                files[relative] = sha256(path)
                modes[relative] = path.stat().st_mode & 0o7777
            else:
                raise ValueError(f"non-regular source input: {relative}")
    files = dict(sorted(files.items()))
    modes = dict(sorted(modes.items()))
    encoded = json.dumps({"files": files, "modes": modes}, sort_keys=True, separators=(",", ":")).encode()
    return {"algorithm": "sha256 of sorted compact JSON files-and-modes map", "sha256": hashlib.sha256(encoded).hexdigest(), "files": files, "modes": modes, "omitted_local_paths": sorted(omitted)}


def verify_physical_inputs(root: Path, actual: dict) -> None:
    """A canonical compile tree contains no unbound file or extra directory.

    Unlike diagnostic discovery, this walk never skips generated-looking names.
    A tracked bin file could be read by go:embed, include_str! or a build script.
    """
    admitted = set(actual["files"])
    directories = {parent.as_posix() for name in admitted
                   for parent in Path(name).parents if parent.as_posix() != "."}
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ValueError(f"unbound canonical source symlink: {relative}")
        if path.is_dir() and relative in directories:
            continue
        if path.is_file() and (relative in admitted or relative == COMPANION):
            continue
        raise ValueError(f"unbound physical canonical source input: {relative}")


def identity(root: Path, *, canonical: bool = False) -> dict:
    actual = inputs(root, canonical=canonical)
    if canonical:
        verify_physical_inputs(root, actual)
    companion = root / COMPANION
    if companion.exists():
        if companion.is_symlink():
            raise ValueError("source companion must be a regular file")
        data = json.loads(companion.read_text())
        if data.get("schema_version") != 1 or data.get("inputs") != actual:
            raise ValueError("source bytes do not match the captured input map")
        revision, epoch = data.get("revision"), data.get("source_epoch")
        if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision) or not isinstance(epoch, int) or epoch <= 0:
            raise ValueError("captured revision and source epoch required")
        return {"revision": revision, "source_epoch": epoch, "inputs": actual, "companion_sha256": sha256(companion)}
    if canonical:
        raise ValueError("canonical build requires the captured source companion")
    result = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=root, capture_output=True, text=True)
    return {"revision": result.stdout.strip() if result.returncode == 0 else None, "source_epoch": None, "inputs": actual, "companion_sha256": None}


def verify_artifacts(record_path: Path, source: Path, names: tuple[str, ...], *, require_canonical: bool = False) -> dict:
    if record_path.is_symlink():
        raise ValueError("artifact record must be a regular file")
    data = json.loads(record_path.read_text())
    canonical = data.get("build_mode") == "canonical-container"
    if require_canonical and not canonical:
        raise ValueError("canonical tools cannot be supplied by a host diagnostic record")
    actual = identity(source, canonical=canonical)
    if data.get("inputs") != actual["inputs"]:
        raise ValueError("artifact source inputs are stale or substituted")
    for name in names:
        if not re.fullmatch(r"[a-z][a-z0-9-]*", name):
            raise ValueError("invalid artifact name")
        expected = data.get("binaries", {}).get(name)
        path = record_path.parent / name
        if not isinstance(expected, str) or not HEX64.fullmatch(expected) or path.is_symlink() or not path.is_file() or sha256(path) != expected:
            raise ValueError(f"missing, stale or substituted artifact: {name}")
    return data


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("identity", "verify-tools"))
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--canonical", action="store_true")
    parser.add_argument("--record", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "identity":
            print(json.dumps(identity(args.source, canonical=args.canonical), sort_keys=True))
        else:
            if args.record is None:
                parser.error("verify-tools requires --record")
            verify_artifacts(args.record, args.source, ("evidence", "qualification-pki"), require_canonical=args.canonical)
            print("Fresh source-bound qualification tools verified")
    except (ValueError, OSError, json.JSONDecodeError) as error:
        parser.exit(1, str(error) + "\n")
