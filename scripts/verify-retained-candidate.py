#!/usr/bin/env python3
"""Retrieve a completed GitHub run's subject and verify its bytes and origin.

Receipts live outside the attested bundle: a workflow cannot attest its own
unfinished success. Failed runs can have valid retained evidence and origin.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tarfile
import urllib.request
import zipfile
sys.dont_write_bytecode = True
from source_record import atomic_json, sha256

REPOSITORY = "5dg/nex-os"
API = "https://api.github.com/repos/" + REPOSITORY
MAX_DOWNLOAD = 16 * 1024**3
DISK_RESERVE = 2 * 1024**3
# Manifest, PAX/header overhead and tar stream buffering. This cap applies
# before tarfile can allocate or decompress an extended-header payload.
MAX_MANIFEST_STREAM = 5 * 1024**2
MAX_BUNDLE_STREAM = 32 * 1024**3
MAX_ARTIFACT_BYTES = 16 * 1024**3
MAX_ARTIFACTS = 4096
MAX_TAR_READ = 1024**2


class BoundedReader:
    def __init__(self, source, limit):
        self.source = source
        self.remaining = limit

    def read(self, size=-1):
        if size < 0 or size > self.remaining:
            raise ValueError("candidate manifest stream exceeds decompression budget")
        data = self.source.read(size)
        self.remaining -= len(data)
        return data


class GuardedTarReader:
    """Bound individual tar parser reads, including PAX and GNU headers."""
    def __init__(self, source):
        self.source = source

    def read(self, size):
        if size < 0 or size > MAX_TAR_READ:
            raise ValueError("candidate tar read exceeds per-call budget")
        return self.source.read(size)

    def __getattr__(self, name):
        return getattr(self.source, name)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate manifest field or artifact")
        result[key] = value
    return result


def validate_artifacts(manifest):
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or not 1 <= len(artifacts) <= MAX_ARTIFACTS:
        raise ValueError("invalid manifest artifact count")
    for name, digest in artifacts.items():
        if (not isinstance(name, str) or not name or name == "release-manifest.json"
            or len(name.encode('utf-8')) > 512 or name.startswith('/') or '\\' in name
            or any(ord(char) < 32 or ord(char) == 127 for char in name)
            or any(part in ('', '.', '..') for part in name.split('/'))
            or not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest)):
            raise ValueError("invalid manifest artifact path or digest")
    return artifacts


def verify_bundle_members(candidate_bundle, artifacts):
    total = 0
    candidate_bundle.fileobj = GuardedTarReader(candidate_bundle.fileobj)
    for name in sorted(artifacts):
        member = candidate_bundle.next()
        if (not member or member.name != name or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
            or member.sparse is not None or any(key.startswith(('GNU.sparse.', 'SCHILY.realsize')) for key in member.pax_headers)
            or member.size < 0 or member.size > MAX_ARTIFACT_BYTES):
            raise ValueError("unexpected, missing, sparse or nonregular bundle member")
        total += member.size
        if total > MAX_BUNDLE_STREAM - MAX_MANIFEST_STREAM:
            raise ValueError("bundle artifact bytes exceed admitted budget")
        digest = hashlib.sha256()
        stream = candidate_bundle.extractfile(member)
        remaining = member.size
        while remaining:
            data = stream.read(min(1024**2, remaining))
            if not data:
                raise ValueError("truncated bundle member")
            digest.update(data)
            remaining -= len(data)
        if digest.hexdigest() != artifacts[name]:
            raise ValueError("bundle artifact differs from signed manifest")
    if candidate_bundle.next() is not None:
        raise ValueError("unexpected extra bundle member")
    # Tarfile stops at the first zero block. Reject hidden trailing members or
    # excessive padding, and consume to gzip EOF so its checksum is checked.
    padding = 0
    while data := candidate_bundle.fileobj.read(tarfile.RECORDSIZE):
        padding += len(data)
        if padding > tarfile.RECORDSIZE or any(data):
            raise ValueError("unexpected trailing bundle data")
    serialized = json.dumps(artifacts, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')
    return {"inner_artifacts_verified": True, "inner_artifact_count": len(artifacts),
            "inner_artifact_bytes": total, "artifact_map_sha256": hashlib.sha256(serialized).hexdigest()}


def copy_bounded(source, output, directory, limit, error):
    """Stream untrusted bytes with an independent filesystem reserve."""
    size = 0
    while block := source.read(1024**2):
        size += len(block)
        if size > limit:
            raise ValueError(error)
        if shutil.disk_usage(directory).free < DISK_RESERVE + len(block):
            raise ValueError("retained verification filesystem reserve would be exceeded")
        output.write(block)


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            raise ValueError("artifact redirect must retain HTTPS")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        # Artifact storage receives only the short-lived signed URL, never the
        # GitHub API bearer credential, including on redirects back to GitHub.
        redirected.remove_header("Authorization")
        return redirected


def request(path):
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        raise ValueError("GitHub actions:read credential must be supplied securely")
    req = urllib.request.Request(API + path, headers={"Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", "Authorization": "Bearer " + token})
    return urllib.request.build_opener(SafeRedirect).open(req, timeout=180)


def metadata(path):
    with request(path) as response:
        content = response.read(4 * 1024**2 + 1)
    if len(content) > 4 * 1024**2:
        raise ValueError("GitHub metadata exceeds bound")
    return json.loads(content)


def validate_metadata(run, artifact, args):
    if (run.get("id") != args.run_id or run.get("head_sha") != args.source_revision
        or run.get("head_branch") != "main" or run.get("event") not in ("push", "workflow_dispatch")
        or run.get("path", "").split("@", 1)[0] != ".github/workflows/ci.yml"
        or run.get("repository", {}).get("full_name") != REPOSITORY
        or run.get("head_repository", {}).get("full_name") != REPOSITORY
        or run.get("status") != "completed" or not run.get("conclusion")):
        raise ValueError("completed trusted-main workflow/source binding mismatch")
    producer = artifact.get("workflow_run", {})
    if (artifact.get("id") != args.artifact_id or artifact.get("name") != "alpha04-candidate-subject"
        or artifact.get("expired") is not False or producer.get("id") != args.run_id
        or producer.get("head_sha") != args.source_revision or producer.get("head_branch") != "main"):
        raise ValueError("retained artifact producer binding mismatch")
    digest = artifact.get("digest", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("GitHub retained archive SHA256 is unavailable")
    return digest.removeprefix("sha256:")


def verify(args):
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_revision) or not re.fullmatch(r"[0-9a-f]{64}", args.subject_sha256):
        raise ValueError("full expected source and subject digests required")
    if args.run_id <= 0 or args.artifact_id <= 0 or args.output.exists():
        raise ValueError("positive remote identifiers and a new receipt directory required")
    run = metadata(f"/actions/runs/{args.run_id}")
    artifact = metadata(f"/actions/artifacts/{args.artifact_id}")
    expected_archive = validate_metadata(run, artifact, args)
    args.output.mkdir(parents=True, mode=0o700)
    archive = args.output / "retained.zip"
    with request(f"/actions/artifacts/{args.artifact_id}/zip") as response, archive.open("xb") as output:
        copy_bounded(response, output, args.output, MAX_DOWNLOAD,
                     "retained archive exceeds admitted download budget")
    if sha256(archive) != expected_archive:
        raise ValueError("downloaded artifact differs from GitHub's retained digest")
    subject = args.output / "candidate-bundle.tar.gz"
    with zipfile.ZipFile(archive) as zipped:
        entries = zipped.infolist()
        if len(entries) != 1 or entries[0].filename != subject.name or entries[0].file_size > MAX_DOWNLOAD:
            raise ValueError("retained artifact must contain one bounded candidate subject")
        with zipped.open(entries[0]) as source, subject.open("xb") as output:
            copy_bounded(source, output, args.output, MAX_DOWNLOAD,
                         "candidate subject exceeds admitted expansion budget")
    if sha256(subject) != args.subject_sha256:
        raise ValueError("retrieved subject differs from expected candidate bundle")
    spec = importlib.util.spec_from_file_location("verify_provenance", Path(__file__).with_name("verify-provenance.py"))
    provenance = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(provenance)
    origin = provenance.verify(argparse.Namespace(subject=subject, subject_sha256=args.subject_sha256,
        source_revision=args.source_revision, tool_root=args.tool_root, output=args.output / "origin.json",
        attestation_bundle=None))
    if origin != 0:
        # Failed origin cannot authorize interpretation of the subject or a
        # completed-run receipt. The separate origin failure remains on disk.
        return 1
    release = None
    # New candidate subjects put the manifest FIRST. Never scan/decompress an
    # arbitrary tar payload looking for it: a tiny gzip could declare huge files.
    # Signature verification precedes interpretation, and the first member still
    # has a strict size/type bound. No extraction, archive paths or links execute.
    with gzip.open(subject, 'rb') as decompressed:
        limited = BoundedReader(decompressed, MAX_MANIFEST_STREAM)
        with tarfile.open(fileobj=limited, mode="r|") as candidate_bundle:
            member = candidate_bundle.next()
            if (not member or member.name != "release-manifest.json" or
                member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or member.sparse is not None or
                any(key.startswith(('GNU.sparse.', 'SCHILY.realsize')) for key in member.pax_headers) or
                member.size > 4 * 1024**2):
                raise ValueError("first subject member must be a bounded regular release manifest")
            manifest_bytes = candidate_bundle.extractfile(member).read(member.size + 1)
            if len(manifest_bytes) != member.size:
                raise ValueError("truncated release manifest")
            release = json.loads(manifest_bytes, object_pairs_hook=unique_object)
            if (not isinstance(release, dict) or not isinstance(release.get("source"), dict)
                or release['source'].get("revision") != args.source_revision):
                raise ValueError("retained release manifest/source mismatch")
            artifacts = validate_artifacts(release)
            limited.remaining += MAX_BUNDLE_STREAM - MAX_MANIFEST_STREAM
            inner = verify_bundle_members(candidate_bundle, artifacts)
            inner['release_manifest_sha256'] = hashlib.sha256(manifest_bytes).hexdigest()
    required_local = ("qualification", "proof-parity", "shutdown", "packaged-shutdown", "history-pagination", "dom-browser", "vulnerability-scans", "reproducibility")
    checks = release.get("checks")
    if not isinstance(checks, dict):
        raise ValueError("retained release checks are invalid")
    local_passed = all(checks.get(name) == "passed" for name in required_local)
    receipt = {"schema_version": 1, "repository": REPOSITORY, "workflow_run_id": args.run_id,
        "source_revision": args.source_revision, "artifact_id": args.artifact_id,
        "retained_archive_sha256": expected_archive, "subject_sha256": args.subject_sha256,
        "hosted_ci": "passed" if run["conclusion"] == "success" else "failed",
        "hosted_conclusion": run["conclusion"], "durable_retention": "passed",
        "origin_verification": "passed" if origin == 0 else "failed", "release_approval": False,
        "internal_checks": checks,
        "synthetic_qualification_gate": "qualified" if local_passed and origin == 0 and run["conclusion"] == "success" else "blocked",
        "run_metadata": run, "artifact_metadata": artifact, **inner}
    atomic_json(args.output / "completed-run-receipt.json", receipt)
    return 0 if local_passed and origin == 0 and run["conclusion"] == "success" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--artifact-id", required=True, type=int)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--subject-sha256", required=True)
    parser.add_argument("--tool-root", type=Path, default=Path(os.environ.get("NEX_TOOLS_DIR", "/workspace/.tools")))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        raise SystemExit(verify(args))
    except (ValueError, OSError, zipfile.BadZipFile, tarfile.TarError, json.JSONDecodeError):
        # Signed storage URLs and API diagnostics may carry credentials. Keep
        # the failure bounded without serializing those URLs or request headers.
        parser.exit(1, "Retained candidate verification failed; no successful receipt established.\n")
