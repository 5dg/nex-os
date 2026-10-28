#!/usr/bin/env python3
"""Execute checks and retain a non-secret, source/image-bound release record."""
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import time
import tempfile
sys.dont_write_bytecode = True
from candidate import load
from image_record import payload
from source_record import atomic_json, sha256


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def build_record(candidate, base, name):
    path = base / "builds" / name / "manifest.json"
    bound = candidate.get("builds", {}).get(name, {})
    if bound.get("path") != str(path.relative_to(base)) or sha256(path) != bound.get("sha256"):
        raise ValueError("candidate/build manifest binding mismatch")
    data = json.loads(path.read_text())
    if data.get("source") != candidate["source"] or data.get("status") != "built" or data.get("build_mode") != "canonical-container":
        raise ValueError("completed exact-source canonical build required")
    for binary, digest in data.get("binaries", {}).items():
        if not re.fullmatch(r"[a-z][a-z0-9-]*", binary):
            raise ValueError("invalid exported binary name")
        exported = path.parent / "bin" / binary
        if exported.is_symlink() or sha256(exported) != digest:
            raise ValueError("exported binary differs from completed build")
    return data


def compare(args):
    candidate, base, _ = load(args.candidate)
    first, second = (build_record(candidate, base, name) for name in ("one", "two"))
    binary_equal = first["binaries"] == second["binaries"]
    images = {}
    for name in sorted(first["images"]):
        left, right = first["images"][name], second["images"].get(name)
        if right is None:
            raise ValueError("image set differs between builds")
        for build, image in (("one", left), ("two", right)):
            if image["archive"]["path"] != "images/" + name + ".tar":
                raise ValueError("unexpected image archive path")
            archive = base / "builds" / build / image["archive"]["path"]
            if sha256(archive) != image["archive"]["sha256"]:
                raise ValueError("saved image archive is stale or substituted")
            # Re-derive the merged payload from the retained archive; a copied
            # manifest digest or edited payload report cannot establish equality.
            with tempfile.TemporaryDirectory(prefix="nex-payload-verify-") as temporary:
                regenerated = Path(temporary) / "payload.json"
                actual = payload(archive, regenerated)
                recorded_path = base / "builds" / build / (name + "-payload.json")
                if actual != image["payload"] or json.loads(recorded_path.read_text()) != json.loads(regenerated.read_text()):
                    raise ValueError("saved payload identity/report differs from image bytes")
        images[name] = {"runtime_payload_identical": left["payload"]["sha256"] == right["payload"]["sha256"],
                        "oci_configuration_identical": left["id"] == right["id"],
                        "oci_layers_identical": left["layers"] == right["layers"],
                        "saved_image_archive_identical": left["archive"]["sha256"] == right["archive"]["sha256"]}
        if not images[name]["runtime_payload_identical"]:
            files = [json.loads((base / "builds" / build / (name + "-payload.json")).read_text())["files"] for build in ("one", "two")]
            changed = [path for path in sorted(files[0].keys() | files[1].keys()) if files[0].get(path) != files[1].get(path)]
            images[name]["changed_runtime_paths"] = changed
    payload_equal = all(image["runtime_payload_identical"] for image in images.values())
    oci_equal = all(image["oci_configuration_identical"] and image["oci_layers_identical"] and image["saved_image_archive_identical"] for image in images.values())
    result = {"schema_version": 1, "source": candidate["source"], "measured_at": now(),
              "targets": {"native_binaries": "exact bytes", "runtime_payload": "merged path/type/mode/uid/gid/content/link/device/PAX-xattrs-ACL-flags; timestamps excluded",
                          "oci": "configuration/layer/archive bytes, separately reported"},
              "native_binaries_identical": binary_equal, "runtime_payloads_identical": payload_equal,
              "oci_bytes_identical": oci_equal, "images": images,
              "status": "passed" if binary_equal and payload_equal and oci_equal else "failed",
              "metadata_differences_are_not_payload_normalization": True}
    path = base / "reproducibility.json"
    if path.exists():
        raise ValueError("comparison exists; preserve it")
    atomic_json(path, result)
    candidate["reproducibility"] = {"path": path.name, "sha256": sha256(path), "status": result["status"]}
    atomic_json(args.candidate, candidate)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


def result(args):
    candidate, base, source = load(args.candidate)
    build = build_record(candidate, base, args.build) if args.action == "run" else None
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", args.name):
        raise ValueError("bounded check name required")
    if args.action == "run" and args.name in ("hosted-ci", "durable-retention"):
        raise ValueError("remote CI/retention cannot be inferred from a local command's exit code")
    records = candidate.setdefault("results", [])
    stamp = str(time.time_ns())
    path = base / "evidence" / (args.name + "-" + stamp + ".log")
    path.parent.mkdir(mode=0o700, exist_ok=True)
    check = {"name": args.name, "build": args.build, "source_revision": candidate["source"]["revision"],
             "source_input_sha256": candidate["source"]["inputs"]["sha256"],
             "tested_image_ids": {name: image["id"] for name, image in build["images"].items()} if build else {}, "started_at": now()}
    if args.action == "note":
        check.update(status=args.status, reason=args.reason, ended_at=now(), exit_code=None)
    else:
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        if not command:
            raise ValueError("an actual check command is required")
        check["command"] = command
        try:
            with path.open("wb") as log:
                process = subprocess.run(command, cwd=source, stdout=log, stderr=subprocess.STDOUT, timeout=args.timeout)
            code = process.returncode
            output = path.read_text(errors="replace")
            empty = args.kind == "verification" and any(text in output for text in ("[no tests to run]", "Ran 0 tests", "--- SKIP:", "test result: ok. 0 passed"))
            check.update(status="passed" if code == 0 and not empty else "failed",
                         exit_code=code, ended_at=now(), kind=args.kind,
                         output={"path": str(path.relative_to(base)), "sha256": sha256(path)})
            if empty:
                check["reason"] = "required verification reported missing or skipped tests"
        except subprocess.TimeoutExpired:
            check.update(status="failed", reason="check timeout", exit_code=None, ended_at=now(),
                         output={"path": str(path.relative_to(base)), "sha256": sha256(path)})
    records.append(check)
    atomic_json(args.candidate, candidate)
    print(json.dumps(check, sort_keys=True))
    return 0 if check["status"] == "passed" else 1


def seal(args):
    candidate, base, _ = load(args.candidate)
    try:
        first = build_record(candidate, base, "one")
    except (ValueError, OSError):
        first = None
    required = ["qualification", "proof-parity", "shutdown", "dom-browser", "vulnerability-scans", "hosted-ci", "durable-retention", "provenance-attestation"]
    checks = {}
    for name in required:
        records = [check for check in candidate.get("results", []) if check["name"] == name]
        checks[name] = records[-1]["status"] if records else "unrun"
    reference = candidate.get("reproducibility", {})
    if reference.get("path") == "reproducibility.json" and sha256(base / reference["path"]) == reference.get("sha256"):
        checks["reproducibility"] = json.loads((base / reference["path"]).read_text())["status"]
    else:
        checks["reproducibility"] = "unrun"
    files = {}
    allowed = [base / "candidate.json", base / "source.tar"]
    for directory in (base / "builds", base / "evidence"):
        if directory.exists():
            for path in directory.rglob("*"):
                if path.is_symlink():
                    raise ValueError("artifact retention refuses symlinks")
                if path.is_file() and not any(part in ("work", "package") for part in path.relative_to(base).parts):
                    allowed.append(path)
    for path in (base / "reproducibility.json", base / "pipeline.log", base / "ipam-preflight.json", base / "browser-image-id"):
        if path.exists():
            allowed.append(path)
    for path in allowed:
        files[str(path.relative_to(base))] = sha256(path)
    record = {"schema_version": 1, "profile": "synthetic-qualification", "production_attestation": False,
              "source": candidate["source"], "run_id": candidate["run_id"], "sealed_at": now(),
              "build_manifest": candidate.get("builds", {}).get("one"), "tested_images": first["images"] if first else {},
              "checks": checks, "release_gate": "qualified" if all(value == "passed" for value in checks.values()) else "blocked",
              "artifacts": files, "runtime_secrets_and_backups_excluded": True,
              "retention_status": "local package prepared; durable remote retrieval must be independently verified"}
    atomic_json(base / "release-manifest.json", record)
    print(json.dumps({"release_gate": record["release_gate"], "checks": checks}, sort_keys=True))
    return 0 if record["release_gate"] == "qualified" else 1


def bundle(args):
    _, base, _ = load(args.candidate)
    record = json.loads((base / "release-manifest.json").read_text())
    if args.output.exists():
        raise ValueError("retained bundle already exists")
    with tarfile.open(args.output, "w:gz") as archive:
        archive.add(base / "release-manifest.json", arcname="release-manifest.json", recursive=False)
        for relative, digest in sorted(record["artifacts"].items()):
            path = base / relative
            if path.is_symlink() or not path.resolve().is_relative_to(base) or sha256(path) != digest:
                raise ValueError("retention artifact is substituted or outside candidate")
            archive.add(path, arcname=relative, recursive=False)
    print(json.dumps({"bundle": str(args.output), "sha256": sha256(args.output)}))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    for name in ("compare", "seal", "bundle", "run", "note"):
        command = commands.add_parser(name)
        command.add_argument("--candidate", type=Path, required=True)
        if name in ("run", "note"):
            command.add_argument("--build", choices=("one", "two"), default="one")
            command.add_argument("--name", required=True)
            if name == "run":
                command.add_argument("--kind", choices=("verification", "compile", "scan"), default="verification")
                command.add_argument("--timeout", type=int, default=1800)
                command.add_argument("command", nargs=argparse.REMAINDER)
            else:
                command.add_argument("--status", choices=("blocked", "unrun", "failed"), required=True)
                command.add_argument("--reason", required=True)
        if name == "bundle":
            command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        action = compare if args.action == "compare" else seal if args.action == "seal" else bundle if args.action == "bundle" else result
        raise SystemExit(action(args))
    except (ValueError, OSError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        parser.exit(1, str(error) + "\n")
