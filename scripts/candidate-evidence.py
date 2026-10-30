#!/usr/bin/env python3
"""Execute checks and retain a non-secret, source/image-bound release record."""
import argparse
import datetime
import io
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
from phase_admission import admit, gzip_bound, QUALIFICATION_FORECAST, RESERVE
from image_archive import inspect as inspect_image_archive


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
    if data.get("images", {}).get("opa", {}).get("archive_origin") == "verified-vendor-base-reconstruction-v1":
        for directory in (path.parent / "bin", path.parent / "package", path.parent / "package/opa"):
            if directory.is_symlink() or not directory.is_dir():
                raise ValueError("regular OPA compiler evidence directories required")
        names = ["bin/opa", "bin/opa-build.txt", "bin/opa-source-inventory.txt", "bin/opa-bundle-tests.txt", "bin/opa-topdown-tests.txt", "bin/opa-private-key-tests.txt", "bin/opa-rest-tests.txt", "bin/opa-jwe-tests.txt", "package/opa/source-files.bin", "package/opa/source-tree.bin"]
        exports = data.get("phase_exports", {}).get("opa", {})
        if set(exports) != set(names):
            raise ValueError("complete OPA compiler evidence required")
        for relative in names:
            exported = path.parent / relative
            record = exports[relative]
            if exported.is_symlink() or not exported.is_file() or sha256(exported) != record.get("sha256") or exported.stat().st_mode & 0o7777 != record.get("mode"):
                raise ValueError("OPA compiler evidence differs from completed build")
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
        preparations = {}
        for build, image in (("one", left), ("two", right)):
            if image["archive"]["path"] != "images/" + name + ".tar":
                raise ValueError("unexpected image archive path")
            archive = base / "builds" / build / image["archive"]["path"]
            if sha256(archive) != image["archive"]["sha256"]:
                raise ValueError("saved image archive is stale or substituted")
            preparation = image.get("archive_preparation", {})
            report_path = base / "builds" / build / (name + "-archive-preparation.json")
            if preparation.get("path") != report_path.name or report_path.is_symlink() or sha256(report_path) != preparation.get("sha256"):
                raise ValueError("canonical archive transformation proof is missing or substituted")
            report = json.loads(report_path.read_text())
            if (report.get("schema_version") != 1 or report.get("kind") != "outer-docker-tar-timestamps-v1"
                    or report.get("source_epoch") != candidate["source"]["source_epoch"]
                    or report.get("image_id") != image["id"] or report.get("emitted_sha256") != image["archive"]["sha256"]
                    or not re.fullmatch(r"[a-f0-9]{64}", report.get("raw_sha256", ""))
                    or report.get("member_bytes_and_non_time_metadata_preserved") is not True):
                raise ValueError("canonical archive proof differs from declared emitted image")
            expected = {path: {**entry, "mtime": report["source_epoch"]} for path, entry in report["members"].items()}
            if inspect_image_archive(archive, image["id"]) != expected:
                raise ValueError("emitted archive members differ from exact transformation proof")
            preparations[build] = report
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
                        "canonical_image_archive_identical": left["archive"]["sha256"] == right["archive"]["sha256"],
                        "raw_docker_export_archive_identical": preparations["one"]["raw_sha256"] == preparations["two"]["raw_sha256"],
                        "raw_docker_export_archive_sha256": {build: report["raw_sha256"] for build, report in preparations.items()},
                        "archive_transformation_proofs": {"one": left["archive_preparation"], "two": right["archive_preparation"]}}
        if not images[name]["runtime_payload_identical"]:
            files = [json.loads((base / "builds" / build / (name + "-payload.json")).read_text())["files"] for build in ("one", "two")]
            changed = [path for path in sorted(files[0].keys() | files[1].keys()) if files[0].get(path) != files[1].get(path)]
            images[name]["changed_runtime_paths"] = changed
    payload_equal = all(image["runtime_payload_identical"] for image in images.values())
    oci_equal = all(image["oci_configuration_identical"] and image["oci_layers_identical"] and image["canonical_image_archive_identical"] for image in images.values())
    result = {"schema_version": 1, "source": candidate["source"], "measured_at": now(),
              "targets": {"native_binaries": "exact bytes", "runtime_payload": "merged path/type/mode/uid/gid/content/link/device/PAX-xattrs-ACL-flags; timestamps excluded",
                          "oci": "configuration/layer bytes and actual emitted canonical archive bytes",
                          "raw_docker_export": "raw archive SHA separately reported, with exact producer transformation proof"},
              "native_binaries_identical": binary_equal, "runtime_payloads_identical": payload_equal,
              "oci_bytes_identical": oci_equal, "images": images,
              "raw_docker_export_archives_identical": all(image["raw_docker_export_archive_identical"] for image in images.values()),
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
    records = candidate.get("results", [])
    if not isinstance(records, list):
        raise ValueError("candidate results must be an append-only list")
    binding = {key: value for key, value in candidate.items() if key != "results"}
    stamp = str(time.time_ns())
    path = base / "evidence" / (args.name + "-" + stamp + ".log")
    path.parent.mkdir(mode=0o700, exist_ok=True)
    check = {"name": args.name, "build": args.build, "run_id": candidate["run_id"],
             "build_manifest": candidate.get("builds", {}).get(args.build), "source_revision": candidate["source"]["revision"],
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
        except OSError as error:
            check.update(status="failed", reason="check could not execute: " + str(error), exit_code=None, ended_at=now())
            if path.exists():
                check["output"] = {"path": str(path.relative_to(base)), "sha256": sha256(path)}
    # Nested gate CLIs append their own results while this command runs. Never
    # replace their records with the snapshot loaded before subprocess.run().
    # Only appends are permitted; source/build/run and prior checks stay bound.
    try:
        latest, latest_base, _ = load(args.candidate)
        if latest_base != base or {key: value for key, value in latest.items() if key != "results"} != binding:
            raise ValueError("immutable candidate binding changed during check")
        latest_records = latest.get("results", [])
        if not isinstance(latest_records, list) or latest_records[:len(records)] != records:
            raise ValueError("prior candidate results changed during check")
        if build is not None and build_record(latest, latest_base, args.build) != build:
            raise ValueError("tested build changed during check")
    except (ValueError, OSError, json.JSONDecodeError) as error:
        check.update(status="failed", reason="post-check candidate validation failed: " + str(error), ended_at=now())
        # Preserve attempted work even when the candidate can no longer safely
        # receive a result. Do not repair or overwrite the substituted manifest.
        atomic_json(path.with_suffix(".json"), check)
        print(json.dumps(check, sort_keys=True))
        return 1
    atomic_json(path.with_suffix(".json"), check)
    latest.setdefault("results", []).append(check)
    atomic_json(args.candidate, latest)
    print(json.dumps(check, sort_keys=True))
    return 0 if check["status"] == "passed" else 1


def seal(args):
    candidate, base, _ = load(args.candidate)
    try:
        first = build_record(candidate, base, "one")
    except (ValueError, OSError):
        first = None
    required = ["qualification", "proof-parity", "shutdown", "packaged-shutdown", "history-pagination", "dom-browser", "vulnerability-scans", "hosted-ci", "durable-retention", "provenance-attestation"]
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
    excluded = {base / "builds" / build / name for build in ("one", "two") for name in ("work", "package")}
    def walk_error(error):
        raise error
    for directory in (base / "builds", base / "evidence"):
        if directory.is_symlink():
            raise ValueError("artifact retention refuses symlinks")
        if directory.exists():
            for root, directories, names in os.walk(directory, topdown=True, followlinks=False, onerror=walk_error):
                for name in directories[:]:
                    path = Path(root) / name
                    if path in excluded:
                        directories.remove(name)
                    elif path.is_symlink():
                        raise ValueError("artifact retention refuses symlinks")
                for name in names:
                    path = Path(root) / name
                    if path in excluded:
                        continue
                    if path.is_symlink():
                        raise ValueError("artifact retention refuses symlinks")
                    if not path.is_file():
                        raise ValueError("artifact retention requires regular files")
                    allowed.append(path)
    for path in (base / "reproducibility.json", base / "pipeline.log", base / "ipam-preflight.json", base / "browser-image-id"):
        if path.exists() or path.is_symlink():
            allowed.append(path)
    for path in allowed:
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(base):
            raise ValueError("artifact retention requires regular in-candidate files, not symlinks")
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
    candidate, base, source = load(args.candidate)
    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate sealed field or artifact")
            value[key] = item
        return value
    record = json.loads((base / "release-manifest.json").read_text(), object_pairs_hook=unique_object)
    if record.get("source") != candidate["source"] or record.get("run_id") != candidate["run_id"]:
        raise ValueError("sealed candidate identity mismatch")
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("retained bundle already exists")
    if args.output.resolve().is_relative_to(source):
        raise ValueError("bundle output must be outside captured source")
    # Construct exactly the members we will write, including PAX headers and
    # logical sizes of sparse files. No bundle is opened until capacity passes.
    members = []
    names = set()
    with tarfile.TarFile(fileobj=io.BytesIO(), mode="w", format=tarfile.PAX_FORMAT) as metadata:
        for relative, digest in [("release-manifest.json", sha256(base / "release-manifest.json")), *sorted(record["artifacts"].items())]:
            if relative in names or Path(relative).is_absolute() or any(part in (".", "..") for part in relative.split("/")) or Path(relative).as_posix() != relative:
                raise ValueError("duplicate or noncanonical sealed artifact path")
            names.add(relative)
            path = base / relative
            if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(base) or sha256(path) != digest:
                raise ValueError("retention artifact is substituted or outside candidate")
            member = metadata.gettarinfo(str(path), arcname=relative)
            if not member.isfile():
                raise ValueError("retention requires regular logical file members")
            members.append((path, member, digest))
    raw_bytes = sum(len(member.tobuf(format=tarfile.PAX_FORMAT)) + ((member.size + 511) // 512) * 512
                    for _, member, _ in members) + 1024
    tar_bytes = ((raw_bytes + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE
    bound = gzip_bound(tar_bytes)
    admit(candidate, "bundle", {"output": (args.output.parent, bound), "candidate": (base, 0),
          "host": (Path("/"), 0), "temporary": (Path("/tmp"), 0)},
          {"release_manifest_sha256": sha256(base / "release-manifest.json"),
           "member_count": len(members), "logical_file_bytes": sum(member.size for _, member, _ in members),
           "tar_bytes_including_headers_padding": tar_bytes, "gzip_upper_bound_bytes": bound,
           "bound_method": "zlib compressBound(tar bytes) + 1 MiB wrapper/metadata allowance"},
          base / ("bundle-admission-" + str(time.time_ns()) + ".json"))
    with tarfile.open(args.output, "x:gz", format=tarfile.PAX_FORMAT) as archive:
        for path, member, digest in members:
            if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(base) or sha256(path) != digest or path.stat().st_size != member.size:
                raise ValueError("retention artifact changed after resource admission")
            with path.open("rb") as stream:
                archive.addfile(member, stream)
    print(json.dumps({"bundle": str(args.output), "sha256": sha256(args.output)}))
    return 0


def admit_qualification(args):
    candidate, base, _ = load(args.candidate)
    build_record(candidate, base, "one")
    record_path = base / "evidence" / ("qualification-admission-" + str(time.time_ns()) + ".json")
    environment = {key: value for key, value in os.environ.items() if key not in
                   ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")}
    try:
        raw = subprocess.check_output(["docker", "--host=unix:///var/run/docker.sock", "info", "--format",
            '{"driver":{{json .Driver}},"data_root":{{json .DockerRootDir}}}'], env=environment, text=True, timeout=30)
        docker = json.loads(raw)
        if not isinstance(docker, dict) or not isinstance(docker.get("data_root"), str) or not Path(docker["data_root"]).is_absolute():
            raise ValueError("absolute actual Docker data filesystem required")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        atomic_json(record_path, {"schema_version": 1, "phase": "qualification", "status": "blocked",
                    "run_id": candidate["run_id"], "source_input_sha256": candidate["source"]["inputs"]["sha256"],
                    "source_revision": candidate["source"]["revision"], "builds": candidate.get("builds", {}),
                    "reserve_bytes": RESERVE, "forecast_additional_bytes": QUALIFICATION_FORECAST,
                    "measured_at": now(), "reason": "Docker filesystem identity unavailable: " + str(error)})
        raise ValueError("Docker filesystem identity unavailable; qualification admission blocked") from error
    result = admit(candidate, "qualification", {"output": (base, QUALIFICATION_FORECAST),
        "docker": (Path(docker["data_root"]), QUALIFICATION_FORECAST), "host": (Path("/"), 0), "temporary": (Path("/tmp"), 0)},
        {"docker": docker, "forecast_basis": "6 GiB combined qualification growth, including measured runtime layers"},
        record_path)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    for name in ("compare", "seal", "bundle", "run", "note", "admit-qualification"):
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
        action = {"compare": compare, "seal": seal, "bundle": bundle, "admit-qualification": admit_qualification}.get(args.action, result)
        raise SystemExit(action(args))
    except (ValueError, OSError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        parser.exit(1, str(error) + "\n")
