#!/usr/bin/env python3
"""Capture and inspect a source-bound synthetic qualification candidate.

Docker operations are deliberately executed only by the integration scheduler.
This tool's capture operation reads Git and creates a new private artifact tree;
it never changes a checkout or resets existing run state.
"""
from __future__ import annotations

import argparse
import datetime
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tarfile

sys.dont_write_bytecode = True
from source_record import COMPANION, atomic_json, identity, inputs, sha256, verify_artifacts, verify_physical_inputs

RUN_ID = re.compile(r"[0-9a-f]{12}\Z")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
IMAGE_ENV = {"control": "NEX_CONTROL_IMAGE", "guard": "NEX_GUARD_IMAGE", "workspace": "NEX_WORKSPACE_IMAGE", "fixtures": "NEX_FIXTURES_IMAGE", "postgres": "NEX_POSTGRES_IMAGE", "opa": "NEX_OPA_IMAGE"}


def git(root: Path, *arguments: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *arguments], text=True).strip()


def capture(args: argparse.Namespace) -> None:
    root = args.source.resolve(strict=True)
    if git(root, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("capture requires a coherent committed source tree")
    revision = git(root, "rev-parse", "--verify", args.revision + "^{commit}")
    if revision != git(root, "rev-parse", "HEAD"):
        raise ValueError("capture the reviewed current HEAD, not an unrelated revision")
    epoch = int(git(root, "show", "-s", "--format=%ct", revision))
    run_id = args.run_id or secrets.token_hex(6)
    if not RUN_ID.fullmatch(run_id):
        raise ValueError("run ID must contain exactly twelve lowercase hexadecimal characters")
    output = args.output.absolute()
    if output.exists():
        raise ValueError("candidate output must be new; retain previous candidates")
    output.mkdir(mode=0o700, parents=True)
    source = output / "source"
    source.mkdir(mode=0o700)
    archive_bytes = subprocess.check_output(["git", "-C", str(root), "archive", "--format=tar", revision])
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
        for member in archive.getmembers():
            if not member.isfile() and not member.isdir():
                raise ValueError("captured authored source must not contain links or special files")
        archive.extractall(source, filter="data")
    record = {"schema_version": 1, "revision": revision, "source_epoch": epoch, "inputs": inputs(source, canonical=True)}
    verify_physical_inputs(source, record["inputs"])
    atomic_json(source / COMPANION, record)
    archive_path = output / "source.tar"
    with tarfile.open(archive_path, "w", format=tarfile.PAX_FORMAT) as archive:
        for relative in sorted([*record["inputs"]["files"], COMPANION]):
            path = source / relative
            member = archive.gettarinfo(str(path), arcname=relative)
            member.uid = member.gid = 0
            member.uname = member.gname = ""
            member.mtime = epoch
            with path.open("rb") as stream:
                archive.addfile(member, stream)
    candidate = {"schema_version": 1, "run_id": run_id, "profile": "synthetic-qualification", "production_attestation": False,
                 "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "source": identity(source, canonical=True),
                 "source_directory": "source", "archive": {"path": "source.tar", "sha256": sha256(archive_path)},
                 "primary_project": "nex-alpha04-" + run_id, "restore_project": "nex-alpha04-" + run_id + "-restore", "builds": {}}
    atomic_json(output / "candidate.json", candidate)
    print(json.dumps({"candidate": str(output / "candidate.json"), "run_id": run_id, "revision": revision, "source_input_sha256": record["inputs"]["sha256"]}))


def load(path: Path) -> tuple[dict, Path, Path]:
    if path.is_symlink():
        raise ValueError("candidate manifest must be regular")
    data = json.loads(path.read_text())
    if data.get("schema_version") != 1 or not RUN_ID.fullmatch(data.get("run_id", "")):
        raise ValueError("unsupported candidate manifest")
    base = path.resolve().parent
    source = base / "source"
    if data.get("source_directory") != "source" or identity(source, canonical=True) != data.get("source"):
        raise ValueError("captured source identity mismatch")
    archive = data.get("archive", {})
    if archive.get("path") != "source.tar" or sha256(base / "source.tar") != archive.get("sha256"):
        raise ValueError("source archive digest mismatch")
    return data, base, source


def ipam(args: argparse.Namespace) -> None:
    data, base, source = load(args.candidate)
    block = ipaddress.ip_network(args.block, strict=True)
    if block.version != 4 or block.prefixlen != 20 or not any(block.subnet_of(ipaddress.ip_network(cidr)) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")):
        raise ValueError("E must supply an inspected RFC1918 IPv4 /20")
    networks = json.loads((source / "deploy/qualification/compose.yaml").read_text())["networks"]
    if any(not value.get("internal") for value in networks.values()):
        raise ValueError("all qualification links must remain internal")
    subnets = list(block.subnets(new_prefix=28))
    if len(networks) > 32:
        raise ValueError("network count exceeds the reviewed IPAM allocation")
    records = {}
    for mode, offset in (("primary", 0), ("restore", 32)):
        value = {"networks": {name: {"ipam": {"config": [{"subnet": str(subnets[offset + i])}]}} for i, name in enumerate(sorted(networks))}}
        path = base / f"{mode}-ipam.json"
        if path.exists():
            raise ValueError("IPAM declaration already exists; do not overwrite it")
        atomic_json(path, value)
        records[mode] = {"path": path.name, "sha256": sha256(path)}
    data["ipam"] = {"block": str(block), "scheduler_overlap_check_required": True, "overrides": records}
    atomic_json(args.candidate, data)
    print("Declared isolated IPAM; E must verify no Docker/host-route overlap before allocation")


def environment(args: argparse.Namespace) -> None:
    data, base, source = load(args.candidate)
    build_path = base / "builds" / args.build / "manifest.json"
    bound = data.get("builds", {}).get(args.build, {})
    if bound.get("path") != str(build_path.relative_to(base)) or sha256(build_path) != bound.get("sha256"):
        raise ValueError("build manifest is not bound to this candidate")
    build = json.loads(build_path.read_text())
    if build.get("source") != data["source"] or build.get("build_mode") != "canonical-container" or build.get("status") != "built":
        raise ValueError("only a completed source-bound canonical build can start a candidate")
    tools = build_path.parent / "bin"
    verify_artifacts(tools / "build-inputs.json", source, ("evidence", "qualification-pki"), require_canonical=True)
    values = {"NEX_QUAL_RUN_ID": data["run_id"], "NEX_QUAL_PROJECT": data["restore_project"] if args.restore else data["primary_project"], "NEX_QUAL_PRIMARY_PROJECT": data["primary_project"], "NEX_QUAL_RESTORE_PROJECT": data["restore_project"],
              "NEX_QUAL_STATE_DIR": str(base / ("restore-state" if args.restore else "state")), "NEX_QUAL_PRIMARY_STATE_DIR": str(base / "state"), "NEX_QUAL_RESTORE_STATE_DIR": str(base / "restore-state"),
              "NEX_QUAL_TOOL_DIR": str(tools), "NEX_QUAL_EVIDENCE_DIR": str(base / "evidence"), "NEX_QUAL_CANDIDATE_MANIFEST": str(args.candidate.resolve()),
              "NEX_QUAL_BACKUP_ROOT": str(base / "private-backups"),
              "NEX_QUAL_BUILD": args.build, "NEX_BUILD_MODE": "canonical", "NEX_SOURCE_INPUT_SHA256": data["source"]["inputs"]["sha256"]}
    for name, variable in IMAGE_ENV.items():
        image = build.get("images", {}).get(name, {}).get("id", "")
        if not IMAGE_ID.fullmatch(image):
            raise ValueError(f"missing immutable candidate image identity: {name}")
        values[variable] = image
    for mode in ("primary", "restore"):
        record = data.get("ipam", {}).get("overrides", {}).get(mode, {})
        path = base / f"{mode}-ipam.json"
        if record.get("path") != path.name or sha256(path) != record.get("sha256"):
            raise ValueError("manifest-bound IPAM declaration required")
        values["NEX_QUAL_" + mode.upper() + "_NETWORK_FILE"] = str(path)
    for key, value in values.items():
        if any(c in value for c in "\r\n\0"):
            raise ValueError("invalid candidate environment value")
        print(key + "=" + value)


def verify_images(args: argparse.Namespace) -> None:
    data, base, _ = load(args.candidate)
    path = base / "builds" / args.build / "manifest.json"
    bound = data.get("builds", {}).get(args.build, {})
    if bound.get("path") != str(path.relative_to(base)) or bound.get("sha256") != sha256(path):
        raise ValueError("build manifest binding mismatch")
    build = json.loads(path.read_text())
    environment_values = {key: value for key, value in os.environ.items() if key not in
                          ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")}
    for name in IMAGE_ENV:
        record = build.get("images", {}).get(name, {})
        image_id = record.get("id", "")
        if not IMAGE_ID.fullmatch(image_id):
            raise ValueError("invalid recorded image identity")
        output = subprocess.check_output(["docker", "--host=unix:///var/run/docker.sock", "image", "inspect", image_id,
            "--format", '{"id":{{json .Id}},"labels":{{json .Config.Labels}},"digests":{{json .RepoDigests}}}'],
            env=environment_values, text=True)
        actual = json.loads(output)
        if actual["id"] != image_id:
            raise ValueError("image identity differs from the tested candidate")
        if name == "opa":
            if record.get("requested") not in (actual.get("digests") or []):
                raise ValueError("OPA vendor digest mismatch")
        else:
            labels = actual.get("labels") or {}
            if labels.get("org.nex.source.inputs") != data["source"]["inputs"]["sha256"] or labels.get("org.opencontainers.image.revision") != data["source"]["revision"]:
                raise ValueError("image source binding mismatch: " + name)
    print("All six immutable candidate image/source identities verified")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    p = commands.add_parser("capture")
    p.add_argument("--source", type=Path, default=Path(__file__).resolve().parent.parent)
    p.add_argument("--revision", default="HEAD")
    p.add_argument("--run-id")
    p.add_argument("--output", type=Path, required=True)
    p = commands.add_parser("verify")
    p.add_argument("--candidate", type=Path, required=True)
    p = commands.add_parser("ipam")
    p.add_argument("--candidate", type=Path, required=True)
    p.add_argument("--block", required=True)
    for action in ("env", "verify-images"):
        p = commands.add_parser(action)
        p.add_argument("--candidate", type=Path, required=True)
        p.add_argument("--build", choices=("one", "two"), default="one")
        p.add_argument("--restore", action="store_true")
    args = parser.parse_args()
    try:
        if args.action == "capture":
            capture(args)
        elif args.action == "verify":
            data, _, _ = load(args.candidate)
            print("Verified captured source " + data["source"]["revision"])
        elif args.action == "ipam":
            ipam(args)
        elif args.action == "env":
            environment(args)
        else:
            verify_images(args)
    except (ValueError, OSError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
