#!/usr/bin/env python3
"""Verify artifact bytes and GitHub keyless origin, without inferring approval."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode = True
from source_record import atomic_json, sha256

GH_VERSION = "2.103.3"
GH_ARCHIVE_SHA256 = "4c806978ffce1cec70853302a56d70ac6da4f19bae7adca4e1a8ab00633dd91d"
GH_BINARY_SHA256 = "b768184570b12536be4ac1528893f6340d1c6a7b40b56ad45bca9cd0e87ad34d"
REPOSITORY = "5dg/nex-os"
WORKFLOW = REPOSITORY + "/.github/workflows/ci.yml"


def verify(args):
    import re
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_revision) or not re.fullmatch(r"[0-9a-f]{64}", args.subject_sha256):
        raise ValueError("full source revision and SHA256 subject digest required")
    if args.subject.is_symlink() or sha256(args.subject) != args.subject_sha256:
        raise ValueError("artifact bytes do not match the expected subject")
    if args.output.exists() or args.output.with_suffix(".verified.json").exists() or args.output.with_suffix(".error.txt").exists():
        raise ValueError("retain the previous provenance receipt; choose a fresh output path")
    tool = args.tool_root / "bin/gh-attestation"
    record = json.loads((tool.parent / "gh-attestation.json").read_text())
    if record.get("version") != GH_VERSION or record.get("archive_sha256") != GH_ARCHIVE_SHA256 or record.get("binary_sha256") != GH_BINARY_SHA256 or tool.is_symlink() or sha256(tool) != GH_BINARY_SHA256:
        raise ValueError("checksum-pinned attestation verifier required")
    command = [str(tool), "attestation", "verify", str(args.subject), "--repo", REPOSITORY,
               "--signer-workflow", WORKFLOW, "--signer-digest", args.source_revision,
               "--source-digest", args.source_revision, "--source-ref", "refs/heads/main",
               "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
               "--deny-self-hosted-runners", "--predicate-type", "https://slsa.dev/provenance/v1",
               "--format", "json"]
    if args.attestation_bundle:
        command += ["--bundle", str(args.attestation_bundle)]
    completed = subprocess.run(command, capture_output=True, timeout=180)
    # gh's signature/certificate/trusted-root verification is mandatory. A local
    # record or a matching checksum alone cannot produce a passed receipt.
    receipt = {"schema_version": 1, "verifier": {"version": GH_VERSION, "binary_sha256": record["binary_sha256"]},
               "subject_sha256": args.subject_sha256, "source_revision": args.source_revision,
               "repository": REPOSITORY, "workflow": WORKFLOW, "source_ref": "refs/heads/main",
               "self_hosted_runners_denied": True, "exit_code": completed.returncode,
               "origin_verification": "passed" if completed.returncode == 0 else "failed",
               "release_approval": False}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if completed.returncode == 0:
        verified = json.loads(completed.stdout)
        if not verified:
            raise ValueError("verifier returned no verified statements")
        proof_path = args.output.with_suffix(".verified.json")
        atomic_json(proof_path, verified)
        receipt["verified_statements_sha256"] = sha256(proof_path)
    else:
        # Errors remain diagnostic evidence, never a successful verification.
        error_path = args.output.with_suffix(".error.txt")
        error_path.write_bytes(completed.stderr[:65536])
        receipt["error_sha256"] = sha256(error_path)
    atomic_json(args.output, receipt)
    return completed.returncode


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subject", type=Path, required=True)
    parser.add_argument("--subject-sha256", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--attestation-bundle", type=Path)
    parser.add_argument("--tool-root", type=Path, default=Path(os.environ.get("NEX_TOOLS_DIR", "/workspace/.tools")))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        raise SystemExit(verify(args))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, str(error) + "\n")
