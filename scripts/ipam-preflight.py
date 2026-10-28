#!/usr/bin/env python3
"""Inspect an explicitly chosen qualification pool; never allocate or delete."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode = True
from source_record import atomic_json


def check(block):
    pool = ipaddress.ip_network(block, strict=True)
    if pool.version != 4 or pool.prefixlen != 20 or not any(pool.subnet_of(ipaddress.ip_network(value)) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")):
        raise ValueError("an explicit RFC1918 /20 is required")
    environment = {k: v for k, v in os.environ.items() if k not in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")}
    docker = ["docker", "--host=unix:///var/run/docker.sock"]
    networks = subprocess.check_output(docker + ["network", "ls", "--format", "{{.ID}}"], env=environment, text=True).split()
    observed = []
    for network in networks:
        values = json.loads(subprocess.check_output(docker + ["network", "inspect", network, "--format", "{{json .IPAM.Config}}"], env=environment, text=True))
        observed.extend({"source": "docker", "subnet": item["Subnet"]} for item in values or [] if item.get("Subnet"))
    routes = json.loads(subprocess.check_output(["ip", "-json", "route", "show", "table", "all"], text=True))
    observed.extend({"source": "host-route", "subnet": row["dst"]} for row in routes if row.get("dst") not in (None, "default"))
    collisions = []
    for item in observed:
        network = ipaddress.ip_network(item["subnet"], strict=False)
        if network.version == 4 and pool.overlaps(network):
            collisions.append(item)
    return {"schema_version": 1, "requested_pool": str(pool), "allocation_performed": False,
            "observed_networks_and_routes": observed, "overlaps": collisions, "status": "passed" if not collisions else "failed"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--block", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.output.exists():
            raise ValueError("retain previous IPAM evidence; choose a fresh output")
        result = check(args.block)
        atomic_json(args.output, result)
        raise SystemExit(0 if result["status"] == "passed" else 1)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, str(error) + "\n")
