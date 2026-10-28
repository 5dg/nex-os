#!/usr/bin/env bash
# E executes this from a reviewed capture. Native/plaintext fixtures are separate
# from the qualified TLS stack. Every failed fixture and its private data survive.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONDONTWRITEBYTECODE=1
exec python3 - "$@" <<'PY'
import argparse
import asyncio
import contextlib
import http.client
import io
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, "scripts")
import candidate
from source_record import atomic_json, sha256


class FixtureError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise FixtureError(message)


def regular(path):
    require(not path.is_symlink() and path.is_file(), "regular candidate artifact required")


def configuration(manifest):
    require(manifest.is_absolute(), "an absolute candidate manifest is required")
    require(manifest.name == "candidate.json", "candidate.json manifest required")
    data, base, source = candidate.load(manifest)
    require(source.resolve() == Path.cwd().resolve(), "run the wrapper from the captured source")
    require(base.stat().st_uid == os.getuid() and not (base.stat().st_mode & 0o077),
            "candidate directory must be private and owned by the invoking user")
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        candidate.environment(argparse.Namespace(candidate=manifest, build="one", restore=False))
    environment = dict(line.split("=", 1) for line in output.getvalue().splitlines())
    path = base / "native-fixture-ipam.json"
    regular(path)
    binding = data.get("ipam", {}).get("native_fixture", {})
    require(binding.get("path") == path.name and binding.get("sha256") == sha256(path),
            "native fixture declaration is not bound to the candidate")
    native = json.loads(path.read_text())
    pool = ipaddress.ip_network(data["ipam"]["block"], strict=True)
    require(pool.version == 4 and pool.prefixlen == 20 and any(
        pool.subnet_of(ipaddress.ip_network(value)) for value in
        ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")), "private /20 allocation required")
    subnet = list(pool.subnets(new_prefix=28))[64]
    expected = {"schema_version": 1, "run_id": data["run_id"],
        "source_input_sha256": data["source"]["inputs"]["sha256"],
        "network_name": "nex-alpha04-" + data["run_id"] + "-native-fixtures",
        "internal": True, "subnet": str(subnet),
        "postgres_ip": str(subnet.network_address + 2), "opa_ip": str(subnet.network_address + 3),
        "maximum_service_endpoints": 2}
    require(native == expected, "native network declaration differs from the reserved allocation")
    for name in ("postgres", "opa"):
        require(candidate.IMAGE_ID.fullmatch(environment["NEX_" + name.upper() + "_IMAGE"]),
                "immutable fixture image IDs required")
    policy = source / "policies" / "guard.rego"
    regular(policy)
    # Reject delimiter-bearing bind paths rather than introducing Docker CSV parsing.
    require(not any(char in str(base) for char in ",\r\n\0"), "unsupported candidate path")
    return data, base, source, environment, native


class Runtime:
    def __init__(self, data, base, source, environment, native):
        self.data, self.base, self.source = data, base, source
        self.environment, self.native = environment, native
        self.private = base / "private-native-fixtures"
        self.record_path = base / "evidence" / "native-fixtures.json"
        self.labels = {"org.nex.native-fixtures": "development-plaintext",
            "org.nex.run-id": data["run_id"],
            "org.nex.source.inputs": data["source"]["inputs"]["sha256"]}
        self.names = {name: native["network_name"] + "-" + name for name in ("postgres", "opa")}
        self.ids = {}
        self.network_id = None
        self.record = {"schema_version": 1, "run_id": data["run_id"], "source": data["source"],
            "scope": "native development/plaintext fixture; separate from qualified TLS verification",
            "production_attestation": False, "status": "preflight", "subnet": native["subnet"],
            "network_name": native["network_name"], "images": {
                name: environment["NEX_" + name.upper() + "_IMAGE"] for name in self.names},
            "private_state_excluded_from_bundle": True, "resources_preserved": True}
        self.docker_env = {key: value for key, value in os.environ.items() if key not in
            ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")}

    def docker(self, *arguments, timeout=30):
        # Never inherit a remote Docker endpoint or print daemon errors/commands.
        result = subprocess.run(["docker", "--host=unix:///var/run/docker.sock", *arguments],
            env=self.docker_env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        require(result.returncode == 0, "native fixture Docker operation failed (private state retained)")
        return result.stdout.strip()

    def inspect(self, kind, name):
        return json.loads(self.docker(kind, "inspect", name))[0]

    def owned(self, value, kind, name):
        labels = value.get("Labels") if kind == "network" else value.get("Config", {}).get("Labels")
        actual_name = value.get("Name", "").lstrip("/")
        require(actual_name == name and all((labels or {}).get(key) == val for key, val in self.labels.items()),
                "refusing a resource outside this exact native fixture ownership")

    def save(self):
        atomic_json(self.record_path, self.record)

    def preflight(self):
        evidence = self.base / "evidence"
        require(not evidence.is_symlink() and (not evidence.exists() or
            (evidence.is_dir() and evidence.stat().st_uid == os.getuid() and not (evidence.stat().st_mode & 0o022))),
            "candidate evidence directory must be owned and may not redirect writes")
        require(not self.private.exists() and not self.private.is_symlink(),
                "native state already exists; preserve it and capture a new candidate")
        require(not self.record_path.exists() and not self.record_path.is_symlink(),
                "native fixture record already exists")
        # This also checks the OPA vendor digest and PG source labels against the build.
        with contextlib.redirect_stdout(io.StringIO()):
            candidate.verify_images(argparse.Namespace(candidate=self.base / "candidate.json", build="one"))
        existing = self.docker("container", "ls", "-a", "--format", "{{.Names}}").splitlines()
        require(not any(name in existing for name in self.names.values()), "native container name already exists")
        subnet = ipaddress.ip_network(self.native["subnet"])
        observed = []
        for network_id in self.docker("network", "ls", "--format", "{{.ID}}").splitlines():
            value = self.inspect("network", network_id)
            require(value.get("Name") != self.native["network_name"], "native network already exists")
            for config in value.get("IPAM", {}).get("Config") or []:
                if config.get("Subnet"):
                    observed.append({"source": "docker", "subnet": config["Subnet"]})
        routes = subprocess.run(["ip", "-json", "route", "show", "table", "all"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        require(routes.returncode == 0, "host route preflight failed")
        observed.extend({"source": "host-route", "subnet": row["dst"]}
            for row in json.loads(routes.stdout) if row.get("dst") not in (None, "default"))
        for item in observed:
            other = ipaddress.ip_network(item["subnet"], strict=False)
            require(other.version != 4 or not subnet.overlaps(other), "native /28 overlaps an existing network or route")
        # Only this reserved /28 must be free: the candidate's primary and restore
        # sibling subnets may already exist elsewhere in its /20.
        self.record["preflight"] = {"status": "passed", "observed_networks_and_routes": observed}

    def create(self):
        self.private.mkdir(mode=0o700)  # exclusive, no retries over existing state
        os.chmod(self.private, 0o700)
        (self.private / "pgdata").mkdir(mode=0o700)
        self.password = secrets.token_hex(32)
        password_file = self.private / "postgres-password"
        fd = os.open(password_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(self.password + "\n")
        self.record["status"] = "creating"
        self.save()
        labels = [argument for key, value in self.labels.items() for argument in ("--label", key + "=" + value)]
        self.network_id = self.docker("network", "create", "--driver", "bridge", "--internal",
            "--subnet", self.native["subnet"], *labels, self.native["network_name"])
        network = self.inspect("network", self.network_id)
        self.owned(network, "network", self.native["network_name"])
        require(network.get("Internal") is True and network.get("Driver") == "bridge"
            and [item.get("Subnet") for item in network.get("IPAM", {}).get("Config", [])] == [self.native["subnet"]]
            and not network.get("Containers"), "unexpected native network configuration")
        common = ["--pull=never", "--network", self.native["network_name"], *labels,
            "--read-only", "--security-opt", "no-new-privileges:true", "--cap-drop", "ALL",
            "--cpus", "1", "--pids-limit", "128", "--restart", "no", "--stop-timeout", "75"]
        pg = ["--name", self.names["postgres"], "--ip", self.native["postgres_ip"], "--memory", "512m", "--memory-swap", "512m",
            "--tmpfs", "/var/run/postgresql:rw,noexec,nosuid,size=16m", "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m",
            "--mount", "type=bind,src=" + str(self.private / "pgdata") + ",dst=/var/lib/postgresql/data",
            "--mount", "type=bind,src=" + str(password_file) + ",dst=/run/secrets/native-postgres-password,readonly",
            "--env", "POSTGRES_PASSWORD_FILE=/run/secrets/native-postgres-password", "--env", "POSTGRES_USER=nex",
            "--env", "POSTGRES_DB=nex", "--env", "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256"]
        # The pinned official entrypoint initializes/chowns only this new mounted
        # PGDATA as container root, then drops to postgres UID999. No host chown,
        # sudo, permission widening, old clusters or application keys are used.
        for capability in ("CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"):
            pg.extend(("--cap-add", capability))
        self.ids["postgres"] = self.docker("container", "create", *common, *pg,
            self.environment["NEX_POSTGRES_IMAGE"], "postgres", "-c", "max_connections=40", "-c", "shared_buffers=32MB")
        self.ids["opa"] = self.docker("container", "create", *common, "--name", self.names["opa"],
            "--ip", self.native["opa_ip"], "--memory", "256m", "--memory-swap", "256m", "--mount",
            "type=bind,src=" + str(self.source / "policies") + ",dst=/policies,readonly",
            self.environment["NEX_OPA_IMAGE"], "run", "--server", "--addr=0.0.0.0:8181",
            "--disable-telemetry", "/policies/guard.rego")
        for name, container_id in self.ids.items():
            value = self.inspect("container", container_id)
            self.owned(value, "container", self.names[name])
            require(value.get("Image") == self.environment["NEX_" + name.upper() + "_IMAGE"], "fixture image mismatch")
            self.docker("container", "start", container_id)
            value = self.inspect("container", container_id)
            networks = value.get("NetworkSettings", {}).get("Networks", {})
            require(list(networks) == [self.native["network_name"]]
                and networks[self.native["network_name"]].get("IPAddress") == self.native[name + "_ip"]
                and not value.get("HostConfig", {}).get("PortBindings"), "fixture endpoint is not private and fixed")
        network = self.inspect("network", self.network_id)
        require(set(network.get("Containers", {})) == set(self.ids.values()), "unexpected native fixture network endpoint")
        self.record.update(status="started", network_id=self.network_id, containers=self.ids)
        self.save()

    def stop(self):
        # Inspect exact deterministic names even after an interrupted create call;
        # ownership must match before stopping. No delete, volume reset or rm -v.
        stopped, failures = {}, []
        owned_ids = []
        try:
            existing = set(self.docker("container", "ls", "-a", "--format", "{{.Names}}").splitlines())
        except (FixtureError, subprocess.SubprocessError, OSError, ValueError):
            existing = set()
            failures.append("container-reconciliation-unknown")
        for name, expected in self.names.items():
            if expected not in existing:
                if name in self.ids:
                    failures.append(name + "-missing")
                continue
            try:
                value = self.inspect("container", expected)
            except (FixtureError, subprocess.SubprocessError, OSError, ValueError):
                failures.append(name + "-inspect-unknown")
                continue
            try:
                self.owned(value, "container", expected)
                require(value.get("Image") == self.environment["NEX_" + name.upper() + "_IMAGE"], "fixture image changed")
                owned_ids.append(value["Id"])
            except FixtureError:
                failures.append(name)
        if owned_ids:
            try:
                self.docker("container", "stop", "--time", "75", *owned_ids, timeout=85)
                for container_id in owned_ids:
                    value = self.inspect("container", container_id)
                    require(not value.get("State", {}).get("Running"), "native fixture did not stop")
                    stopped[container_id] = {"exit_code": value["State"].get("ExitCode"), "running": False}
            except (FixtureError, subprocess.TimeoutExpired, OSError):
                failures.append("bounded-stop")
        self.record["cleanup"] = {"status": "failed" if failures else "stopped-and-retained",
            "containers": stopped, "failures": failures, "network_retained": True, "private_state_retained": True}
        if failures:
            self.record["status"] = "failed"
        self.save()
        return not failures


async def fixture_child(runtime, command):
    interrupted = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, interrupted.set)
    servers, connections = [], set()
    child = None

    def group_alive():
        if child is None:
            return False
        try:
            os.killpg(child.pid, 0)
            return True
        except ProcessLookupError:
            return False

    async def stop_child_group():
        if group_alive():
            with contextlib.suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGTERM)
            deadline = time.monotonic() + 75
            while group_alive() and time.monotonic() < deadline:
                await asyncio.sleep(0.05)
            if group_alive():
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(child.pid, signal.SIGKILL)
                runtime.record["child_forced_kill"] = True
        if child and child.returncode is None:
            await child.wait()

    async def relay(reader, writer, destination, port):
        task = asyncio.current_task()
        if len(connections) >= 64:
            writer.close()
            return
        connections.add(task)
        upstream = None
        pipes = []
        try:
            remote, upstream = await asyncio.wait_for(asyncio.open_connection(destination, port), 5)

            async def pipe(source, target):
                while chunk := await source.read(65536):
                    target.write(chunk)
                    await target.drain()
                if target.can_write_eof():
                    target.write_eof()

            pipes = [asyncio.create_task(pipe(reader, upstream)), asyncio.create_task(pipe(remote, writer))]
            await asyncio.gather(*pipes)
        except (OSError, asyncio.TimeoutError, ConnectionError):
            pass
        finally:
            for pending in pipes:
                pending.cancel()
            await asyncio.gather(*pipes, return_exceptions=True)
            writer.close()
            if upstream:
                upstream.close()
            connections.discard(task)

    def policy_ready(port):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        try:
            connection.request("GET", "/v1/policies")
            response = connection.getresponse()
            body = response.read(1024 * 1024)
            values = json.loads(body).get("result", [])
            return response.status == 200 and len(values) == 1 and values[0].get("raw", "").strip() == (
                runtime.source / "policies" / "guard.rego").read_text().strip()
        except (OSError, ValueError, http.client.HTTPException):
            return False
        finally:
            connection.close()

    try:
        ports = {}
        for name, destination_port in (("postgres", 5432), ("opa", 8181)):
            destination = runtime.native[name + "_ip"]
            server = await asyncio.start_server(
                lambda reader, writer, host=destination, port=destination_port: relay(reader, writer, host, port),
                "127.0.0.1", 0)
            servers.append(server)
            ports[name] = server.sockets[0].getsockname()[1]
        # Parent owns the bound sockets continuously: no find-a-free-port race,
        # Docker host publish, proxy environment, external DNS or remote relay.
        deadline = time.monotonic() + 45
        while True:
            if interrupted.is_set():
                raise FixtureError("native fixtures interrupted before readiness")
            try:
                pg = await asyncio.to_thread(runtime.docker, "container", "exec", runtime.ids["postgres"],
                    "pg_isready", "--host=127.0.0.1", "--port=5432", "--username=nex", "--dbname=nex", timeout=5)
                ready = "accepting connections" in pg and await asyncio.to_thread(policy_ready, ports["opa"])
            except (FixtureError, subprocess.TimeoutExpired):
                ready = False
            if ready:
                break
            require(time.monotonic() < deadline, "native fixture readiness failed; state retained")
            try:
                await asyncio.wait_for(interrupted.wait(), 0.25)
            except asyncio.TimeoutError:
                pass
        environment = os.environ.copy()
        environment.update(runtime.environment)
        environment["NEX_TEST_DATABASE_URL"] = "postgres://nex:" + runtime.password + "@127.0.0.1:" + str(ports["postgres"]) + "/nex?sslmode=disable"
        environment["NEX_TEST_OPA_URL"] = "http://127.0.0.1:" + str(ports["opa"])
        for variable in ("NO_PROXY", "no_proxy"):
            environment[variable] = ",".join(filter(None, (environment.get(variable, ""), "localhost", "127.0.0.1")))
        runtime.record.update(status="ready", loopback_ports=ports)
        runtime.save()
        # Only the controlled suite inherits credentials. Do not echo its env,
        # connection URLs, raw Docker inspect/logs or a reconstructed command.
        child = await asyncio.create_subprocess_exec(*command, cwd=runtime.source, env=environment, start_new_session=True)
        completed = asyncio.create_task(child.wait())
        cancelled = asyncio.create_task(interrupted.wait())
        done, _ = await asyncio.wait((completed, cancelled), timeout=1500, return_when=asyncio.FIRST_COMPLETED)
        if completed in done:
            code = completed.result()
            if group_alive():
                # A successful shell leader is insufficient if test/kernel
                # grandchildren escaped its own completion bookkeeping.
                runtime.record["child_descendants_survived_leader"] = True
                code = 1
        else:
            code = 130 if interrupted.is_set() else 124
        cancelled.cancel()
        await stop_child_group()
        await completed
        runtime.record.update(status="passed" if code == 0 else "failed",
            child_status="passed" if child.returncode == 0 else "failed",
            child_exit_code=child.returncode, supervision_exit_code=code)
        runtime.save()
        return code
    finally:
        if child and group_alive():
            with contextlib.suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
        if child and child.returncode is None:
            await child.wait()
        for server in servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in servers))
        for task in list(connections):
            task.cancel()
        await asyncio.gather(*list(connections), return_exceptions=True)
        for signum in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(signum)


def main():
    parser = argparse.ArgumentParser(description="Private one-shot candidate-native PostgreSQL and OPA fixtures")
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--plan", action="store_true", help="validate source/IPAM only, without runtime or state creation")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    require(bool(command), "supply a child suite after --")
    runtime = Runtime(*configuration(args.candidate))
    if args.plan:
        print(json.dumps(runtime.record, sort_keys=True))
        return 0
    os.umask(0o077)
    runtime.preflight()
    code = 1
    # Before asyncio installs persistent handlers, interrupt synchronous setup
    # through the same retained-state finally path.
    previous = signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        runtime.create()
        code = asyncio.run(fixture_child(runtime, command))
    except (KeyboardInterrupt, FixtureError, OSError, ValueError, subprocess.SubprocessError):
        runtime.record.update(status="failed", reason="fixture setup, child, or interruption failed; private state retained")
        print("Native fixture failed; inspect retained private fixture state without exporting credentials.", file=sys.stderr)
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        if runtime.private.exists() and not runtime.stop():
            code = 1
        signal.signal(signal.SIGTERM, previous)
    return code


try:
    raise SystemExit(main())
except (FixtureError, ValueError, OSError, KeyError, subprocess.SubprocessError):
    # Never stringify exceptions that could contain a connection URL or command.
    print("Native fixture validation failed; no existing state is reused.", file=sys.stderr)
    raise SystemExit(1)
PY
