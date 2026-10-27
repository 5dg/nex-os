#!/usr/bin/env python3
"""Loopback-only byte relays for Docker internal-network qualification fixtures.

Some Docker versions omit published ports on internal-only networks. This local
test transport preserves those networks and leaves TLS verification end to end.
Destinations are fixed services inspected from the qualification project only.
"""
import argparse
import asyncio
import fcntl
import json
import os
import pathlib
import signal
import socket
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PROJECT = os.environ.get('NEX_QUAL_PROJECT', 'nex-qualification')
if PROJECT not in ('nex-qualification', 'nex-qualification-restore'):
    raise SystemExit('Only the primary and isolated restore qualification projects are allowed')
ENDPOINTS = {
    'postgres': (55432, 5432), 'guard': (55051, 50051),
    'control': (18080, 8080), 'opa-edge': (18181, 8181),
    'workspace': (9443, 9443), 'issuer': (9444, 9444),
}

def docker(*arguments):
    env = {k: v for k, v in os.environ.items() if k not in (
        'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH')}
    return subprocess.check_output(['docker', '--host=unix:///var/run/docker.sock', *arguments],
                                   env=env, text=True, stderr=subprocess.DEVNULL)

def endpoints():
    result = []
    for service, (public_port, private_port) in ENDPOINTS.items():
        try:
            info = json.loads(docker('inspect', f'{PROJECT}-{service}-1'))[0]
        except (subprocess.CalledProcessError, IndexError):
            continue  # The initial core-only bootstrap does not start the workspace.
        labels = info['Config'].get('Labels', {})
        if (labels.get('com.docker.compose.project') != PROJECT
                or labels.get('com.docker.compose.service') != service):
            raise SystemExit('Qualification container ownership mismatch')
        if not info['State']['Running']:
            continue
        # Native published bindings need no relay. Never take an existing listener.
        if info['NetworkSettings']['Ports'].get(f'{private_port}/tcp'):
            continue
        addresses = [(name, value['IPAddress']) for name, value in
                     info['NetworkSettings']['Networks'].items() if value.get('IPAddress')]
        if not addresses:
            continue
        name, address = sorted(addresses)[0]
        network = json.loads(docker('network', 'inspect', name))[0]
        if not network['Internal'] or network.get('Labels', {}).get('com.docker.compose.project') != PROJECT:
            raise SystemExit('Relay destination must belong to an internal qualification network')
        result.append({'service': service, 'listen': public_port, 'address': address, 'port': private_port})
    return result

def owned(pid, state):
    try:
        args = pathlib.Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
        return (str(pathlib.Path(__file__).resolve()).encode() in args
                and b'_serve' in args and str(state).encode() in args)
    except (FileNotFoundError, PermissionError):
        return False

def stop(state):
    pidfile = state / 'relay.pid'
    if pidfile.exists():
        pid = int(pidfile.read_text())
        if owned(pid, state):
            os.kill(pid, signal.SIGTERM)
            # Wait for the owned server to release its sockets; no unrelated PID kill.
            import time
            for _ in range(100):
                if not owned(pid, state):
                    break
                time.sleep(0.02)
        pidfile.unlink(missing_ok=True)

async def serve(state):
    config = json.loads((state / 'relay-endpoints.json').read_text())
    async def connect(reader, writer, item):
        peer = None
        try:
            remote, peer = await asyncio.wait_for(asyncio.open_connection(item['address'], item['port']), 3)
            async def copy(source, target):
                while data := await source.read(65536):
                    target.write(data)
                    await target.drain()
            tasks = [asyncio.create_task(copy(reader, peer)), asyncio.create_task(copy(remote, writer))]
            _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        except (OSError, asyncio.TimeoutError):
            pass  # Never log transported bytes, credentials, or request URLs.
        finally:
            for stream in (writer, peer):
                if stream:
                    stream.close()
    servers = []
    for item in config:
        servers.append(await asyncio.start_server(lambda r, w, i=item: connect(r, w, i), '127.0.0.1', item['listen']))
    (state / 'relay.ready').touch(mode=0o600)
    stopped = asyncio.Event()
    asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, stopped.set)
    await stopped.wait()
    for server in servers:
        server.close()
    await asyncio.gather(*(server.wait_closed() for server in servers))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('start', 'stop', 'status', '_serve'))
    parser.add_argument('--state', default=os.environ.get('NEX_QUAL_STATE_DIR', str(ROOT / '.local/qualification')))
    args = parser.parse_args()
    state = pathlib.Path(args.state).resolve()
    marker = state / 'synthetic-qualification.state'
    if not marker.is_file() or marker.read_text() != 'synthetic-qualification\n':
        raise SystemExit('An initialized qualification state directory is required')
    if args.action == '_serve':
        asyncio.run(serve(state))
        return
    if args.action == 'status':
        pidfile = state / 'relay.pid'
        running = pidfile.exists() and owned(int(pidfile.read_text()), state)
        print('Qualification loopback relay running' if running else 'Qualification loopback relay stopped')
        return
    lock = (state / 'relay.lock').open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    stop(state)
    if args.action == 'stop':
        return
    config = endpoints()
    # Fail before spawning if any unrelated process already owns a requested port.
    for item in config:
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(('127.0.0.1', item['listen']))
    (state / 'relay.ready').unlink(missing_ok=True)
    (state / 'relay-endpoints.json').write_text(json.dumps(config, indent=2) + '\n')
    with (state / 'relay.log').open('ab') as log:
        process = subprocess.Popen([sys.executable, str(pathlib.Path(__file__).resolve()), '_serve', '--state', str(state)],
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
    (state / 'relay.pid').write_text(str(process.pid))
    import time
    for _ in range(100):
        if (state / 'relay.ready').exists():
            print(f'Qualification loopback relays ready ({len(config)} fixed endpoints)')
            return
        if process.poll() is not None:
            raise SystemExit('Qualification relay failed; inspect private relay.log')
        time.sleep(0.02)
    stop(state)
    raise SystemExit('Qualification relay startup timed out')

if __name__ == '__main__':
    main()
