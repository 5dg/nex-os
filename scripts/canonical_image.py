#!/usr/bin/env python3
"""Package one image with a fresh, owned, pinned BuildKit daemon and cache."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import shutil
import subprocess
import sys
import tarfile
import time

sys.dont_write_bytecode = True
from candidate import load
from image_archive import inspect as inspect_archive
from image_record import payload
from resource_admission import image_forecast
from source_record import atomic_json, sha256

GIB = 1024 ** 3
RESERVE = 2 * GIB
IMAGE = 'moby/buildkit:v0.34.1@sha256:b651bf250c2805569f1db385ad1ea8fb73737dfc851de305f274ca02690fa93f'
IMAGE_ID = 'sha256:2a2c53740b68d6a814cfed5af9f6d9a8eaec67a8546058c226a8251ad4680450'
FRONTEND = 'docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e'
CONFIG = '''debug = false
insecure-entitlements = []
[cdi]
  disabled = true
[worker.oci]
  enabled = true
  snapshotter = "native"
  max-parallelism = 1
  networkMode = "bridge"
  gc = true
[worker.containerd]
  enabled = false
[registry."docker.io"]
  ca = ["/etc/buildkit/public-ca.crt"]
'''
ROLES = {'control': 'deploy/qualification/Dockerfile.control.runtime',
         'guard': 'deploy/local/Dockerfile.guard',
         'fixtures': 'deploy/qualification/Dockerfile.fixtures.runtime',
         'workspace': 'deploy/qualification/Dockerfile.workspace.runtime',
         'postgres': 'deploy/qualification/Dockerfile.postgres.runtime'}


def archive_identity(path, *, allow_repo_tags=False):
    """Verify actual exported config and every uncompressed layer before load."""
    if path.is_symlink() or not path.is_file():
        raise ValueError('regular direct export archive required')
    with tarfile.open(path, 'r:') as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        if len(set(names)) != len(names):
            raise ValueError('duplicate export archive member')
        manifest_member = archive.getmember('manifest.json')
        if not manifest_member.isfile() or manifest_member.size > 1024 ** 2:
            raise ValueError('bounded regular export manifest required')
        manifest = json.load(archive.extractfile(manifest_member))
        if not isinstance(manifest, list) or len(manifest) != 1 or not isinstance(manifest[0], dict):
            raise ValueError('one exported image required')
        manifest = manifest[0]
        if manifest.get('RepoTags') and not allow_repo_tags:
            raise ValueError('canonical exporter archive must be untagged')
        member = archive.getmember(manifest['Config'])
        if not member.isfile() or member.size > 16 * 1024 ** 2:
            raise ValueError('bounded regular image config required')
        raw_config = archive.extractfile(member).read()
        config = json.loads(raw_config)
        layers = manifest.get('Layers')
        if not isinstance(layers, list):
            raise ValueError('export layers required')
        actual = []
        for name in layers:
            member = archive.getmember(name)
            if not member.isfile():
                raise ValueError('regular exported layer required')
            with archive.extractfile(member) as stream:
                compressed = stream.read(2) == b'\x1f\x8b'
            with archive.extractfile(member) as stream:
                if compressed:
                    with gzip.GzipFile(fileobj=stream) as expanded:
                        digest = hashlib.file_digest(expanded, 'sha256').hexdigest()
                else:
                    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            actual.append('sha256:' + digest)
        if config.get('rootfs') != {'type': 'layers', 'diff_ids': actual}:
            raise ValueError('exported config diffIDs do not match actual layer bytes')
        image_id = 'sha256:' + hashlib.sha256(raw_config).hexdigest()
        inspect_archive(path, image_id)
        return {'id': image_id, 'layers': actual,
                'raw_archive_sha256': sha256(path)}


def selected_proxies(env):
    """Select only Docker's local-daemon proxy settings; never expose auth config."""
    directory = Path(env.get('DOCKER_CONFIG', str(Path.home() / '.docker')))
    path = directory / 'config.json'
    config = json.loads(path.read_text()) if path.exists() else {}
    choices = config.get('proxies', {})
    selected = choices.get('unix:///var/run/docker.sock', choices.get('default'))
    mapping = {'httpProxy': 'HTTP_PROXY', 'httpsProxy': 'HTTPS_PROXY', 'noProxy': 'NO_PROXY'}
    if selected is None:
        selected = {key: env.get(name, env.get(name.lower(), '')) for key, name in mapping.items()}
    if not isinstance(selected, dict) or set(selected) - {*mapping, 'ftpProxy', 'allProxy'} or selected.get('ftpProxy') or selected.get('allProxy'):
        raise ValueError('unsupported local Docker proxy configuration')
    result = {}
    for key, name in mapping.items():
        value = selected.get(key, '')
        if not isinstance(value, str) or len(value) > 4096 or any(char in value for char in ('\n', '\r', '@')):
            raise ValueError('proxy must be a bounded public endpoint without credentials')
        if value and key != 'noProxy' and not re.fullmatch(r'https?://[^/\s]+/?', value):
            raise ValueError('HTTP(S) proxy endpoint required')
        result[name] = result[name.lower()] = value
    return result


def verify_container(info, expected):
    if info['Id'] != expected['container_id'] or info['Image'] != IMAGE_ID or info['Config']['Labels'] != expected['labels']:
        raise ValueError('owned packaging container identity changed')
    host = info['HostConfig']
    if not host['Privileged'] or host['NetworkMode'] != 'bridge' or host['PidMode'] not in ('', 'private') or host['IpcMode'] not in ('', 'private'):
        raise ValueError('packaging container namespace/privilege mismatch')
    if host['Memory'] != 2 * GIB or host['NanoCpus'] != 2_000_000_000:
        raise ValueError('packaging container resource limits changed')
    mounts = info['Mounts']
    if len(mounts) != 1 or mounts[0]['Type'] != 'volume' or mounts[0]['Name'] != expected['volume'] or mounts[0]['Destination'] != '/var/lib/buildkit':
        raise ValueError('packaging container has unexpected mounts')
    if info['Config']['Entrypoint'] != ['/usr/bin/buildkitd-entrypoint'] or info['Config']['Cmd'] != ['--config', '/etc/buildkit/buildkitd.toml']:
        raise ValueError('unexpected packaging daemon entrypoint/flags')
    if dict(item.split('=', 1) for item in info['Config']['Env']) != expected['environment']:
        raise ValueError('unexpected packaging container environment')


def verify_worker(raw):
    """Assert the effective worker; its random ID is diagnostic, not tool identity."""
    workers = json.loads(raw)
    if not isinstance(workers, list) or len(workers) != 1 or not isinstance(workers[0], dict):
        raise ValueError('exactly one OCI native worker required')
    worker = workers[0]
    labels = worker.get('labels')
    if (not isinstance(worker.get('id'), str) or not worker['id'] or not isinstance(labels, dict)
            or labels.get('org.mobyproject.buildkit.worker.executor') != 'oci'
            or labels.get('org.mobyproject.buildkit.worker.snapshotter') != 'native'):
        raise ValueError('effective OCI native snapshotter required')
    return worker


class Packager:
    def __init__(self, args):
        self.args = args
        self.candidate, self.base, self.source = load(args.candidate)
        self.path = self.base / 'builds' / args.build
        self.manifest_path = self.path / 'manifest.json'
        parent = json.loads(self.manifest_path.read_text())
        if parent.get('status') != 'building' or parent.get('source') != self.candidate['source'] or parent.get('run_id') != self.candidate['run_id'] or parent.get('build_id') != args.build:
            raise ValueError('active source-bound canonical build required')
        settings = parent.get('resource_budget', {}).get('phase_settings')
        if not isinstance(settings, dict):
            raise ValueError('canonical parent phase settings required')
        budgets = settings.get('packaging_image_estimated_peak_additional', {})
        self.forecast = image_forecast(args.name, budgets)
        self.package = self.path / 'package'
        if self.package.is_symlink() or not self.package.is_dir():
            raise ValueError('owned regular package directory required')
        self.report_path = self.path / (args.name + '-packaging.json')
        if self.report_path.exists() or self.report_path.is_symlink():
            raise ValueError('packaging report already exists; preserve failed attempt')
        self.work = self.path / 'work' / ('packaging-' + args.name)
        self.work.mkdir(mode=0o700)
        self.exports = self.path / 'work' / 'image-exports'
        self.exports.mkdir(mode=0o700, exist_ok=True)
        self.raw = self.exports / (args.name + '.tar')
        self.archive = self.path / 'images' / (args.name + '.tar')
        self.archive.parent.mkdir(exist_ok=True)
        for path in (self.raw, self.archive):
            if path.exists() or path.is_symlink():
                raise ValueError('packaging output already exists')
        nonce = secrets.token_hex(8)
        name = f'nex-pkg-{self.candidate["run_id"]}-{args.build}-{args.name}-{nonce}'
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,180}', name):
            raise ValueError('bounded packaging owner name required')
        self.name, self.volume = name, name + '-state'
        self.labels = {'org.nex.packaging.owner': nonce, 'org.nex.source.inputs': self.candidate['source']['inputs']['sha256'],
                       'org.nex.run': self.candidate['run_id'], 'org.nex.build': args.build, 'org.nex.image': args.name}
        self.env = {key: value for key, value in os.environ.items() if key not in ('DOCKER_CONTEXT', 'DOCKER_HOST', 'DOCKER_TLS', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'BUILDX_BUILDER', 'BUILDKIT_HOST')}
        self.env['DOCKER_HOST'] = 'unix:///var/run/docker.sock'
        self.proxies = selected_proxies(self.env)
        self.env.update(self.proxies)
        self.record = {'schema_version': 1, 'kind': 'dedicated-pinned-buildkit-image-v1', 'source': self.candidate['source'],
                       'run_id': self.candidate['run_id'], 'build_id': args.build, 'image_role': args.name, 'status': 'preparing',
                       'owner': {'name': name, 'volume': self.volume, 'labels': self.labels},
                       'backend_image': IMAGE, 'backend_image_id': IMAGE_ID, 'frontend': FRONTEND,
                       'configured_snapshotter': 'native',
                       'config_sha256': hashlib.sha256(CONFIG.encode()).hexdigest(), 'public_ca_sha256': sha256(args.ca),
                       'endpoint': 'docker-container://' + name + '?context=default',
                       'resource_policy': {'additional_forecast_bytes': self.forecast, 'reserve_bytes': RESERVE, 'memory_bytes': 2 * GIB, 'cpus': 2, 'concurrent_images': 1},
                       'commands': [], 'samples': []}
        self.container_id = None
        self.volume_created = False
        self.expected = None
        self.docker_fs = None
        self.initial_free = None
        self.deadline = time.monotonic() + 1500
        self.parent = parent
        self.write()

    def write(self):
        atomic_json(self.report_path, self.record)

    def free(self):
        paths = {'output': self.path, 'docker': self.docker_fs, 'host': Path('/'), 'tmp': Path('/tmp')}
        return {key: {'device': path.stat().st_dev, 'free': shutil.disk_usage(path).free} for key, path in paths.items()}

    def sample(self):
        if self.docker_fs is None:
            return
        values = self.free()
        self.record['samples'].append({'time_ns': time.time_ns(), 'filesystems': values})
        if self.initial_free is None:
            self.initial_free = values
        if any(item['free'] < RESERVE for item in values.values()):
            raise ValueError('packaging 2 GiB reserve reached; stop owned daemon')
        if any(self.initial_free[key]['free'] - values[key]['free'] > self.forecast for key in ('output', 'docker')):
            raise ValueError('packaging reviewed additional disk forecast exceeded')

    def command(self, label, argv, cleanup=False, timeout=120, private_output=False):
        if not cleanup:
            self.sample()
        item = {'name': label, 'argv': argv, 'started_ns': time.time_ns()}
        self.record['commands'].append(item)
        if not cleanup:
            self.write()
        proc = subprocess.Popen(argv, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + timeout if cleanup else min(self.deadline, time.monotonic() + timeout)
        output = None
        output_attempted = False
        def retain_output():
            nonlocal output_attempted
            if output_attempted or output is None:
                return True
            output_attempted = True
            if private_output:
                item['private_output_sha256'] = hashlib.sha256(output).hexdigest()
                return True
            try:
                sys.stdout.buffer.write(output)
                sys.stdout.buffer.flush()
                return True
            except (OSError, ValueError):
                # Logging failure must never abort exact owned-daemon cleanup,
                # or replace the original timeout/resource/interruption error.
                item['output_retention_failed'] = True
                return False
        try:
            while True:
                try:
                    output, _ = proc.communicate(timeout=1)
                    break
                except subprocess.TimeoutExpired as partial:
                    output = partial.output  # cumulative prefix, never append it
                    if not cleanup:
                        self.sample()
                    if time.monotonic() > deadline:
                        raise ValueError('bounded packaging command deadline exceeded: ' + label)
            if not retain_output() and not cleanup:
                raise ValueError('packaging command output could not be retained: ' + label)
            item.update(exit_code=proc.returncode, ended_ns=time.time_ns())
            if not cleanup:
                self.sample()
                self.write()
            if proc.returncode:
                raise ValueError(f'packaging command {label} failed with exit {proc.returncode}')
            return output
        except BaseException:
            # Buildx can leave descendants holding stdout after its own exit.
            # Cancel only this newly created command session, with bounded pipe
            # draining, so exact daemon termination always gets its grace window.
            try: os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError: pass
            try:
                try:
                    output, _ = proc.communicate(timeout=10)
                except subprocess.TimeoutExpired as partial:
                    output = partial.output
                    try: os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    try: output, _ = proc.communicate(timeout=5)
                    except subprocess.TimeoutExpired as partial:
                        output = partial.output
                        if proc.stdout: proc.stdout.close()
                        item['client_pipe_reconciliation_required'] = True
                if proc.poll() is None:
                    proc.wait(timeout=1)
            finally:
                retain_output()
                item.update(exit_code=proc.returncode, ended_ns=time.time_ns())
            raise

    def docker(self, label, *args, **kwargs):
        return self.command(label, ['docker', '--host=unix:///var/run/docker.sock', *args], **kwargs)

    def inspect_owned(self, cleanup=False):
        info = json.loads(self.docker('inspect-owned', 'inspect', self.container_id, cleanup=cleanup, private_output=True, timeout=20 if cleanup else 120))[0]
        verify_container(info, self.expected)
        return info

    def stop_owned(self):
        # A TERM arriving after a disk/error failure must not interrupt the
        # already-running stop. The parent grants this bounded cleanup window.
        handlers = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGTERM, signal.SIGINT)}
        try:
            if self.container_id:
                # Bypass disk/record admission during termination, never identity.
                info = self.inspect_owned(cleanup=True)
                if info['State']['Running']:
                    self.docker('stop-owned', 'stop', '--time', '30', self.container_id, cleanup=True, timeout=45)
                if self.inspect_owned(cleanup=True)['State']['Running']:
                    raise ValueError('owned packaging daemon still running')
                self.record.setdefault('owner', {})['stopped'] = True
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)

    def clean_success(self):
        self.stop_owned()
        self.docker('remove-remote', 'buildx', 'rm', self.name, cleanup=True)
        self.inspect_owned(cleanup=True)
        self.docker('remove-owned-container', 'rm', self.container_id, cleanup=True)
        self.container_id = None
        info = json.loads(self.docker('inspect-owned-volume', 'volume', 'inspect', self.volume, cleanup=True))[0]
        if info['Labels'] != self.labels or info['Name'] != self.volume:
            raise ValueError('owned packaging cache labels changed')
        references = self.docker('cache-references', 'ps', '-aq', '--filter', 'volume=' + self.volume, cleanup=True)
        if references.strip():
            raise ValueError('owned cache has remaining references')
        self.docker('remove-owned-cache', 'volume', 'rm', self.volume, cleanup=True)
        self.volume_created = False
        self.record['owner']['cleanup'] = 'stopped-and-removed-exact-container-remote-and-unused-cache'

    def execute(self):
        info = json.loads(self.docker('docker-info', 'info', '--format', '{{json .}}', private_output=True))
        self.docker_fs = Path(info['DockerRootDir'])
        if not self.docker_fs.is_dir():
            raise ValueError('actual Docker filesystem must be measurable')
        self.sample()
        if min(self.initial_free[key]['free'] for key in ('output', 'docker')) < self.forecast + RESERVE:
            raise ValueError('packaging requires reviewed per-image forecast plus 2 GiB reserve')
        self.record['docker'] = {'version': info['ServerVersion'], 'driver': info['Driver'], 'data_root': str(self.docker_fs)}
        plugins = [plugin for plugin in info['ClientInfo']['Plugins'] if plugin['Name'] == 'buildx']
        if len(plugins) != 1:
            raise ValueError('one identified Buildx plugin required')
        plugin = plugins[0]
        executable = Path(plugin['Path']).resolve(strict=True)
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError('resolved executable Buildx plugin required')
        tool = {'version': plugin['Version'], 'path': str(executable), 'sha256': sha256(executable),
                'version_output': self.docker('buildx-version', 'buildx', 'version').decode().strip()}
        expected_tool = self.parent.get('packaging_tool_identity')
        if self.args.build == 'two':
            first_path = self.base / self.candidate['builds']['one']['path']
            if first_path.is_symlink() or sha256(first_path) != self.candidate['builds']['one']['sha256']:
                raise ValueError('completed first-build binding changed')
            first = json.loads(first_path.read_text())
            expected_tool = first.get('packaging_tool_identity')
            if not expected_tool:
                raise ValueError('first-build packaging tool identity missing')
        if expected_tool is not None and expected_tool != tool:
            raise ValueError('Buildx CLI identity changed between images/builds')
        self.record['tool_identity'] = tool
        self.docker('pull-backend', 'pull', IMAGE, timeout=600)
        image = json.loads(self.docker('inspect-backend-image', 'image', 'inspect', IMAGE, private_output=True))[0]
        if image['Id'] != IMAGE_ID or image['Config']['Entrypoint'] != ['/usr/bin/buildkitd-entrypoint']:
            raise ValueError('pinned official BuildKit image identity changed')
        for label, args in [('container-absence', ('ps', '-aq', '--filter', 'name=^/' + self.name + '$')),
                            ('volume-absence', ('volume', 'ls', '-q', '--filter', 'name=^' + self.volume + '$'))]:
            if self.docker(label, *args).strip():
                raise ValueError('owned packaging identity already exists')
        labels = [part for key, value in self.labels.items() for part in ('--label', key + '=' + value)]
        self.volume_created = True  # Conservative across post-command sampling/write failure.
        self.record['owner']['cache_creation_attempted'] = True
        self.docker('create-cache', 'volume', 'create', *labels, self.volume)
        environment = dict(item.split('=', 1) for item in image['Config']['Env'])
        environment.update(self.proxies)
        environment['SSL_CERT_FILE'] = '/etc/buildkit/public-ca.crt'
        declared = {**self.proxies, 'SSL_CERT_FILE': '/etc/buildkit/public-ca.crt'}
        self.env.update(declared)
        self.container_id = self.docker('create-owned-container', 'create', '--name', self.name, *labels,
            '--privileged', '--network', 'bridge', '--cpus', '2', '--memory', '2g',
            '--mount', f'type=volume,src={self.volume},dst=/var/lib/buildkit',
            *[part for key in declared for part in ('--env', key)],
            IMAGE, '--config', '/etc/buildkit/buildkitd.toml').decode().strip()
        self.expected = {'container_id': self.container_id, 'labels': {**(image['Config'].get('Labels') or {}), **self.labels}, 'volume': self.volume, 'environment': environment}
        self.record['owner']['container_id'] = self.container_id
        self.inspect_owned()
        public = self.work / 'public' / 'buildkit'
        public.mkdir(parents=True, mode=0o755)
        (public / 'buildkitd.toml').write_text(CONFIG)
        shutil.copyfile(self.args.ca, public / 'public-ca.crt')
        self.docker('copy-public-config', 'cp', str(public), self.name + ':/etc/')
        for filename in ('buildkitd.toml', 'public-ca.crt'):
            copied = self.work / ('copied-' + filename)
            self.docker('read-public-' + filename, 'cp', self.name + ':/etc/buildkit/' + filename, str(copied))
            if sha256(copied) != sha256(public / filename):
                raise ValueError('public config/CA copy changed before daemon start')
        self.inspect_owned()
        self.docker('start-owned', 'start', self.container_id)
        args = self.docker('actual-daemon-args', 'exec', self.container_id, 'cat', '/proc/1/cmdline').decode().rstrip('\0').split('\0')
        if not args or Path(args[0]).name != 'buildkitd' or args[1:] != ['--config', '/etc/buildkit/buildkitd.toml']:
            raise ValueError('actual daemon arguments differ from reviewed zero-entitlement configuration')
        self.inspect_owned()
        self.docker('create-remote', 'buildx', 'create', '--name', self.name, '--driver', 'remote', self.record['endpoint'])
        self.docker('bootstrap-remote', 'buildx', 'inspect', '--bootstrap', self.name, timeout=180)
        self.record['worker_diagnostics'] = verify_worker(self.docker('effective-worker', 'exec', self.container_id,
            'buildctl', 'debug', 'workers', '--format', '{{json .}}'))
        self.write()
        self.record['status'] = 'packaging'
        dockerfile = ROLES[self.args.name]
        self.docker('export-image', 'buildx', 'build', '--builder', self.name, '--no-cache', '--platform', 'linux/amd64',
            '--provenance=false', '--sbom=false', '--secret', 'id=proxy_ca,src=' + str(self.args.ca.resolve()),
            '--build-arg', 'BUILDKIT_SYNTAX=' + FRONTEND, '--build-arg', 'SOURCE_DATE_EPOCH=' + str(self.candidate['source']['source_epoch']),
            *[part for key in self.proxies for part in ('--build-arg', key)],
            '--label', 'org.nex.qualification.builder=canonical-container',
            '--label', 'org.opencontainers.image.revision=' + self.candidate['source']['revision'],
            '--label', 'org.nex.source.inputs=' + self.candidate['source']['inputs']['sha256'],
            '--output', 'type=docker,dest=' + str(self.raw) + ',rewrite-timestamp=true,oci-mediatypes=false,compression=gzip',
            '-f', str(self.source / dockerfile), str(self.package), timeout=1200)
        exported = archive_identity(self.raw)
        self.record['exported'] = exported
        self.write()
        self.docker('load-export', 'image', 'load', '--input', str(self.raw), timeout=300)
        loaded = json.loads(self.docker('inspect-loaded', 'image', 'inspect', exported['id'], private_output=True))[0]
        if loaded['Id'] != exported['id'] or loaded['RootFS']['Layers'] != exported['layers']:
            raise ValueError('loaded image differs from actual export config/layer bytes')
        preparation = self.path / (self.args.name + '-archive-preparation.json')
        self.command('prepare-archive', [sys.executable, str(self.source / 'scripts/image_archive.py'),
            '--source', str(self.raw), '--output', str(self.archive), '--report', str(preparation),
            '--epoch', str(self.candidate['source']['source_epoch']), '--image-id', exported['id']], timeout=300)
        tag = f'nex-alpha04-{self.candidate["run_id"]}-{self.args.name}:{self.args.build}'
        self.docker('tag-loaded-identity', 'image', 'tag', exported['id'], tag)
        details = {'id': exported['id'], 'repo_digests': loaded['RepoDigests'], 'layers': exported['layers'], 'tag': tag,
            'dockerfile': dockerfile, 'dockerfile_sha256': sha256(self.source / dockerfile),
            'archive': {'path': str(self.archive.relative_to(self.path)), 'sha256': sha256(self.archive)},
            'archive_preparation': {'path': preparation.name, 'sha256': sha256(preparation)},
            'payload': payload(self.archive, self.path / (self.args.name + '-payload.json')),
            'archive_origin': 'pinned-buildkit-direct-docker-export'}
        self.record['image'] = details
        self.clean_success()
        if sha256(executable) != tool['sha256'] or sha256(self.args.ca) != self.record['public_ca_sha256']:
            raise ValueError('packaging CLI or public CA changed during phase')
        self.sample()
        self.record['status'] = 'packaged'
        self.write()

    def run(self):
        try:
            self.execute()
        except BaseException as error:
            self.record.update(status='failed', error=str(error))
            try:
                self.stop_owned()
            except BaseException as stop_error:
                self.record['stop_error'] = str(stop_error)
                print('Owned packaging stop/reconciliation failed: ' + str(stop_error), file=sys.stderr)
            self.record['owned_cache_retained'] = self.volume_created
            try:
                self.write()
            except OSError as record_error:
                print('Cannot write packaging failure record: ' + str(record_error), file=sys.stderr)
            raise


def interrupted(signum, _frame):
    signal.signal(signum, signal.SIG_IGN)
    # selectors.select() catches InterruptedError and would swallow TERM while
    # communicate() polls pipes. Use an exception that reaches owned cleanup.
    raise ValueError('packaging interrupted by signal ' + str(signum))


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--build', choices=('one', 'two'), required=True)
    parser.add_argument('--name', choices=tuple(ROLES), required=True)
    parser.add_argument('--ca', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.ca.is_symlink() or not args.ca.is_file():
            raise ValueError('regular public CA file required')
        Packager(args).run()
    except (OSError, ValueError, KeyError, tarfile.TarError, json.JSONDecodeError) as error:
        parser.exit(1, str(error) + '\n')
