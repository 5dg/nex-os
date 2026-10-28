"""Dedicated packaging identity, archive integrity and real process shutdown."""
import copy
import gzip
import hashlib
import importlib.util
import io
import inspect
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from types import SimpleNamespace

SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import canonical_image as packaging
spec = importlib.util.spec_from_file_location('canonical_builder', SCRIPTS / 'canonical-build.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def container_fixture():
    expected = {'container_id': 'owned-id', 'labels': {'owner': 'nonce'}, 'volume': 'owned-cache',
                'environment': {'HTTP_PROXY': 'private-proxy-value'}}
    actual = {'Id': 'owned-id', 'Image': packaging.IMAGE_ID, 'State': {'Running': True},
              'Config': {'Labels': expected['labels'].copy(), 'Entrypoint': ['/usr/bin/buildkitd-entrypoint'],
                         'Cmd': ['--config', '/etc/buildkit/buildkitd.toml'], 'Env': ['HTTP_PROXY=private-proxy-value']},
              'HostConfig': {'Privileged': True, 'NetworkMode': 'bridge', 'PidMode': '', 'IpcMode': 'private',
                             'Memory': 2 * packaging.GIB, 'NanoCpus': 2_000_000_000},
              'Mounts': [{'Type': 'volume', 'Name': 'owned-cache', 'Destination': '/var/lib/buildkit'}]}
    return expected, actual


class CanonicalImageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def archive(self, corrupt=False, tags=None, duplicate=False):
        inner = io.BytesIO()
        with tarfile.open(fileobj=inner, mode='w:') as archive:
            member = tarfile.TarInfo('usr/lib/preserved.so'); member.size = 7; member.mode = 0o640
            member.pax_headers = {'SCHILY.xattr.security.capability': 'preserved'}
            archive.addfile(member, io.BytesIO(b'payload'))
        layer = inner.getvalue()
        layer_id = hashlib.sha256(layer).hexdigest()
        config = json.dumps({'architecture': 'amd64', 'os': 'linux', 'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + ('0' * 64 if corrupt else layer_id)]}}).encode()
        config_id = hashlib.sha256(config).hexdigest()
        compressed = gzip.compress(layer, mtime=0)
        manifest = json.dumps([{'Config': 'config.json', 'RepoTags': tags, 'Layers': ['layer.tar.gz']}]).encode()
        path = self.root / 'export.tar'
        with tarfile.open(path, 'w:') as archive:
            for name, data in [('config.json', config), ('layer.tar.gz', compressed), ('manifest.json', manifest)]:
                member = tarfile.TarInfo(name); member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            if duplicate:
                archive.addfile(member, io.BytesIO(manifest))
        return path, 'sha256:' + config_id, 'sha256:' + layer_id

    def test_actual_compressed_layer_bytes_bound_to_loaded_identity(self):
        path, config_id, layer_id = self.archive()
        result = packaging.archive_identity(path)
        self.assertEqual(result['id'], config_id)
        self.assertEqual(result['layers'], [layer_id])

    def test_mismatched_diffid_rejected_before_load(self):
        path, _, _ = self.archive(corrupt=True)
        with self.assertRaisesRegex(ValueError, 'diffIDs'):
            packaging.archive_identity(path)

    def test_build_specific_tag_rejected(self):
        path, _, _ = self.archive(tags=['candidate:two'])
        with self.assertRaisesRegex(ValueError, 'untagged'):
            packaging.archive_identity(path)

    def test_duplicate_archive_member_rejected(self):
        path, _, _ = self.archive(duplicate=True)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            packaging.archive_identity(path)

    def test_symlink_export_rejected(self):
        path, _, _ = self.archive()
        link = self.root / 'link.tar'; link.symlink_to(path)
        with self.assertRaisesRegex(ValueError, 'regular direct'):
            packaging.archive_identity(link)

    def test_exact_container_scope_accepts_and_changed_ownership_rejects(self):
        expected, info = container_fixture()
        packaging.verify_container(info, expected)
        changes = [('Id', 'foreign'), ('Image', 'sha256:' + '0' * 64)]
        for key, value in changes:
            altered = copy.deepcopy(info); altered[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                packaging.verify_container(altered, expected)
        for key, value in [('NetworkMode', 'host'), ('Memory', 8 * packaging.GIB), ('Privileged', False)]:
            altered = copy.deepcopy(info); altered['HostConfig'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                packaging.verify_container(altered, expected)
        for key, value in [('Cmd', ['--allow-insecure-entitlement=network.host']), ('Env', ['HTTP_PROXY=changed'])]:
            altered = copy.deepcopy(info); altered['Config'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                packaging.verify_container(altered, expected)
        altered = copy.deepcopy(info); altered['Mounts'].append({'Type': 'bind', 'Source': '/var/run/docker.sock'})
        with self.assertRaises(ValueError): packaging.verify_container(altered, expected)

    def test_selected_proxy_values_remain_in_memory_and_endpoint_selection_is_exact(self):
        config = self.root / 'config.json'
        config.write_text(json.dumps({'auths': {'private': {'auth': 'never-retain-this'}}, 'proxies': {
            'default': {'httpProxy': 'http://default:8080'},
            'unix:///var/run/docker.sock': {'httpProxy': 'http://local:8080', 'httpsProxy': 'http://local:8080', 'noProxy': 'localhost,127.0.0.1'}}}))
        result = packaging.selected_proxies({'DOCKER_CONFIG': str(self.root)})
        self.assertEqual(result['HTTP_PROXY'], 'http://local:8080')
        self.assertEqual(result['NO_PROXY'], 'localhost,127.0.0.1')
        self.assertNotIn('never-retain-this', repr(result))

    def test_proxy_credentials_fail_without_echoing_value(self):
        with self.assertRaises(ValueError) as result:
            packaging.selected_proxies({'DOCKER_CONFIG': str(self.root), 'HTTP_PROXY': 'http://user:secret@proxy:80'})
        self.assertNotIn('secret', str(result.exception))

    def test_command_cancellation_kills_owned_descendants_holding_stdout(self):
        helper = self.root / 'hold-pipe.py'
        helper.write_text("import os,pathlib,subprocess,sys,time\nchild=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\npathlib.Path(sys.argv[1]).write_text(str(child.pid))\ntime.sleep(60)\n")
        packager = packaging.Packager.__new__(packaging.Packager)
        packager.env = os.environ.copy(); packager.record = {'commands': []}
        packager.sample = lambda: None; packager.write = lambda: None
        packager.deadline = time.monotonic() + 10
        start = time.monotonic()
        with self.assertRaisesRegex(ValueError, 'deadline'):
            packager.command('pipe-holder', [sys.executable, str(helper), str(self.root / 'grandchild.pid')], timeout=0.2)
        self.assertLess(time.monotonic() - start, 4)
        pid = int((self.root / 'grandchild.pid').read_text())
        status = Path('/proc') / str(pid) / 'stat'
        if status.exists():
            self.assertEqual(status.read_text().split()[2], 'Z')

    def test_parent_grace_exceeds_full_bounded_stop_path(self):
        grace = inspect.signature(builder.supervise_packager).parameters['grace'].default
        self.assertGreater(grace, 16 + 20 + 45 + 20 + 16 + 3)

    def test_second_build_cli_drift_rejected_before_backend_pull(self):
        executable = self.root / 'buildx-plugin'; executable.write_bytes(b'first reviewed binary'); executable.chmod(0o755)
        tool = {'version': 'v0.31.0', 'path': str(executable), 'sha256': hashlib.sha256(executable.read_bytes()).hexdigest(), 'version_output': 'buildx v0.31.0'}
        first = self.root / 'first.json'; first.write_text(json.dumps({'packaging_tool_identity': tool}))
        packager = packaging.Packager.__new__(packaging.Packager)
        packager.args = SimpleNamespace(build='two'); packager.parent = {}; packager.base = self.root
        packager.candidate = {'builds': {'one': {'path': 'first.json', 'sha256': hashlib.sha256(first.read_bytes()).hexdigest()}}}
        packager.record = {}; packager.initial_free = {'output': {'free': 12*packaging.GIB}, 'docker': {'free': 12*packaging.GIB}}
        packager.forecast = 4*packaging.GIB; packager.sample = lambda: None
        calls = []
        def docker(label, *args, **kwargs):
            calls.append(label)
            if label == 'docker-info': return json.dumps({'DockerRootDir': str(self.root), 'ServerVersion': '28.4', 'Driver': 'vfs', 'ClientInfo': {'Plugins': [{'Name': 'buildx', 'Version': 'v0.31.0', 'Path': str(executable)}]}}).encode()
            if label == 'buildx-version': return b'buildx v0.31.0'
            if label == 'pull-backend': raise RuntimeError('approved identity reached next admission')
            raise AssertionError(label)
        packager.docker = docker
        with self.assertRaisesRegex(RuntimeError, 'approved identity'):
            packager.execute()
        self.assertIn('pull-backend', calls)
        calls.clear(); executable.write_bytes(b'substituted plugin binary')
        with self.assertRaisesRegex(ValueError, 'CLI identity changed'):
            packager.execute()
        self.assertNotIn('pull-backend', calls)
        executable.write_bytes(b'first reviewed binary'); first.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'first-build binding changed'):
            packager.execute()

    def child_fixture(self, foreign=False):
        expected, info = container_fixture()
        if foreign:
            info['Config']['Labels'] = {'owner': 'foreign'}
        (self.root / 'container.json').write_text(json.dumps(info))
        stub = self.root / 'docker'
        stub.write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys
root=pathlib.Path(os.environ['STUB_ROOT']); args=sys.argv[1:]
if args[0].startswith('--host='): args=args[1:]
if args[0]=='inspect':
 info=json.loads((root/'container.json').read_text()); info['State']['Running']=not(root/'stopped').exists(); print(json.dumps([info]))
elif args[0]=='stop':
 assert args[-1]=='owned-id'; (root/'stopped').write_text(args[-1]); print(args[-1])
else: raise SystemExit('unexpected stub command')
''')
        stub.chmod(0o755)
        child = self.root / 'child.py'
        child.write_text(f'''import os,sys,time,signal,pathlib
sys.path.insert(0,{str(SCRIPTS)!r})
import canonical_image as module
root=pathlib.Path({str(self.root)!r})
obj=module.Packager.__new__(module.Packager)
obj.env=os.environ.copy(); obj.record={{'commands':[]}}; obj.container_id='owned-id'; obj.expected={expected!r}; obj.volume_created=True
obj.sample=lambda: (_ for _ in ()).throw(ValueError('simulated low disk'))
obj.write=lambda: (_ for _ in ()).throw(OSError('simulated full report filesystem'))
def work():
 (root/'ready').write_text('ready')
 while True: time.sleep(0.05)
obj.execute=work
signal.signal(signal.SIGTERM,module.interrupted)
obj.run()
''')
        env = os.environ.copy(); env['PATH'] = str(self.root) + os.pathsep + env['PATH']; env['STUB_ROOT'] = str(self.root)
        return child, env

    def test_real_timeout_stops_owned_daemon_despite_low_disk_and_report_failure(self):
        child, env = self.child_fixture()
        log = self.root / 'parent.log'
        with log.open('wb') as stream, self.assertRaises(subprocess.TimeoutExpired):
            builder.supervise_packager([sys.executable, str(child)], env, stream, timeout=1, grace=5)
        self.assertEqual((self.root / 'stopped').read_text(), 'owned-id')
        self.assertNotIn('private-proxy-value', log.read_text())

    def test_foreign_identity_is_never_stopped_on_timeout(self):
        child, env = self.child_fixture(foreign=True)
        with (self.root / 'parent.log').open('wb') as stream, self.assertRaises(subprocess.TimeoutExpired):
            builder.supervise_packager([sys.executable, str(child)], env, stream, timeout=1, grace=5)
        self.assertFalse((self.root / 'stopped').exists())
        self.assertIn('reconciliation failed', (self.root / 'parent.log').read_text())

    def test_term_after_error_cleanup_started_cannot_abort_owned_stop(self):
        child, env = self.child_fixture()
        child.write_text(child.read_text().replace('while True: time.sleep(0.05)', "raise ValueError('initial phase failure')"))
        stub = self.root / 'docker'
        stub.write_text(stub.read_text().replace('import json,os,pathlib,sys', 'import json,os,pathlib,sys,time').replace("assert args[-1]=='owned-id';", "assert args[-1]=='owned-id'; (root/'stop-started').write_text('ready'); time.sleep(0.5);"))
        with (self.root / 'child.log').open('wb') as output:
            proc = subprocess.Popen([sys.executable, str(child)], env=env, stdout=output, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 5
                while not (self.root / 'stop-started').exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue((self.root / 'stop-started').exists())
                proc.terminate(); proc.wait(timeout=5)
            finally:
                if proc.poll() is None: proc.kill(); proc.wait()
        self.assertEqual((self.root / 'stopped').read_text(), 'owned-id')
        self.assertIn('initial phase failure', (self.root / 'child.log').read_text())

    def test_actual_parent_sigterm_forwards_cleanup_to_child(self):
        child, env = self.child_fixture()
        parent = self.root / 'parent.py'
        parent.write_text(f'''import importlib.util,os,signal,sys
sys.path.insert(0,{str(SCRIPTS)!r})
spec=importlib.util.spec_from_file_location('builder',{str(SCRIPTS / 'canonical-build.py')!r}); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
signal.signal(signal.SIGTERM,module.interrupted)
with open({str(self.root / 'child.log')!r},'wb') as output:
 module.supervise_packager([sys.executable,{str(child)!r}],os.environ.copy(),output,timeout=20,grace=5)
''')
        with (self.root / 'parent.log').open('wb') as output:
            proc = subprocess.Popen([sys.executable, str(parent)], env=env, stdout=output, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 5
                while not (self.root / 'ready').exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue((self.root / 'ready').exists())
                proc.terminate(); proc.wait(timeout=8)
            finally:
                if proc.poll() is None: proc.kill(); proc.wait()
        self.assertEqual((self.root / 'stopped').read_text(), 'owned-id')
        self.assertNotIn('private-proxy-value', (self.root / 'child.log').read_text())


if __name__ == '__main__':
    unittest.main()
