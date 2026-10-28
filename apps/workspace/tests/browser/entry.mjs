// Isolated synthetic browser tool. It never changes host trust or disables TLS
// verification. Chrome logs, cookies and NSS files remain on container tmpfs.
import { spawn, execFileSync } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { userInfo } from 'node:os';
import { once } from 'node:events';

const browserBinary = '/usr/lib/chromium/chromium';
const driverPath = '/driver/qualification-browser.mjs';
const metadataPath = '/fixture/browser-build-info.json';
const homePath = '/home/node';
const nssPath = `${homePath}/.pki/nssdb`;
const chromiumVersion = '156.0.8078.47-1~deb12u1';
const nssVersion = '2:3.87.1-1+deb12u4';
const baseDigest = 'sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df';

function command(file, args, limit = 1024 * 1024) {
  return execFileSync(file, args, { encoding: 'utf8', timeout: 15000, maxBuffer: limit, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}
async function sha256(path) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest('hex');
}
function packageVersions() {
  return command('dpkg-query', ['-W', '-f=${Package}\t${Version}\t${Architecture}\n']).split('\n').map(line => {
    const [name, version, architecture] = line.split('\t');
    return { name, version, architecture };
  });
}
async function buildInventory() {
  if (process.getuid() !== 0) throw new Error('build inventory requires image construction');
  const packages = packageVersions();
  for (const name of ['chromium', 'chromium-common', 'chromium-sandbox']) {
    if (packages.find(p => p.name === name)?.version !== chromiumVersion) throw new Error('Chromium version differs from fixture pin');
  }
  for (const name of ['libnss3', 'libnss3-tools']) {
    if (packages.find(p => p.name === name)?.version !== nssVersion) throw new Error('NSS version differs from fixture pin');
  }
  const playwright = JSON.parse(await readFile('/fixture/node_modules/playwright-core/package.json', 'utf8'));
  if (playwright.version !== '1.64.1' || process.version !== 'v24.19.0') throw new Error('Node/Playwright differs from fixture pin');
  const info = {
    schema_version: 1, scope: 'synthetic browser tooling only', node_base_digest: baseDigest,
    node_version: process.version, playwright_version: playwright.version,
    chromium_version: command('/usr/bin/chromium', ['--version']),
    chromium_binary_sha256: await sha256(browserBinary), certutil_sha256: await sha256('/usr/bin/certutil'),
    packages, transitive_package_versions_are_recorded_not_fully_pinned: true,
  };
  await writeFile(metadataPath, JSON.stringify(info, null, 2) + '\n', { mode: 0o444 });
}
function loopbackDebuggingOnly() {
  return Promise.all(['/proc/net/tcp', '/proc/net/tcp6'].map(path => readFile(path, 'utf8'))).then(tables => {
    let found = false;
    for (const table of tables) for (const line of table.split('\n').slice(1)) {
      const fields = line.trim().split(/\s+/);
      if (fields[3] !== '0A') continue;
      const [address, port] = (fields[1] || '').split(':');
      if (port !== '2406') continue; // TCP port 9222.
      if (!['0100007F', '00000000000000000000000001000000'].includes(address)) throw new Error('browser debugging is not loopback-only');
      found = true;
    }
    if (!found) throw new Error('loopback browser debugger unavailable');
  });
}
function alive(child) { return child && child.exitCode === null && child.signalCode === null; }
async function stop(child) {
  if (!alive(child)) return;
  const finished = once(child, 'exit').catch(() => {});
  child.kill('SIGTERM');
  await Promise.race([finished, new Promise(resolve => setTimeout(resolve, 2000))]);
  if (alive(child)) child.kill('SIGKILL');
}
async function run() {
  if (process.env.NEX_PROFILE !== 'synthetic-qualification' || process.env.APP_ENV !== 'development') throw new Error('explicit synthetic fixture profile required');
  const user = userInfo();
  if (user.uid !== 1000 || user.homedir !== homePath || process.env.HOME !== homePath) throw new Error('native node user/home required');
  const mounts = await readFile('/proc/mounts', 'utf8');
  if (!mounts.split('\n').some(line => { const fields = line.split(' '); return fields[1] === homePath && fields[2] === 'tmpfs'; })) throw new Error('browser home requires private container tmpfs');
  const sandboxOption = process.env.NEX_BROWSER_FIXTURE_NO_SANDBOX;
  if (sandboxOption !== undefined && sandboxOption !== '0' && sandboxOption !== '1') throw new Error('invalid fixture sandbox option');
  const sandbox = sandboxOption !== '1';
  await mkdir(nssPath, { recursive: true, mode: 0o700 });
  if ((await readdir(nssPath)).length !== 0) throw new Error('browser trust must start empty');
  const caPath = '/trust/ca.crt';
  const ca = await readFile(caPath);
  if (ca.length > 128 * 1024 || ca.toString().includes('PRIVATE KEY') || (ca.toString().match(/-----BEGIN CERTIFICATE-----/g) || []).length !== 1) throw new Error('single public fixture CA required');
  const root = new X509Certificate(ca);
  if (!root.ca || Date.now() < Date.parse(root.validFrom) || Date.now() >= Date.parse(root.validTo)) throw new Error('current fixture CA required');
  command('/usr/bin/certutil', ['-N', '-d', `sql:${nssPath}`, '--empty-password']);
  command('/usr/bin/certutil', ['-A', '-d', `sql:${nssPath}`, '-n', 'Nex synthetic qualification root', '-t', 'C,,', '-i', caPath]);
  const inventory = JSON.parse(await readFile(metadataPath, 'utf8'));
  const actualHash = await sha256(browserBinary);
  if (actualHash !== inventory.chromium_binary_sha256) throw new Error('browser binary differs from recorded image input');
  await mkdir(`${homePath}/profile`, { mode: 0o700 });
  const chromiumArgs = [
    '--headless=new', '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=9222',
    `--user-data-dir=${homePath}/profile`, '--no-first-run', '--no-default-browser-check',
    '--disable-background-networking', '--disable-component-update', '--disable-extensions',
    '--disable-sync', '--disable-breakpad', '--disable-crash-reporter',
  ];
  if (!sandbox) chromiumArgs.push('--no-sandbox'); // Only E may enable after measured failure and lead approval.
  chromiumArgs.push('about:blank');
  const privateLog = createWriteStream(`${homePath}/chromium.log`, { flags: 'wx', mode: 0o600 });
  await once(privateLog, 'open');
  const chrome = spawn('/usr/bin/chromium', chromiumArgs, { stdio: ['ignore', privateLog, privateLog] });
  let driver;
  let interrupted = false;
  const interrupt = () => { interrupted = true; void stop(driver); void stop(chrome); };
  process.once('SIGTERM', interrupt); process.once('SIGINT', interrupt);
  try {
    let version;
    for (let attempt = 0; attempt < 60 && !interrupted; attempt++) {
      if (!alive(chrome)) break;
      try {
        const response = await fetch('http://127.0.0.1:9222/json/version', { signal: AbortSignal.timeout(500) });
        if (response.ok) { version = await response.json(); break; }
      } catch {}
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!version || interrupted) {
      const log = await readFile(`${homePath}/chromium.log`, 'utf8').catch(() => '');
      throw new Error(/No usable sandbox|Failed to move to new namespace|user namespace|Operation not permitted/i.test(log) ? 'BROWSER_SANDBOX_UNAVAILABLE' : 'BROWSER_STARTUP_UNAVAILABLE');
    }
    await loopbackDebuggingOnly();
    await writeFile('/results/browser-engine.json', JSON.stringify({ ...inventory, effective_sandbox: sandbox ? 'native' : 'disabled-fixture-only', cdp_browser: version.Browser, cdp_protocol_version: version['Protocol-Version'], public_ca_sha256: createHash('sha256').update(ca).digest('hex') }, null, 2) + '\n', { mode: 0o600 });
    driver = spawn(process.execPath, [driverPath, ...process.argv.slice(2)], { stdio: 'inherit', env: { ...process.env, NEX_PLAYWRIGHT_MODULE: '/fixture/node_modules/playwright-core/index.mjs', NEX_BROWSER_BINARY_SHA256: actualHash, NEX_BROWSER_EFFECTIVE_SANDBOX: sandbox ? 'native' : 'disabled-fixture-only' } });
    const [code] = await once(driver, 'exit');
    if (interrupted || code !== 0) throw new Error('BROWSER_ASSERTION_FAILED');
  } finally {
    await stop(driver); await stop(chrome); privateLog.end();
    process.off('SIGTERM', interrupt); process.off('SIGINT', interrupt);
  }
}
try {
  if (process.argv.length === 3 && process.argv[2] === '--build-inventory') await buildInventory();
  else await run();
} catch (error) {
  const known = ['BROWSER_SANDBOX_UNAVAILABLE', 'BROWSER_STARTUP_UNAVAILABLE', 'BROWSER_ASSERTION_FAILED'];
  console.error(known.includes(error?.message) ? error.message : 'BROWSER_FIXTURE_UNAVAILABLE');
  process.exitCode = 1;
}
