import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect } from 'node:net';
import pg from 'pg';
import { createPostgresSessionStore } from '../lib/postgres-session-config.ts';

// Run only against an operator-created disposable TLS PostgreSQL fixture.
// Correct and wrong hosts must both reach the fixture, but only the correct
// hostname may appear in its server certificate's subject alternative names.
const enabled = process.env.NEX_SESSION_TLS_TEST_DISPOSABLE === 'yes';
const roleURL = process.env.NEX_SESSION_TLS_TEST_ROLE_URL;
const goodCA = process.env.NEX_SESSION_TLS_TEST_CA;
const badCA = process.env.NEX_SESSION_TLS_TEST_BAD_CA;
const wrongHost = process.env.NEX_SESSION_TLS_TEST_WRONG_HOST;

test('PostgreSQL session configuration verifies CA and exact server hostname', { skip: !enabled }, async t => {
  assert.ok(roleURL && goodCA && badCA && wrongHost, 'disposable TLS fixture inputs required');
  const url = new URL(roleURL);
  assert.equal(url.searchParams.get('sslmode'), 'verify-full');
  assert.notEqual(url.hostname, wrongHost);
  const dir = await mkdtemp(join(tmpdir(), 'nex-session-tls-test-'));
  const urlFile = join(dir, 'url'), keyFile = join(dir, 'key');
  const envKeys = ['NEX_SESSION_DB_URL_FILE', 'NEX_SESSION_ENCRYPTION_KEY_FILE', 'NEX_SESSION_DB_CA_FILE', 'NEX_SESSION_DB_HOST'];
  const previous = Object.fromEntries(envKeys.map(name => [name, process.env[name]]));
  const OriginalPool = pg.Pool;
  let createdPool;
  pg.Pool = class extends OriginalPool {
    constructor(config) { super(config); createdPool = this; }
  };
  t.after(async () => {
    pg.Pool = OriginalPool;
    for (const name of envKeys) {
      if (previous[name] === undefined) delete process.env[name];
      else process.env[name] = previous[name];
    }
    await rm(dir, { recursive: true, force: true });
  });
  await writeFile(urlFile, roleURL, { mode: 0o600 });
  await writeFile(keyFile, randomBytes(32), { mode: 0o600 });
  process.env.NEX_SESSION_DB_URL_FILE = urlFile;
  process.env.NEX_SESSION_ENCRYPTION_KEY_FILE = keyFile;
  process.env.NEX_SESSION_DB_CA_FILE = goodCA;
  process.env.NEX_SESSION_DB_HOST = url.hostname;
  async function check(allowed) {
    createdPool = undefined;
    const store = createPostgresSessionStore();
    assert.ok(createdPool, 'session config must construct a tracked pool');
    try {
      if (allowed) await store.readiness();
      else await assert.rejects(store.readiness(), /Session store unavailable/);
    } finally { await createdPool.end(); }
  }
  await t.test('trusted CA and matching hostname permit least-privilege readiness', async () => { await check(true); });
  await t.test('untrusted CA fails closed', async () => {
    process.env.NEX_SESSION_DB_CA_FILE = badCA;
    try { await check(false); } finally { process.env.NEX_SESSION_DB_CA_FILE = goodCA; }
  });
  await t.test('reachable hostname absent from certificate fails closed', async () => {
    const wrong = new URL(roleURL); wrong.hostname = wrongHost;
    await new Promise((resolve, reject) => {
      const socket = connect({ host: wrongHost, port: Number(wrong.port || 5432), timeout: 3000 });
      socket.once('connect', () => { socket.destroy(); resolve(); });
      socket.once('timeout', () => { socket.destroy(); reject(new Error('wrong-host TCP fixture unreachable')); });
      socket.once('error', reject);
    });
    await writeFile(urlFile, wrong.toString(), { mode: 0o600 });
    process.env.NEX_SESSION_DB_HOST = wrongHost;
    try { await check(false); } finally {
      await writeFile(urlFile, roleURL, { mode: 0o600 });
      process.env.NEX_SESSION_DB_HOST = url.hostname;
    }
  });
  await t.test('downgraded SSL and nonprivate key fail before connection', async () => {
    const downgraded = new URL(roleURL); downgraded.searchParams.set('sslmode', 'disable');
    await writeFile(urlFile, downgraded.toString(), { mode: 0o600 });
    assert.throws(() => createPostgresSessionStore(), /Session configuration invalid/);
    await writeFile(urlFile, roleURL, { mode: 0o600 });
    await chmod(keyFile, 0o644);
    assert.throws(() => createPostgresSessionStore(), /Session configuration invalid/);
  });
});
