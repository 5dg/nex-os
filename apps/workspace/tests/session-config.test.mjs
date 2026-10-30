import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, chmodSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPostgresSessionStore } from '../lib/postgres-session-config.ts';

const variables = ['NEX_SESSION_DB_URL_FILE', 'NEX_SESSION_DB_HOST', 'NEX_SESSION_DB_CA_FILE', 'NEX_SESSION_ENCRYPTION_KEY_FILE', 'NEX_SESSION_PREVIOUS_ENCRYPTION_KEY_FILE'];
test('postgres session configuration requires private files and verified exact database identity', t => {
  const dir = mkdtempSync(join(tmpdir(), 'nex-session-config-'));
  const previous = Object.fromEntries(variables.map(name => [name, process.env[name]]));
  t.after(() => { for (const name of variables) { if (previous[name] === undefined) delete process.env[name]; else process.env[name] = previous[name]; } rmSync(dir, { recursive: true, force: true }); });
  const url = join(dir, 'database'), key = join(dir, 'key');
  const good = 'postgresql://workspace:synthetic-secret@db.example.test:5432/nex?sslmode=verify-full';
  writeFileSync(url, good, { mode: 0o600 }); writeFileSync(key, Buffer.alloc(32, 0x5b), { mode: 0o600 });
  Object.assign(process.env, { NEX_SESSION_DB_URL_FILE: url, NEX_SESSION_DB_HOST: 'db.example.test', NEX_SESSION_DB_CA_FILE: '/etc/ssl/certs/ca-certificates.crt', NEX_SESSION_ENCRYPTION_KEY_FILE: key });
  delete process.env.NEX_SESSION_PREVIOUS_ENCRYPTION_KEY_FILE;
  assert.ok(createPostgresSessionStore());
  const oldKey = join(dir, 'previous-key');
  writeFileSync(oldKey, Buffer.alloc(32, 0x7a), { mode: 0o600 });
  process.env.NEX_SESSION_PREVIOUS_ENCRYPTION_KEY_FILE = oldKey;
  assert.ok(createPostgresSessionStore());
  for (const invalid of [Buffer.alloc(32), Buffer.alloc(31, 0x7a), Buffer.alloc(32, 0x5b)]) {
    writeFileSync(oldKey, invalid); assert.throws(() => createPostgresSessionStore(), /Session configuration invalid/);
  }
  writeFileSync(oldKey, Buffer.alloc(32, 0x7a)); chmodSync(oldKey, 0o644);
  assert.throws(() => createPostgresSessionStore(), /Session configuration invalid/);
  chmodSync(oldKey, 0o600); const oldLink = join(dir, 'previous-link'); symlinkSync(oldKey, oldLink);
  process.env.NEX_SESSION_PREVIOUS_ENCRYPTION_KEY_FILE = oldLink;
  assert.throws(() => createPostgresSessionStore(), /Session configuration invalid/);
  process.env.NEX_SESSION_PREVIOUS_ENCRYPTION_KEY_FILE = '';
  assert.throws(() => createPostgresSessionStore(), /Session configuration invalid/);
  delete process.env.NEX_SESSION_PREVIOUS_ENCRYPTION_KEY_FILE;
  for (const invalid of [good.replace('verify-full', 'disable'), good + '&sslmode=verify-full', good.replace('db.example.test', 'other.example.test'), good.replace('synthetic-secret@', '@'), good + '#fragment']) {
    writeFileSync(url, invalid); assert.throws(() => createPostgresSessionStore(), /Session configuration invalid/);
  }
  writeFileSync(url, good); chmodSync(key, 0o644);
  assert.throws(() => createPostgresSessionStore(), /Session configuration invalid/);
  chmodSync(key, 0o600); writeFileSync(key, Buffer.alloc(32));
  assert.throws(() => createPostgresSessionStore(), /Session configuration invalid/);
  writeFileSync(key, Buffer.alloc(31, 0x5b)); assert.throws(() => createPostgresSessionStore(), /Session configuration invalid/);
  writeFileSync(key, Buffer.alloc(32, 0x5b)); const link = join(dir, 'link'); symlinkSync(key, link); process.env.NEX_SESSION_ENCRYPTION_KEY_FILE = link;
  assert.throws(() => createPostgresSessionStore(), /Session configuration invalid/);
  process.env.NEX_SESSION_ENCRYPTION_KEY_FILE = key; process.env.NEX_SESSION_DB_CA_FILE = join(dir, 'missing-ca');
  assert.throws(() => createPostgresSessionStore(), /Session configuration invalid/);
});
