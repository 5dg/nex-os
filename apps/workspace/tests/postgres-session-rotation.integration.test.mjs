import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import pg from 'pg';
import { PostgresSessionStore } from '../lib/postgres-sessions.ts';

// Only the isolated runtime owner may provide these disposable DB credentials.
const enabled = process.env.NEX_SESSION_TEST_DISPOSABLE === 'yes';
const roleURL = process.env.NEX_SESSION_TEST_ROLE_URL;
const adminURL = process.env.NEX_SESSION_TEST_ADMIN_URL;
const actor = { issuer: 'https://issuer.test', subject: 'subject', user_id: 'user', tenant_id: 'tenant', delegation_id: 'delegation', permissions: ['document.read'] };
const hash = id => createHash('sha256').update(id, 'ascii').digest('hex');

test('PostgreSQL session key overlap, re-encryption and retirement', { skip: !enabled, timeout: 30000 }, async t => {
  assert.ok(roleURL && adminURL, 'both disposable DB URLs required');
  const pools = Array.from({ length: 4 }, () => new pg.Pool({ connectionString: roleURL, options: '-c search_path=pg_catalog', max: 3 }));
  const admin = new pg.Pool({ connectionString: adminURL, max: 2 });
  t.after(async () => { await Promise.all([...pools.map(pool => pool.end()), admin.end()]); });
  const oldKey = randomBytes(32), newKey = randomBytes(32);
  const legacy = new PostgresSessionStore(pools[0], oldKey);
  const prepared = new PostgresSessionStore(pools[1], oldKey, newKey);
  const rotated = new PostgresSessionStore(pools[2], newKey, oldKey);
  const retired = new PostgresSessionStore(pools[3], newKey);
  await Promise.all([legacy.readiness(), prepared.readiness(), rotated.readiness(), retired.readiness()]);
  const now = Math.floor(Date.now() / 1000);
  const assurance = { iss: actor.issuer, sub: actor.subject, iat: now, exp: now + 60, auth_time: now, acr: 'synthetic-mfa-marker', amr: ['pwd', 'otp'] };
  const old = await legacy.open(actor, 'synthetic-private-access', Date.now() + 60000, Date.now() + 60000, assurance);
  const untouched = await legacy.open(actor, 'synthetic-private-access', Date.now() + 60000, Date.now() + 60000, assurance);
  const fresh = await rotated.open(actor, 'synthetic-private-access', Date.now() + 60000, Date.now() + 60000, assurance);
  assert.deepEqual((await rotated.get(old.id)).assurance, assurance);
  assert.deepEqual((await prepared.get(fresh.id)).assurance, assurance);
  await assert.rejects(legacy.get(fresh.id), /unavailable/);
  await assert.rejects(retired.get(untouched.id), /unavailable/);
  const record = await admin.query("SELECT sealed FROM nex_workspace_auth.workspace_session_state WHERE kind='session' AND handle_hash=$1", [hash(old.id)]);
  assert.equal(record.rowCount, 1);
  for (const marker of ['synthetic-private-access', 'synthetic-mfa-marker', 'auth_time']) assert.equal(record.rows[0].sealed.includes(Buffer.from(marker)), false);
  await rotated.get(old.id, true); // Touch rewrites under new current key.
  assert.deepEqual((await retired.get(old.id)).assurance, assurance);
  await prepared.get(fresh.id, true); // Older replica writes old current key.
  assert.ok(await rotated.get(fresh.id));
  await assert.rejects(retired.get(fresh.id), /unavailable/);
  await rotated.get(fresh.id, true);
  assert.ok(await retired.get(fresh.id));
  const oldLogin = await legacy.begin('state', 'nonce', 'verifier');
  assert.equal((await rotated.consume(oldLogin.id, 'state')).verifier, 'verifier');
  await assert.rejects(prepared.consume(oldLogin.id, 'state'), /denied/);
  const newLogin = await rotated.begin('state', 'nonce', 'verifier');
  assert.equal((await prepared.consume(newLogin.id, 'state')).verifier, 'verifier');
  await admin.query("UPDATE nex_workspace_auth.workspace_session_state SET sealed=set_byte(sealed,13,get_byte(sealed,13) # 1) WHERE kind='session' AND handle_hash=$1", [hash(old.id)]);
  await assert.rejects(rotated.get(old.id, true), /unavailable/);
  await Promise.all([rotated.close(old.id), rotated.close(untouched.id), rotated.close(fresh.id)]);
  assert.equal(await prepared.get(old.id), undefined);
});
