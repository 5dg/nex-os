import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import pg from 'pg';
import { PostgresSessionStore } from '../lib/postgres-sessions.ts';

// The runtime operator provides a disposable database, an admin connection and
// a separate login with only schema USAGE and table SELECT/INSERT/UPDATE/DELETE.
// This test temporarily modifies grants on that login. Never point it at a real database.
const adminURL = process.env.NEX_SESSION_TEST_ADMIN_URL;
const roleURL = process.env.NEX_SESSION_TEST_ROLE_URL;
const enabled = process.env.NEX_SESSION_TEST_DISPOSABLE === 'yes';
const actor = { issuer: 'https://issuer.test', subject: 'subject', user_id: 'user', tenant_id: 'tenant', delegation_id: 'delegation', permissions: ['document.read'] };
const hash = id => createHash('sha256').update(id, 'ascii').digest('hex');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

test('encrypted PostgreSQL sessions across independent instances', { skip: !enabled }, async t => {
  assert.ok(adminURL && roleURL, 'both disposable database URLs are required');
  const admin = new pg.Pool({ connectionString: adminURL, max: 3 });
  const poolA = new pg.Pool({ connectionString: roleURL, options: '-c search_path=pg_catalog', max: 4 });
  const poolB = new pg.Pool({ connectionString: roleURL, options: '-c search_path=pg_catalog', application_name: 'nex_session_replica_b_test', max: 4 });
  t.after(async () => { await Promise.all([poolA.end(), poolB.end(), admin.end()]); });
  const key = randomBytes(32), a = new PostgresSessionStore(poolA, key), b = new PostgresSessionStore(poolB, key);
  const wrong = new PostgresSessionStore(poolB, randomBytes(32));
  const role = (await poolA.query('SELECT current_user AS name')).rows[0].name;
  assert.match(role, /^[a-z][a-z0-9_]{0,62}$/);
  const quotedRole = `"${role}"`;
  await a.readiness();
  await b.readiness();

  await t.test('login consumption is single use across replicas, even after wrong state', async () => {
    const login = await a.begin('state', 'nonce', 'verifier');
    const results = await Promise.allSettled([a.consume(login.id, 'state'), b.consume(login.id, 'state')]);
    assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
    assert.equal(results.filter(r => r.status === 'rejected').length, 1);
    const bad = await a.begin('state', 'nonce', 'verifier');
    await assert.rejects(b.consume(bad.id, 'wrong'), /denied/);
    await assert.rejects(a.consume(bad.id, 'state'), /denied/);
  });

  await t.test('session is encrypted, shared, authenticated and revocable', async () => {
    const session = await a.open(actor, 'private-access-token', Date.now() + 60_000, Date.now() + 60_000);
    const saved = await admin.query('SELECT handle_hash, sealed FROM nex_workspace_auth.workspace_session_state WHERE kind=$1 AND handle_hash=$2', ['session', hash(session.id)]);
    assert.equal(saved.rowCount, 1);
    assert.notEqual(saved.rows[0].handle_hash, session.id);
    assert.equal(saved.rows[0].sealed.includes(Buffer.from('private-access-token')), false);
    const touched = await b.get(session.id, true);
    assert.deepEqual(touched.actor, actor);
    assert.equal(touched.expires, session.expires);
    assert.ok(touched.idleExpires <= touched.expires);
    await assert.rejects(wrong.get(session.id, true), /unavailable/);
    assert.ok(await a.get(session.id));
    await admin.query("UPDATE nex_workspace_auth.workspace_session_state SET sealed=set_byte(sealed, 13, get_byte(sealed, 13) # 1) WHERE kind='session' AND handle_hash=$1", [hash(session.id)]);
    await assert.rejects(b.get(session.id, true), /unavailable/);
    await a.close(session.id);
    assert.equal(await b.get(session.id), undefined);
  });

  await t.test('waiting on a row lock cannot revive an expired session', async () => {
    const session = await a.open(actor, 'token', Date.now() + 1800, Date.now() + 1800);
    const client = await admin.connect();
    try {
      await client.query('BEGIN');
      await client.query("SELECT 1 FROM nex_workspace_auth.workspace_session_state WHERE kind='session' AND handle_hash=$1 FOR UPDATE", [hash(session.id)]);
      const pending = b.get(session.id, true);
      let waiting = false;
      for (let attempt = 0; attempt < 100 && !waiting; attempt++) {
        const state = await admin.query("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_stat_activity WHERE application_name='nex_session_replica_b_test' AND state='active' AND wait_event_type='Lock') AS waiting");
        waiting = state.rows[0].waiting;
        if (!waiting) await pause(10);
      }
      assert.equal(waiting, true, 'replica must be blocked on the held row lock');
      await pause(2100);
      await client.query('COMMIT');
      assert.equal(await pending, undefined);
      assert.equal(await a.get(session.id), undefined);
    } finally { await client.query('ROLLBACK').catch(() => {}); client.release(); await a.close(session.id); }
  });

  await t.test('logout racing a touch leaves no usable session', async () => {
    const session = await a.open(actor, 'token', Date.now() + 60_000, Date.now() + 60_000);
    await Promise.all([a.get(session.id, true), b.close(session.id)]);
    assert.equal(await a.get(session.id), undefined);
  });

  await t.test('unavailable database fails closed', async () => {
    const deadPool = new pg.Pool({ connectionString: roleURL, options: '-c search_path=pg_catalog' });
    const dead = new PostgresSessionStore(deadPool, key);
    await deadPool.end();
    await assert.rejects(dead.readiness(), /unavailable/);
    await assert.rejects(dead.begin('state', 'nonce', 'verifier'), /unavailable/);
    await assert.rejects(dead.get(randomBytes(32).toString('base64url'), true), /unavailable/);
    await assert.rejects(dead.close(randomBytes(32).toString('base64url')), /unavailable/);
  });

  await t.test('readiness rejects extra table and grant-option privileges', async () => {
    for (const privilege of ['TRUNCATE', 'REFERENCES', 'TRIGGER']) {
      try {
        await admin.query(`GRANT ${privilege} ON nex_workspace_auth.workspace_session_state TO ${quotedRole}`);
        await assert.rejects(a.readiness(), /unavailable/);
      } finally { await admin.query(`REVOKE ${privilege} ON nex_workspace_auth.workspace_session_state FROM ${quotedRole}`); }
      await a.readiness();
    }
    try {
      await admin.query(`GRANT INSERT ON nex_workspace_auth.workspace_session_state TO ${quotedRole} WITH GRANT OPTION`);
      await assert.rejects(a.readiness(), /unavailable/);
    } finally { await admin.query(`REVOKE GRANT OPTION FOR INSERT ON nex_workspace_auth.workspace_session_state FROM ${quotedRole}`); }
    try {
      await admin.query(`GRANT USAGE ON SCHEMA nex_workspace_auth TO ${quotedRole} WITH GRANT OPTION`);
      await assert.rejects(a.readiness(), /unavailable/);
    } finally { await admin.query(`REVOKE GRANT OPTION FOR USAGE ON SCHEMA nex_workspace_auth FROM ${quotedRole}`); }
    await a.readiness();
  });

  await t.test('readiness rejects schema creation, other-table columns, functions, sequences and membership', async () => {
    try {
      await admin.query(`GRANT CREATE ON SCHEMA public TO ${quotedRole}`);
      await assert.rejects(a.readiness(), /unavailable/);
    } finally { await admin.query(`REVOKE CREATE ON SCHEMA public FROM ${quotedRole}`); }
    try {
      await admin.query('CREATE TABLE public.nex_session_fixture_other (value text)');
      await admin.query(`GRANT SELECT (value) ON public.nex_session_fixture_other TO ${quotedRole}`);
      await assert.rejects(a.readiness(), /unavailable/);
    } finally { await admin.query('DROP TABLE IF EXISTS public.nex_session_fixture_other'); }
    try {
      await admin.query('CREATE FUNCTION public.nex_session_fixture_function() RETURNS integer LANGUAGE SQL AS $$ SELECT 1 $$');
      await admin.query('REVOKE ALL ON FUNCTION public.nex_session_fixture_function() FROM PUBLIC');
      await admin.query(`GRANT EXECUTE ON FUNCTION public.nex_session_fixture_function() TO ${quotedRole}`);
      await assert.rejects(a.readiness(), /unavailable/);
    } finally { await admin.query('DROP FUNCTION IF EXISTS public.nex_session_fixture_function()'); }
    try {
      await admin.query('CREATE SEQUENCE public.nex_session_fixture_sequence');
      await admin.query(`GRANT USAGE ON SEQUENCE public.nex_session_fixture_sequence TO ${quotedRole}`);
      await assert.rejects(a.readiness(), /unavailable/);
    } finally { await admin.query('DROP SEQUENCE IF EXISTS public.nex_session_fixture_sequence'); }
    try {
      await admin.query('CREATE ROLE nex_session_membership_probe NOLOGIN');
      await admin.query(`GRANT nex_session_membership_probe TO ${quotedRole}`);
      await assert.rejects(a.readiness(), /unavailable/);
    } finally {
      await admin.query(`REVOKE nex_session_membership_probe FROM ${quotedRole}`).catch(() => {});
      await admin.query('DROP ROLE IF EXISTS nex_session_membership_probe');
    }
    await a.readiness();
  });
});
