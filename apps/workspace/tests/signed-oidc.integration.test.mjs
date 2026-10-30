// Source-level synthetic acceptance: signed OIDC + real route handlers in two
// processes + disposable TLS PostgreSQL. This is not a browser or live IdP.
import 'reflect-metadata';
import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { fork } from 'node:child_process';
import { createHash, generateKeyPairSync, randomBytes, sign, verify, X509Certificate } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as x509 from '@peculiar/x509';
import pg from 'pg';

const enabled = process.env.NEX_SIGNED_OIDC_DISPOSABLE === 'yes';
const roleURL = process.env.NEX_SESSION_TLS_TEST_ROLE_URL;
const dbCAPath = process.env.NEX_SESSION_TLS_TEST_CA;
const adminURL = process.env.NEX_SESSION_TEST_ADMIN_URL;
const b64 = value => Buffer.from(value).toString('base64url');
const random = () => randomBytes(32).toString('base64url');
const fields = req => new Promise((resolve, reject) => { const chunks = []; let size = 0; req.on('data', x => { size += x.length; if (size > 8192) req.destroy(); else chunks.push(x); }); req.on('end', () => resolve(new URLSearchParams(Buffer.concat(chunks).toString()))); req.on('error', reject); });
const start = server => new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', () => resolve(server.address().port)); });
const request = (port, hostname, ca, path, options = {}) => new Promise((resolve, reject) => {
  const req = https.request({ host: '127.0.0.1', port, servername: hostname, ca, method: options.method || 'GET', path, headers: options.headers || {}, minVersion: 'TLSv1.3', timeout: 5000 }, res => {
    const parts = []; let size = 0; res.on('data', part => { size += part.length; if (size > 128 * 1024) res.destroy(); else parts.push(part); });
    res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(parts).toString() })); res.on('error', reject);
  }); req.on('timeout', () => req.destroy(new Error('synthetic request timeout'))); req.on('error', reject); if (options.body) req.write(options.body); req.end();
});
const cookie = (response, name) => {
  const value = (response.headers['set-cookie'] || []).find(entry => entry.startsWith(name + '='));
  assert.ok(value, `missing ${name} cookie`); return value.split(';', 1)[0];
};

test('signed synthetic OIDC MFA across independent shared-session replicas', { skip: !enabled, timeout: 60000 }, async t => {
  assert.ok(roleURL && dbCAPath && adminURL, 'disposable PostgreSQL fixture inputs required');
  const database = new URL(roleURL); assert.equal(database.searchParams.get('sslmode'), 'verify-full');
  const dir = mkdtempSync(join(tmpdir(), 'nex-signed-oidc-'));
  const put = (name, value) => { const path = join(dir, name); writeFileSync(path, value, { mode: 0o600 }); return path; };
  const children = [], servers = [];
  const admin = new pg.Pool({ connectionString: adminURL, max: 2 });
  t.after(async () => {
    for (const child of children) { child.kill('SIGTERM'); }
    for (const server of servers) await new Promise(resolve => server.close(resolve));
    await admin.end(); rmSync(dir, { recursive: true, force: true });
  });
  const keygen = () => crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const rootKeys = await keygen();
  const root = await x509.X509CertificateGenerator.createSelfSigned({ name: 'CN=synthetic-root', keys: rootKeys, notBefore: new Date(Date.now() - 60_000), notAfter: new Date(Date.now() + 3600_000), extensions: [new x509.BasicConstraintsExtension(true, 1, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true)] });
  async function identity(name, dns) {
    const keys = await keygen();
    const cert = await x509.X509CertificateGenerator.create({ subject: `CN=${name}`, issuer: root.subject, publicKey: keys.publicKey, signingKey: rootKeys.privateKey, notBefore: new Date(Date.now() - 60_000), notAfter: new Date(Date.now() + 3600_000), extensions: [new x509.BasicConstraintsExtension(false), new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: dns }, { type: 'url', value: `spiffe://nex.local/service/${name}` }]), new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.clientAuth, x509.ExtendedKeyUsage.serverAuth])] });
    const der = Buffer.from(await crypto.subtle.exportKey('pkcs8', keys.privateKey));
    return { cert: cert.toString('pem'), key: `-----BEGIN PRIVATE KEY-----\n${der.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----` };
  }
  const [workspace, issuerTLS, controlTLS] = await Promise.all([identity('workspace', 'workspace.nex.test'), identity('oidc', 'issuer.nex.test'), identity('control', 'control')]);
  const ca = root.toString('pem'), caFile = put('ca.pem', ca), certFile = put('workspace.pem', workspace.cert), keyFile = put('workspace.key', workspace.key);
  const secret = random(), secretFile = put('client-secret', secret), dbURLFile = put('db-url', roleURL), sessionKey = put('session.key', randomBytes(32));
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }), rogue = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const publicJwk = rsa.publicKey.export({ format: 'jwk' });
  const jwt = (payload, key = rsa.privateKey, typ = 'JWT') => { const body = b64(JSON.stringify({ alg: 'RS256', typ, kid: 'synthetic-key' })) + '.' + b64(JSON.stringify(payload)); return body + '.' + sign('RSA-SHA256', Buffer.from(body), key).toString('base64url'); };
  const decode = token => JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
  const codes = new Map(), trace = []; let scenario = 'valid'; let issuerOrigin = '';
  const workspaceOrigin = 'https://workspace.nex.test:9443';
  const issuer = https.createServer({ key: issuerTLS.key, cert: issuerTLS.cert, minVersion: 'TLSv1.3' }, async (req, res) => {
    try {
      const url = new URL(req.url, issuerOrigin);
      trace.push(`issuer ${req.method} ${url.pathname}`);
      const json = value => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(value)); };
      if (url.pathname === '/.well-known/openid-configuration' && req.method === 'GET') return json({ issuer: issuerOrigin, authorization_endpoint: issuerOrigin + '/authorize', token_endpoint: issuerOrigin + '/token', jwks_uri: issuerOrigin + '/jwks', response_types_supported: ['code'], grant_types_supported: ['authorization_code'], subject_types_supported: ['public'], id_token_signing_alg_values_supported: ['RS256'], token_endpoint_auth_methods_supported: ['client_secret_basic'], code_challenge_methods_supported: ['S256'], authorization_response_iss_parameter_supported: true });
      if (url.pathname === '/jwks' && req.method === 'GET') return json({ keys: [{ ...publicJwk, kid: 'synthetic-key', alg: 'RS256', use: 'sig' }] });
      if (url.pathname === '/authorize' && req.method === 'GET') {
        assert.equal(url.searchParams.get('client_id'), 'nex-workspace'); assert.equal(url.searchParams.get('redirect_uri'), workspaceOrigin + '/auth/callback');
        assert.equal(url.searchParams.get('code_challenge_method'), 'S256'); assert.equal(url.searchParams.get('max_age'), '600'); assert.equal(url.searchParams.get('acr_values'), 'urn:fixture:simulated-mfa');
        const code = random(); codes.set(code, { nonce: url.searchParams.get('nonce'), state: url.searchParams.get('state'), challenge: scenario === 'pkce' ? random() : url.searchParams.get('code_challenge'), scenario });
        const callback = new URL(workspaceOrigin + '/auth/callback'); callback.searchParams.set('code', code); callback.searchParams.set('state', scenario === 'state' ? 'wrong-state' : url.searchParams.get('state')); callback.searchParams.set('iss', issuerOrigin);
        res.writeHead(303, { location: callback.toString() }); return res.end();
      }
      if (url.pathname === '/token' && req.method === 'POST') {
        const form = await fields(req), txn = codes.get(form.get('code')); codes.delete(form.get('code'));
        const basic = /^Basic ([A-Za-z0-9+/]+={0,2})$/.exec(req.headers.authorization || '');
        let clientValid = false;
        if (basic) {
          const raw = Buffer.from(basic[1], 'base64').toString('utf8');
          const split = raw.indexOf(':');
          if (split >= 0) {
            const decodeForm = value => decodeURIComponent(value.replace(/\+/g, ' '));
            clientValid = decodeForm(raw.slice(0, split)) === 'nex-workspace' && decodeForm(raw.slice(split + 1)) === secret;
          }
        }
        const valid = { transaction: !!txn, client: clientValid, grant: form.get('grant_type') === 'authorization_code', redirect: form.get('redirect_uri') === workspaceOrigin + '/auth/callback', pkce: !!txn && createHash('sha256').update(form.get('code_verifier') || '').digest('base64url') === txn.challenge };
        if (!Object.values(valid).every(Boolean)) { trace.push('token validation ' + JSON.stringify(valid)); res.writeHead(400); return res.end(); }
        const now = Math.floor(Date.now() / 1000), access = { iss: issuerOrigin, sub: 'alice', aud: 'nex-api', client_id: 'nex-workspace', scope: 'nex:access', iat: now, exp: now + 120 };
        const id = { iss: txn.scenario === 'issuer' ? 'https://wrong.example.test' : issuerOrigin, sub: txn.scenario === 'subject' ? 'mallory' : 'alice', aud: txn.scenario === 'audience' ? 'wrong-client' : 'nex-workspace', nonce: txn.scenario === 'nonce' ? 'wrong-nonce' : txn.nonce, iat: now, exp: now + 120, auth_time: txn.scenario === 'old-auth' ? now - 601 : now, acr: txn.scenario === 'acr' ? 'weak' : 'urn:fixture:simulated-mfa', amr: txn.scenario === 'amr' ? ['pwd'] : ['pwd', 'otp'] };
        return json({ access_token: jwt(access, rsa.privateKey, 'at+jwt'), id_token: jwt(id, txn.scenario === 'signature' ? rogue.privateKey : rsa.privateKey), token_type: 'Bearer', expires_in: 120, scope: 'nex:access' });
      }
      res.writeHead(404); res.end();
    } catch { res.writeHead(500); res.end(); }
  });
  servers.push(issuer); const issuerPort = await start(issuer); issuerOrigin = `https://issuer.nex.test:${issuerPort}`;
  const control = https.createServer({ key: controlTLS.key, cert: controlTLS.cert, ca, requestCert: true, rejectUnauthorized: true, minVersion: 'TLSv1.3' }, (req, res) => {
    try {
      trace.push(`control ${req.method} ${req.url}`);
      assert.ok(req.socket.authorized); assert.equal(new X509Certificate(req.socket.getPeerCertificate().raw).fingerprint256, new X509Certificate(workspace.cert).fingerprint256);
      assert.equal(req.url, '/v1/me'); const token = (req.headers.authorization || '').replace(/^Bearer /, ''), parts = token.split('.');
      assert.equal(parts.length, 3); assert.ok(verify('RSA-SHA256', Buffer.from(parts[0] + '.' + parts[1]), rsa.publicKey, Buffer.from(parts[2], 'base64url')));
      const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString()); assert.equal(header.alg, 'RS256'); assert.equal(header.typ, 'at+jwt');
      const claims = decode(token); assert.equal(claims.iss, issuerOrigin); assert.equal(claims.aud, 'nex-api'); assert.equal(claims.sub, 'alice'); assert.equal(claims.client_id, 'nex-workspace'); assert.equal(claims.scope, 'nex:access'); assert.ok(claims.iat <= Date.now() / 1000 && claims.exp > Date.now() / 1000);
      res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ issuer: issuerOrigin, subject: 'alice', user_id: 'alice', tenant_id: 'tenant', delegation_id: 'delegation', permissions: ['document.read'] }));
    } catch { res.writeHead(401); res.end(); }
  });
  servers.push(control); const controlPort = await start(control);
  const policy = { issuer: issuerOrigin, clientId: 'nex-workspace', audience: 'nex-api', requiredAccessScope: 'nex:access', authorizationScopes: ['openid', 'nex:access'], workspaceOrigin, redirectURI: workspaceOrigin + '/auth/callback', authorizationEndpoint: issuerOrigin + '/authorize', tokenEndpoint: issuerOrigin + '/token', jwksURI: issuerOrigin + '/jwks', allowedAcr: ['urn:fixture:simulated-mfa'], requiredAmr: ['pwd', 'otp'], maxAuthAgeSeconds: 600 };
  const env = { ...process.env, APP_ENV: 'development', NEX_PROFILE: 'synthetic-qualification', NEX_SYNTHETIC_OIDC_WORKER: 'yes', NEX_SESSION_BACKEND: 'postgres', WORKSPACE_ORIGIN: workspaceOrigin, OIDC_ISSUER: issuerOrigin, OIDC_AUDIENCE: 'nex-api', OIDC_CLIENT_ID: 'nex-workspace', OIDC_REQUIRED_SCOPE: 'nex:access', OIDC_REDIRECT_URI: workspaceOrigin + '/auth/callback', CONTROL_URL: `https://control:${controlPort}`, NEX_TLS_CA_FILE: caFile, NEX_TLS_CERT_FILE: certFile, NEX_TLS_KEY_FILE: keyFile, OIDC_CLIENT_SECRET_FILE: secretFile, NEX_OIDC_ASSURANCE_POLICY_FILE: put('oidc.json', JSON.stringify(policy)), NEX_SESSION_DB_URL_FILE: dbURLFile, NEX_SESSION_DB_HOST: database.hostname, NEX_SESSION_DB_CA_FILE: dbCAPath, NEX_SESSION_ENCRYPTION_KEY_FILE: sessionKey };
  async function worker() {
    const child = fork(new URL('./synthetic-oidc-worker.mjs', import.meta.url), [], { env, silent: true }); children.push(child);
    child.stdout.resume(); child.stderr.resume();
    return await new Promise((resolve, reject) => { child.once('message', m => m.ready ? resolve({ child, port: m.port }) : reject(new Error('worker failed'))); child.once('exit', () => reject(new Error('worker exited before ready'))); });
  }
  const a = await worker(), b = await worker();
  const app = (replica, path, method = 'GET', extra = {}) => request(replica.port, 'workspace.nex.test', ca, path, { method, headers: { host: 'workspace.nex.test:9443', origin: workspaceOrigin, ...extra } });
  async function flow(variant) {
    scenario = variant;
    const login = await app(a, '/auth/login'); assert.equal(login.status, 303);
    const correlation = cookie(login, '__Host-nex_login'), authorization = new URL(login.headers.location);
    assert.equal(authorization.origin, issuerOrigin);
    const authorize = await request(issuerPort, 'issuer.nex.test', ca, authorization.pathname + authorization.search, { headers: { host: `issuer.nex.test:${issuerPort}` } });
    assert.equal(authorize.status, 303); const callback = new URL(authorize.headers.location); assert.equal(callback.origin, workspaceOrigin);
    if (variant === 'concurrent') {
      const raced = await Promise.all([app(a, callback.pathname + callback.search, 'GET', { cookie: correlation }), app(b, callback.pathname + callback.search, 'GET', { cookie: correlation })]);
      assert.deepEqual(raced.map(value => value.status).sort(), [303, 401], 'exactly one replica may consume the login');
      return raced.find(value => value.status === 303);
    }
    const response = await app(b, callback.pathname + callback.search, 'GET', { cookie: correlation });
    if (variant === 'valid' && response.status === 303) {
      const replay = await Promise.all([app(a, callback.pathname + callback.search, 'GET', { cookie: correlation }), app(b, callback.pathname + callback.search, 'GET', { cookie: correlation })]);
      assert.ok(replay.every(value => value.status === 401), 'consumed login callback must not replay on either replica');
    }
    return response;
  }
  const success = await flow('valid'); await new Promise(resolve => setImmediate(resolve)); assert.equal(success.status, 303, `valid callback failed; fixture stages: ${trace.join(', ')}`);
  const sessionCookie = cookie(success, '__Host-nex_session'), id = sessionCookie.split('=')[1];
  const first = await app(a, '/api/session', 'GET', { cookie: sessionCookie }), second = await app(b, '/api/session', 'GET', { cookie: sessionCookie });
  assert.equal(first.status, 200); assert.equal(second.status, 200);
  const view = JSON.parse(first.body); assert.equal(view.subject, 'alice'); assert.ok(!first.body.includes('access_token'));
  const row = await admin.query("SELECT sealed FROM nex_workspace_auth.workspace_session_state WHERE kind='session' AND handle_hash=$1", [createHash('sha256').update(id, 'ascii').digest('hex')]);
  assert.equal(row.rowCount, 1); for (const plaintext of ['urn:fixture:simulated-mfa', 'alice', 'auth_time']) assert.equal(row.rows[0].sealed.includes(Buffer.from(plaintext)), false);
  assert.equal((await app(b, '/auth/logout', 'POST', { cookie: sessionCookie, 'x-nex-csrf': view.csrf_token })).status, 200);
  assert.equal((await app(a, '/api/session', 'GET', { cookie: sessionCookie })).status, 401);
  const raced = await flow('concurrent'), racedCookie = cookie(raced, '__Host-nex_session');
  const racedView = await app(a, '/api/session', 'GET', { cookie: racedCookie }); assert.equal(racedView.status, 200);
  assert.equal((await app(b, '/auth/logout', 'POST', { cookie: racedCookie, 'x-nex-csrf': JSON.parse(racedView.body).csrf_token })).status, 200);
  for (const type of ['ciphertext', 'expiry']) {
    const fresh = await flow('valid'), freshCookie = cookie(fresh, '__Host-nex_session');
    const hash = createHash('sha256').update(freshCookie.split('=')[1], 'ascii').digest('hex');
    if (type === 'ciphertext') await admin.query("UPDATE nex_workspace_auth.workspace_session_state SET sealed=set_byte(sealed, 13, get_byte(sealed, 13) # 1) WHERE kind='session' AND handle_hash=$1", [hash]);
    else await admin.query("UPDATE nex_workspace_auth.workspace_session_state SET hard_expires_ms=hard_expires_ms+1000 WHERE kind='session' AND handle_hash=$1", [hash]);
    assert.equal((await app(a, '/api/session', 'GET', { cookie: freshCookie })).status, 503, `tampered ${type} must fail closed`);
    await admin.query("DELETE FROM nex_workspace_auth.workspace_session_state WHERE kind='session' AND handle_hash=$1", [hash]);
  }
  for (const variant of ['acr', 'amr', 'old-auth', 'nonce', 'audience', 'issuer', 'subject', 'signature', 'pkce', 'state']) {
    const before = trace.filter(value => value === 'control GET /v1/me').length;
    const denied = await flow(variant); assert.equal(denied.status, 401, `expected signed ${variant} rejection`);
    assert.equal((denied.headers['set-cookie'] || []).some(value => value.startsWith('__Host-nex_session=')), false);
    if (variant !== 'subject') assert.equal(trace.filter(value => value === 'control GET /v1/me').length, before, `${variant} must be denied before control identity lookup`);
  }
  const legacy = await new Promise(resolve => { const listener = value => { if (value.legacy) { a.child.off('message', listener); resolve(value.legacy); } }; a.child.on('message', listener); a.child.send('seed-legacy'); });
  assert.equal((await app(b, '/api/session', 'GET', { cookie: `__Host-nex_session=${legacy.id}` })).status, 401);
  assert.equal((await app(b, '/auth/logout', 'POST', { cookie: `__Host-nex_session=${legacy.id}`, 'x-nex-csrf': legacy.csrf })).status, 200);
});
