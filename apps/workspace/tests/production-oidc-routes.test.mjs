import 'reflect-metadata';
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as x509 from '@peculiar/x509';
import { SessionStore, SESSION_COOKIE } from '../lib/sessions.ts';
import { GET as sessionGET } from '../app/api/session/route.ts';
import { POST as logoutPOST } from '../app/auth/logout/route.ts';
import { qualificationWorkflow } from '../lib/workflow.ts';
import { startControlFixture } from './control-fixture.mjs';

test('OIDC assurance is required for sessions but logout can revoke stale sessions', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'nex-oidc-routes-'));
  const keygen = () => crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const rootKeys = await keygen(), ownKeys = await keygen();
  const root = await x509.X509CertificateGenerator.createSelfSigned({ name: 'CN=test-root', keys: rootKeys, notBefore: new Date(Date.now() - 60_000), notAfter: new Date(Date.now() + 3600_000), extensions: [new x509.BasicConstraintsExtension(true, 1, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true)] });
  const own = await x509.X509CertificateGenerator.create({ subject: 'CN=workspace', issuer: root.subject, publicKey: ownKeys.publicKey, signingKey: rootKeys.privateKey, notBefore: new Date(Date.now() - 60_000), notAfter: new Date(Date.now() + 3600_000), extensions: [new x509.BasicConstraintsExtension(false), new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: 'workspace.nex.test' }, { type: 'url', value: 'spiffe://nex.local/service/workspace' }]), new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.clientAuth, x509.ExtendedKeyUsage.serverAuth])] });
  const privateDER = Buffer.from(await crypto.subtle.exportKey('pkcs8', ownKeys.privateKey));
  const keyPEM = `-----BEGIN PRIVATE KEY-----\n${privateDER.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;
  const put = (name, value) => { const path = join(dir, name); writeFileSync(path, value, { mode: 0o600 }); return path; };
  const origin = 'https://workspace.nex.test:9443', issuer = 'https://issuer.nex.test:9444';
  const actor = { issuer, subject: 'alice', user_id: 'alice', tenant_id: 'tenant', delegation_id: 'delegation', permissions: ['document.read'] };
  const control = await startControlFixture(t, root, rootKeys, actor, 'PRIVATE_TOKEN');
  const policy = { issuer, clientId: 'nex-workspace', audience: 'nex-api', requiredAccessScope: 'nex:access', authorizationScopes: ['openid', 'nex:access'], workspaceOrigin: origin, redirectURI: origin + '/auth/callback', authorizationEndpoint: issuer + '/authorize', tokenEndpoint: issuer + '/token', jwksURI: issuer + '/keys', allowedAcr: ['urn:test:mfa'], requiredAmr: ['pwd', 'otp'], maxAuthAgeSeconds: 600 };
  const values = { APP_ENV: 'development', NEX_PROFILE: 'synthetic-qualification', NEX_SESSION_BACKEND: 'memory', WORKSPACE_ORIGIN: origin, OIDC_ISSUER: issuer, OIDC_AUDIENCE: 'nex-api', OIDC_CLIENT_ID: 'nex-workspace', OIDC_REQUIRED_SCOPE: 'nex:access', OIDC_REDIRECT_URI: origin + '/auth/callback', CONTROL_URL: control.url, NEX_TLS_CA_FILE: put('ca.pem', root.toString('pem')), NEX_TLS_CERT_FILE: put('cert.pem', own.toString('pem')), NEX_TLS_KEY_FILE: put('key.pem', keyPEM), OIDC_CLIENT_SECRET_FILE: put('client-secret', 'synthetic-secret'), NEX_OIDC_ASSURANCE_POLICY_FILE: put('oidc.json', JSON.stringify(policy)) };
  const previous = Object.fromEntries(Object.keys(values).map(key => [key, process.env[key]]));
  const oldStore = globalThis.__nexQualificationSessions;
  t.after(() => {
    for (const key of Object.keys(values)) { if (previous[key] === undefined) delete process.env[key]; else process.env[key] = previous[key]; }
    if (oldStore === undefined) delete globalThis.__nexQualificationSessions; else globalThis.__nexQualificationSessions = oldStore;
    rmSync(dir, { recursive: true, force: true });
  });
  Object.assign(process.env, values);
  const store = new SessionStore(); globalThis.__nexQualificationSessions = store;
  const now = Math.floor(Date.now() / 1000);
  const assurance = { iss: issuer, sub: 'alice', iat: now, exp: now + 300, auth_time: now, acr: 'urn:test:mfa', amr: ['pwd', 'otp'] };
  const open = claims => store.open(actor, 'PRIVATE_TOKEN', Date.now() + 120_000, Date.now() + 120_000, claims);
  const req = (session, path, method = 'GET', overrides = {}, workflow = { operation: 'documents' }) => new Request(origin + path, { method, headers: { Host: 'workspace.nex.test:9443', Origin: origin, Cookie: `${SESSION_COOKIE}=${session.id}`, 'X-Nex-CSRF': session.csrf, 'Content-Type': 'application/json', ...overrides }, ...(path === '/api/workflow' ? { body: JSON.stringify(workflow) } : {}) });
  const waitForControl = async count => {
    const deadline = Date.now() + 3000;
    while (control.state.requests.length === count && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 5));
    assert.ok(control.state.requests.length > count, 'control lookup did not arrive');
  };
  const valid = open(assurance);
  const view = await sessionGET(req(valid, '/api/session'));
  assert.equal(view.status, 200);
  const body = await view.text();
  assert.equal(JSON.parse(body).subject, 'alice');
  assert.ok(!body.includes('PRIVATE_TOKEN'));
  assert.deepEqual(control.state.requests.at(-1), { method: 'GET', path: '/v1/me', authenticated: true, tokenMatches: true, body: '' });
  control.state.actor = { ...actor, delegation_id: '', permissions: ['approval.decide'] };
  const changed = await (await sessionGET(req(valid, '/api/session'))).json();
  assert.equal(changed.can_request_review, false);
  assert.equal(changed.can_approve, true);
  control.state.actor = { ...actor, delegation_id: 'fresh-delegation', permissions: [] };
  const current = await (await sessionGET(req(valid, '/api/session'))).json();
  assert.equal(current.can_request_review, true);
  assert.equal(current.can_approve, false);
  const create = { operation: 'create', document_id: 'doc-1', idempotency_key: 'unique-123', question_catalogue_id: 'access-review-controls' };
  assert.equal((await qualificationWorkflow(req(valid, '/api/workflow', 'POST', {}, create))).status, 200);
  const sent = control.state.requests.at(-1);
  assert.equal(sent.path, '/v1/jobs');
  assert.equal(JSON.parse(sent.body).delegation_id, 'fresh-delegation');
  control.state.actor = { ...actor, delegation_id: '', permissions: [] };
  const beforeDenied = control.state.requests.length;
  assert.equal((await qualificationWorkflow(req(valid, '/api/workflow', 'POST', {}, create))).status, 400);
  assert.deepEqual(control.state.requests.slice(beforeDenied).map(r => r.path), ['/v1/me']);
  control.state.actor = actor;
  for (const field of ['issuer', 'subject', 'user_id', 'tenant_id']) {
    const victim = open(assurance); control.state.actor = { ...actor, [field]: 'different' };
    assert.equal((await sessionGET(req(victim, '/api/session'))).status, 401, `${field} mismatch`);
    assert.equal(store.get(victim.id), undefined);
  }
  control.state.actor = actor;
  for (const status of [401, 403]) {
    const revoked = open(assurance); control.state.status = status; control.state.body = '';
    assert.equal((await sessionGET(req(revoked, '/api/session'))).status, 401, `empty ${status} revokes session`);
    assert.equal(store.get(revoked.id), undefined);
  }
  control.state.status = 200; control.state.body = '{';
  const unavailable = open(assurance);
  assert.equal((await sessionGET(req(unavailable, '/api/session'))).status, 503);
  assert.equal((await qualificationWorkflow(req(unavailable, '/api/workflow', 'POST'))).status, 503);
  assert.ok(store.get(unavailable.id));
  control.state.body = undefined; control.state.drop = true;
  assert.equal((await sessionGET(req(unavailable, '/api/session'))).status, 503);
  assert.equal((await logoutPOST(req(unavailable, '/auth/logout', 'POST'))).status, 200);
  assert.equal(store.get(unavailable.id), undefined);
  control.state.drop = false;
  const racing = open(assurance); let release;
  control.state.gate = new Promise(resolve => { release = resolve; });
  const count = control.state.requests.length;
  const pending = sessionGET(req(racing, '/api/session'));
  await waitForControl(count);
  assert.equal((await logoutPOST(req(racing, '/auth/logout', 'POST'))).status, 200);
  release(); control.state.gate = null;
  assert.equal((await pending).status, 401, 'logout during current-authority lookup invalidates the in-flight request');
  const nearlyStale = open({ ...assurance, auth_time: Math.floor(Date.now() / 1000) - 599 });
  control.state.gate = new Promise(resolve => { release = resolve; });
  const beforeSlow = control.state.requests.length;
  const delayed = sessionGET(req(nearlyStale, '/api/session'));
  await waitForControl(beforeSlow);
  await new Promise(resolve => setTimeout(resolve, 2100));
  release(); control.state.gate = null;
  assert.equal((await delayed).status, 401, 'assurance expiry during current-authority lookup denies the request');
  for (const claims of [undefined, { ...assurance, sub: 'bob' }, { ...assurance, iss: 'https://other.test' }, { ...assurance, acr: 'weak' }, { ...assurance, amr: ['pwd'] }, { ...assurance, auth_time: now - 601 }, { ...assurance, exp: now - 1 }]) {
    const stale = open(claims);
    assert.equal((await sessionGET(req(stale, '/api/session'))).status, 401);
    assert.equal((await qualificationWorkflow(req(stale, '/api/workflow', 'POST'))).status, 403);
  }
  const stale = open({ ...assurance, auth_time: now - 601 });
  assert.equal((await logoutPOST(req(stale, '/auth/logout', 'POST', { 'X-Nex-CSRF': 'invalid' }))).status, 403);
  assert.ok(store.get(stale.id));
  assert.equal((await logoutPOST(req(stale, '/auth/logout', 'POST'))).status, 200);
  assert.equal(store.get(stale.id), undefined);
});
