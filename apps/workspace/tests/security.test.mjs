import 'reflect-metadata';
import test from 'node:test';
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as x509 from '@peculiar/x509';
import { certificateRole, assertPeerIdentity, assertCertificateTime, assertCertificatePathTime, workspaceConfig } from '../lib/trust.ts';
import { SessionStore, sessions, cookie, cookieHeader, SESSION_COOKIE, LOGIN_COOKIE, IDLE_MILLISECONDS, TOTAL_MILLISECONDS } from '../lib/sessions.ts';
import { requireSession, sessionView, logout } from '../lib/auth.ts';
import { qualificationWorkflow } from '../lib/workflow.ts';
import { profile } from '../lib/profile.ts';

const actor = { issuer: 'https://issuer.nex.test:9444', subject: 'alice', user_id: 'alice', tenant_id: 'tenant-a', delegation_id: 'delegation-alice', permissions: ['document.read', 'model.invoke'] };

test('server sessions distinguish idle and hard credential expiry without exposing tokens', () => {
  let clock = 1000; const store = new SessionStore(() => clock);
  const value = store.open(actor, 'private-access-token', clock + TOTAL_MILLISECONDS * 2, clock + TOTAL_MILLISECONDS * 2);
  assert.equal(store.get(value.id).accessToken, 'private-access-token');
  clock += IDLE_MILLISECONDS - 1; assert.ok(store.get(value.id));
  clock++; assert.equal(store.get(value.id), undefined, 'background reads must not extend idle timeout');
  clock = 1000; const bounded = store.open(actor, 'private-token', clock + 8 * 60_000, clock + 30 * 60_000);
  clock += 4 * 60_000; assert.ok(store.get(bounded.id, true));
  clock += 4 * 60_000; assert.equal(store.get(bounded.id), undefined, 'access expiry is an absolute boundary');
  clock = 1000; const hard = store.open(actor, 'private-token', clock + 30 * 60_000, clock + 30 * 60_000);
  for (let i = 0; i < 3; i++) { clock += 4 * 60_000; assert.ok(store.get(hard.id, true)); }
  clock = 1000 + TOTAL_MILLISECONDS; assert.equal(store.get(hard.id, true), undefined);
  assert.equal(new SessionStore().get(value.id), undefined, 'process restart invalidates prior sessions');
});

test('login correlation is one-use, bounded and invalid state cannot be replayed', () => {
  let clock = 0; const store = new SessionStore(() => clock);
  const transaction = store.begin('correct-state', 'nonce', 'private-pkce-verifier');
  assert.throws(() => store.consume(transaction.id, 'wrong-state'));
  assert.throws(() => store.consume(transaction.id, 'correct-state'));
  const valid = store.begin('valid', 'nonce', 'private-verifier');
  assert.equal(store.consume(valid.id, 'valid').verifier, 'private-verifier');
  assert.throws(() => store.consume(valid.id, 'valid'));
  for (let i = 0; i < 1000; i++) store.begin('state', 'nonce', 'verifier');
  assert.throws(() => store.begin('state', 'nonce', 'verifier'));
  clock = 300001; assert.ok(store.begin('new', 'nonce', 'verifier'));
});

test('host cookies have mandatory browser protections and ambiguous handles reject', () => {
  const header = cookieHeader(SESSION_COOKIE, 'a'.repeat(43), 90);
  for (const field of ['__Host-nex_session=', 'Path=/', 'HttpOnly', 'Secure', 'SameSite=Lax', 'Max-Age=90']) assert.ok(header.includes(field));
  assert.ok(!header.includes('Domain='));
  const request = new Request('https://workspace.nex.test:9443', { headers: { cookie: `${SESSION_COOKIE}=${'a'.repeat(43)}; ${SESSION_COOKIE}=${'b'.repeat(43)}` } });
  assert.throws(() => cookie(request, SESSION_COOKIE));
  assert.equal(cookie(new Request('https://workspace.nex.test', { headers: { cookie: `${SESSION_COOKIE}=invalid` } }), SESSION_COOKIE), undefined);
});

async function keys() { return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']); }
async function leaf(roles, dns = ['control'], dates = {}) {
  const pair = await keys();
  const certificate = await x509.X509CertificateGenerator.createSelfSigned({ name: 'CN=control', keys: pair, notBefore: new Date(Date.now() - 60_000), notAfter: new Date(Date.now() + 60_000), ...dates,
    extensions: [new x509.SubjectAlternativeNameExtension([...dns.map(value => ({ type: 'dns', value })), ...roles.map(value => ({ type: 'url', value }))])] });
  return { raw: new Uint8Array(certificate.rawData), certificate };
}
test('DER workload identity rejects wrong role, DNS text spoof, CN fallback and multiple identities', async () => {
  const valid = await leaf(['spiffe://nex.local/service/control']);
  assert.equal(certificateRole(valid.raw), 'spiffe://nex.local/service/control');
  assert.ok(assertPeerIdentity(valid.raw, 'control', 'control'));
  assert.throws(() => assertPeerIdentity(valid.raw, 'guard', 'control'));
  assert.throws(() => assertPeerIdentity(valid.raw, 'control', 'other'));
  const spoof = await leaf(['spiffe://nex.local/service/guard'], ['control', 'evil, URI:spiffe://nex.local/service/control, injected']);
  assert.throws(() => assertPeerIdentity(spoof.raw, 'control', 'control'));
  const cn = await leaf(['spiffe://nex.local/service/control'], []);
  assert.throws(() => assertPeerIdentity(cn.raw, 'control', 'control'));
  const ambiguous = await leaf(['spiffe://nex.local/service/control', 'spiffe://nex.local/service/guard']);
  assert.throws(() => certificateRole(ambiguous.raw));
  const duplicateKeys = await keys();
  const duplicateSAN = await x509.X509CertificateGenerator.createSelfSigned({ name: 'CN=control', keys: duplicateKeys, extensions: [new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: 'control' }, { type: 'url', value: 'spiffe://nex.local/service/control' }]), new x509.SubjectAlternativeNameExtension([{ type: 'url', value: 'spiffe://nex.local/service/guard' }])] });
  assert.throws(() => certificateRole(new Uint8Array(duplicateSAN.rawData)), 'the first of two SAN extensions must never choose identity');
  const expired = await leaf(['spiffe://nex.local/service/control'], ['control'], { notBefore: new Date(Date.now() - 120_000), notAfter: new Date(Date.now() - 60_000) });
  const expiredEntry = new X509Certificate(expired.raw), liveEntry = new X509Certificate(valid.raw);
  assert.throws(() => assertCertificateTime(expiredEntry));
  assert.doesNotThrow(() => assertCertificatePathTime([liveEntry]));
  assert.throws(() => assertCertificatePathTime([liveEntry, expiredEntry]), 'an expired issuer cannot hide behind a live leaf');
  assert.throws(() => assertCertificatePathTime([expiredEntry, liveEntry]));
});

test('qualification sessions enforce origin/CSRF, omit tokens and cannot select another identity', async t => {
  const directory = mkdtempSync(join(tmpdir(), 'nex-web-auth-')); t.after(() => rmSync(directory, { recursive: true, force: true }));
  const rootKeys = await keys(), ownKeys = await keys();
  const root = await x509.X509CertificateGenerator.createSelfSigned({ name: 'CN=test-root', keys: rootKeys, notBefore: new Date(Date.now() - 60_000), notAfter: new Date(Date.now() + 3600_000), extensions: [new x509.BasicConstraintsExtension(true, 1, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true)] });
  const own = await x509.X509CertificateGenerator.create({ subject: 'CN=workspace', issuer: root.subject, publicKey: ownKeys.publicKey, signingKey: rootKeys.privateKey, notBefore: new Date(Date.now() - 60_000), notAfter: new Date(Date.now() + 3600_000), extensions: [new x509.BasicConstraintsExtension(false), new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: 'workspace.nex.test' }, { type: 'url', value: 'spiffe://nex.local/service/workspace' }]), new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.clientAuth, x509.ExtendedKeyUsage.serverAuth])] });
  const privateDER = Buffer.from(await crypto.subtle.exportKey('pkcs8', ownKeys.privateKey));
  const keyPEM = `-----BEGIN PRIVATE KEY-----\n${privateDER.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;
  const put = (name, content) => { const path = join(directory, name); writeFileSync(path, content, { mode: 0o600 }); return path; };
  const previous = { ...process.env };
  const values = { APP_ENV: 'development', NEX_PROFILE: 'synthetic-qualification', WORKSPACE_ORIGIN: 'https://workspace.nex.test:9443', OIDC_ISSUER: actor.issuer, OIDC_AUDIENCE: 'nex-api', OIDC_CLIENT_ID: 'nex-workspace', OIDC_REQUIRED_SCOPE: 'nex:access', OIDC_REDIRECT_URI: 'https://workspace.nex.test:9443/auth/callback', CONTROL_URL: 'https://control:8443', NEX_TLS_CA_FILE: put('ca.pem', root.toString('pem')), NEX_TLS_CERT_FILE: put('cert.pem', own.toString('pem')), NEX_TLS_KEY_FILE: put('key.pem', keyPEM), OIDC_CLIENT_SECRET_FILE: put('client-secret', 'synthetic-confidential-client-secret') };
  Object.assign(process.env, values); t.after(() => { for (const key of Object.keys(values)) { if (previous[key] === undefined) delete process.env[key]; else process.env[key] = previous[key]; } });
  assert.ok(workspaceConfig());
  const value = sessions().open(actor, 'PRIVATE_ACCESS_TOKEN_NOT_FOR_BROWSER', Date.now() + 120_000, Date.now() + 120_000);
  const headers = { Host: 'workspace.nex.test:9443', Origin: 'https://workspace.nex.test:9443', Cookie: `${SESSION_COOKIE}=${value.id}`, 'X-Nex-CSRF': value.csrf, 'Content-Type': 'application/json' };
  const request = (changes = {}, body) => new Request('https://workspace.nex.test:9443/api/workflow', { method: 'POST', headers: { ...headers, ...changes }, body: body === undefined ? undefined : JSON.stringify(body) });
  assert.equal(requireSession(request(), true).actor.subject, 'alice');
  assert.throws(() => requireSession(request({ Origin: 'https://attacker.test' }), true));
  assert.throws(() => requireSession(request({ 'X-Nex-CSRF': 'forged' }), true));
  assert.throws(() => requireSession(request({ Host: 'attacker.test', 'X-Forwarded-Host': 'workspace.nex.test:9443' }), true));
  const view = await sessionView(request()).json();
  assert.equal(view.subject, 'alice'); assert.equal(view.csrf_token, value.csrf);
  assert.ok(!JSON.stringify(view).includes('PRIVATE_ACCESS_TOKEN'));
  for (const body of [ { operation: 'documents', subject: 'bob' }, { operation: 'create', document_id: 'review-alice', idempotency_key: 'test-123456', question: 'arbitrary' }, { operation: 'documents', tenant_id: 'tenant-b' }, { operation: 'documents', roles: ['admin'] } ]) assert.equal((await qualificationWorkflow(request({}, body))).status, 400);
  const response = await logout(request()); assert.equal(response.status, 200);
  assert.ok(response.headers.get('set-cookie').includes('Max-Age=0'));
  assert.equal(sessions().get(value.id), undefined);
  assert.equal(sessionView(request()).status, 401);
  const other = sessions().open(actor, 'private', Date.now() + 60_000, Date.now() + 60_000); other.expires = Date.now() - 1;
  assert.equal(sessionView(request({ Cookie: `${SESSION_COOKIE}=${other.id}` })).status, 401);
  process.env.NEX_PROFILE = 'production'; assert.throws(() => profile());
});
