import 'reflect-metadata';
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as x509 from '@peculiar/x509';
import { SESSION_COOKIE } from '../lib/sessions.ts';
import { qualificationWorkflow } from '../lib/workflow.ts';
import { GET as sessionGET } from '../app/api/session/route.ts';
import { POST as logoutPOST } from '../app/auth/logout/route.ts';

// Exercise HTTP mappings with a failing store, independently of live PostgreSQL.
test('workspace returns 503 without disclosing session data when the session store fails', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'nex-session-http-'));
  const rootKeys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const ownKeys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const root = await x509.X509CertificateGenerator.createSelfSigned({ name: 'CN=test-root', keys: rootKeys, notBefore: new Date(Date.now() - 60_000), notAfter: new Date(Date.now() + 3600_000), extensions: [new x509.BasicConstraintsExtension(true, 1, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true)] });
  const own = await x509.X509CertificateGenerator.create({ subject: 'CN=workspace', issuer: root.subject, publicKey: ownKeys.publicKey, signingKey: rootKeys.privateKey, notBefore: new Date(Date.now() - 60_000), notAfter: new Date(Date.now() + 3600_000), extensions: [new x509.BasicConstraintsExtension(false), new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: 'workspace.nex.test' }, { type: 'url', value: 'spiffe://nex.local/service/workspace' }]), new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.clientAuth, x509.ExtendedKeyUsage.serverAuth])] });
  const privateDER = Buffer.from(await crypto.subtle.exportKey('pkcs8', ownKeys.privateKey));
  const keyPEM = `-----BEGIN PRIVATE KEY-----\n${privateDER.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;
  const put = (name, value) => { const path = join(dir, name); writeFileSync(path, value, { mode: 0o600 }); return path; };
  const values = { APP_ENV: 'development', NEX_PROFILE: 'synthetic-qualification', NEX_SESSION_BACKEND: 'postgres', WORKSPACE_ORIGIN: 'https://workspace.nex.test:9443', OIDC_ISSUER: 'https://issuer.nex.test:9444', OIDC_AUDIENCE: 'nex-api', OIDC_CLIENT_ID: 'nex-workspace', OIDC_REQUIRED_SCOPE: 'nex:access', OIDC_REDIRECT_URI: 'https://workspace.nex.test:9443/auth/callback', CONTROL_URL: 'https://control:8443', NEX_TLS_CA_FILE: put('ca.pem', root.toString('pem')), NEX_TLS_CERT_FILE: put('cert.pem', own.toString('pem')), NEX_TLS_KEY_FILE: put('key.pem', keyPEM), OIDC_CLIENT_SECRET_FILE: put('client-secret', 'synthetic-secret') };
  const previous = Object.fromEntries(Object.keys(values).map(key => [key, process.env[key]]));
  const oldStore = globalThis.__nexQualificationSessions;
  t.after(() => {
    for (const key of Object.keys(values)) { if (previous[key] === undefined) delete process.env[key]; else process.env[key] = previous[key]; }
    if (oldStore === undefined) delete globalThis.__nexQualificationSessions; else globalThis.__nexQualificationSessions = oldStore;
    rmSync(dir, { recursive: true, force: true });
  });
  Object.assign(process.env, values);
  const id = 'a'.repeat(43), csrf = 'b'.repeat(43);
  let failGet = true;
  globalThis.__nexQualificationSessions = {
    async readiness() {},
    async get() {
      if (failGet) throw new Error('Session store unavailable');
      return { id, csrf, accessToken: 'PRIVATE_SESSION_TOKEN', actor: { issuer: 'issuer', subject: 'alice', user_id: 'alice', tenant_id: 'tenant', delegation_id: 'delegation', permissions: [] }, expires: Date.now() + 60_000, idleExpires: Date.now() + 60_000 };
    },
    async close() { throw new Error('Session store unavailable'); },
  };
  const headers = { Host: 'workspace.nex.test:9443', Origin: 'https://workspace.nex.test:9443', Cookie: `${SESSION_COOKIE}=${id}`, 'X-Nex-CSRF': csrf, 'Content-Type': 'application/json' };
  const request = (path, method, body) => new Request(`https://workspace.nex.test:9443${path}`, { method, headers, ...(body ? { body: JSON.stringify(body) } : {}) });
  async function unavailable(response) {
    assert.equal(response.status, 503);
    const text = await response.text();
    assert.equal(JSON.parse(text).code, 'AUTHENTICATION_UNAVAILABLE');
    assert.ok(!text.includes('PRIVATE_SESSION_TOKEN'));
  }
  await unavailable(await sessionGET(request('/api/session', 'GET')));
  await unavailable(await qualificationWorkflow(request('/api/workflow', 'POST', { operation: 'documents' })));
  await unavailable(await logoutPOST(request('/auth/logout', 'POST')));
  failGet = false;
  await unavailable(await logoutPOST(request('/auth/logout', 'POST')));
});
