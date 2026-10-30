import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, chmodSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const policy = () => ({ issuer: 'https://issuer.example.test/tenant', clientId: 'workspace-client', audience: 'control-api', requiredAccessScope: 'api:access', authorizationScopes: ['openid', 'api:access'], workspaceOrigin: 'https://workspace.example.test', redirectURI: 'https://workspace.example.test/auth/callback', authorizationEndpoint: 'https://issuer.example.test/authorize', tokenEndpoint: 'https://issuer.example.test/token', jwksURI: 'https://issuer.example.test/jwks', allowedAcr: ['approved-mfa'], requiredAmr: [], maxAuthAgeSeconds: 600 });
const config = () => ({ issuerText: 'https://issuer.example.test/tenant', issuer: new URL('https://issuer.example.test/tenant'), clientID: 'workspace-client', origin: new URL('https://workspace.example.test'), redirectURI: 'https://workspace.example.test/auth/callback' });
let serial = 0;
async function loader() { return (await import(`../lib/production-oidc-config.ts?case=${serial++}`)).configuredProductionOidcPolicy; }

test('private trusted policy is immutable and bound to active workspace identity', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'nex-oidc-policy-'));
  const names = ['NEX_OIDC_ASSURANCE_POLICY_FILE', 'OIDC_AUDIENCE', 'OIDC_REQUIRED_SCOPE'];
  const previous = Object.fromEntries(names.map(name => [name, process.env[name]]));
  t.after(() => { for (const name of names) { if (previous[name] === undefined) delete process.env[name]; else process.env[name] = previous[name]; } rmSync(dir, { recursive: true, force: true }); });
  const file = join(dir, 'policy.json'); writeFileSync(file, JSON.stringify(policy()), { mode: 0o600 });
  process.env.OIDC_AUDIENCE = 'control-api'; process.env.OIDC_REQUIRED_SCOPE = 'api:access';
  process.env.NEX_OIDC_ASSURANCE_POLICY_FILE = file;
  const load = await loader(), configured = load(config());
  assert.equal(configured.clientId, 'workspace-client');
  assert.ok(Object.isFrozen(configured) && Object.isFrozen(configured.allowedAcr));
  writeFileSync(file, JSON.stringify({ ...policy(), allowedAcr: ['changed'] }));
  assert.deepEqual(load(config()).allowedAcr, ['approved-mfa'], 'policy must not silently reload');
  process.env.NEX_OIDC_ASSURANCE_POLICY_FILE = file + '.other';
  assert.throws(() => load(config()), /changed/);

  process.env.NEX_OIDC_ASSURANCE_POLICY_FILE = file;
  writeFileSync(file, JSON.stringify(policy())); chmodSync(file, 0o644);
  async function freshReject() { const fresh = await loader(); assert.throws(() => fresh(config()), /invalid/); }
  await freshReject(); chmodSync(file, 0o600);
  const link = join(dir, 'link'); symlinkSync(file, link); process.env.NEX_OIDC_ASSURANCE_POLICY_FILE = link;
  await freshReject(); process.env.NEX_OIDC_ASSURANCE_POLICY_FILE = file;
  writeFileSync(file, JSON.stringify({ ...policy(), issuer: 'https://other.example.test/tenant' })); await freshReject();
  writeFileSync(file, JSON.stringify({ ...policy(), authorizationEndpoint: 'https://other.example.test/authorize' })); await freshReject();
  writeFileSync(file, '{broken'); await freshReject();
});

test('starting without a policy cannot silently enable one later', async t => {
  const previous = process.env.NEX_OIDC_ASSURANCE_POLICY_FILE;
  t.after(() => { if (previous === undefined) delete process.env.NEX_OIDC_ASSURANCE_POLICY_FILE; else process.env.NEX_OIDC_ASSURANCE_POLICY_FILE = previous; });
  delete process.env.NEX_OIDC_ASSURANCE_POLICY_FILE;
  const load = await loader(); assert.equal(load(config()), undefined);
  process.env.NEX_OIDC_ASSURANCE_POLICY_FILE = '/unused'; assert.throws(() => load(config()), /changed/);
});
