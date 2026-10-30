import test from 'node:test';
import assert from 'node:assert/strict';
import { createProductionOidcPolicy, productionAuthorizationRequirements, validateProductionDiscovery, validateVerifiedProductionIdentity } from '../lib/production-oidc-policy.ts';

const inputs = () => ({
  issuer: 'https://identity.example.test/tenant', clientId: 'workspace-client', audience: 'control-api', requiredAccessScope: 'api:access',
  authorizationScopes: ['openid', 'api:access'], workspaceOrigin: 'https://workspace.example.test', redirectURI: 'https://workspace.example.test/auth/callback',
  authorizationEndpoint: 'https://login.example.test/oauth2/authorize', tokenEndpoint: 'https://login.example.test/oauth2/token', jwksURI: 'https://identity.example.test/tenant/keys',
  allowedAcr: ['urn:example:verified-mfa'], requiredAmr: ['pwd', 'otp'], maxAuthAgeSeconds: 600,
});
const claims = () => ({ iss: 'https://identity.example.test/tenant', sub: 'alice', iat: 1700000000, exp: 1700000900, auth_time: 1699999999, acr: 'urn:example:verified-mfa', amr: ['pwd', 'otp'] });
const actor = () => ({ issuer: 'https://identity.example.test/tenant', subject: 'alice', user_id: 'u1', tenant_id: 't1', delegation_id: '', permissions: ['document.read'] });
const metadata = policy => ({ issuer: policy.issuer, authorization_endpoint: policy.authorizationEndpoint, token_endpoint: policy.tokenEndpoint, jwks_uri: policy.jwksURI, response_types_supported: ['code'], code_challenge_methods_supported: ['S256'], id_token_signing_alg_values_supported: ['RS256'], token_endpoint_auth_methods_supported: ['client_secret_basic'] });

test('explicit production policy validates split-origin provider and signed-identity binding', () => {
  const mutable = inputs(), policy = createProductionOidcPolicy(mutable);
  mutable.authorizationScopes.push('unexpected'); mutable.allowedAcr.push('weak'); mutable.requiredAmr.splice(0);
  assert.deepEqual(productionAuthorizationRequirements(policy), { scope: 'openid api:access', max_age: '600', acr_values: 'urn:example:verified-mfa' });
  validateProductionDiscovery(policy, metadata(policy));
  validateVerifiedProductionIdentity(policy, claims(), actor(), 1700000000);
  assert.throws(() => validateProductionDiscovery(policy, { ...metadata(policy), authorization_endpoint: 'https://attacker.test' }), /denied/);
  assert.throws(() => validateProductionDiscovery(policy, { ...metadata(policy), jwks_uri: 'https://attacker.test/keys' }), /denied/);
  for (const change of [{ code_challenge_methods_supported: ['plain'] }, { response_types_supported: ['token'] }, { id_token_signing_alg_values_supported: ['none'] }, { token_endpoint_auth_methods_supported: ['none'] }]) assert.throws(() => validateProductionDiscovery(policy, { ...metadata(policy), ...change }), /denied/);
});

test('policy requires HTTPS, exact callback, explicit access scope and meaningful MFA', () => {
  for (const change of [
    { issuer: 'http://identity.example.test/tenant' }, { issuer: 'https://user:pass@identity.example.test/tenant' }, { issuer: 'https://identity.example.test/tenant?x=1' },
    { authorizationEndpoint: 'http://login.example.test' }, { authorizationEndpoint: 'https://login.example.test/oauth2/authorize?redirect_uri=https://attacker.test' }, { tokenEndpoint: 'https://login.example.test/#fragment' },
    { workspaceOrigin: 'https://workspace.example.test/path' }, { redirectURI: 'https://other.example.test/auth/callback' },
    { authorizationScopes: ['openid'] }, { authorizationScopes: ['openid', 'api:access', 'api:access'] },
    { allowedAcr: [], requiredAmr: [] }, { allowedAcr: [], requiredAmr: ['pwd'] }, { allowedAcr: [], requiredAmr: ['otp', 'sms'] },
    { maxAuthAgeSeconds: 0 }, { maxAuthAgeSeconds: 86401 }, { clientId: '' }, { unexpectedOption: true },
  ]) assert.throws(() => createProductionOidcPolicy({ ...inputs(), ...change }), /invalid/);
  assert.ok(createProductionOidcPolicy({ ...inputs(), allowedAcr: [], requiredAmr: ['pwd', 'otp'] }));
  assert.ok(createProductionOidcPolicy({ ...inputs(), allowedAcr: [], requiredAmr: ['mfa'] }));
});

test('assurance, expiry and current authority must all match', () => {
  const policy = createProductionOidcPolicy(inputs());
  for (const change of [
    { iss: 'https://other.example.test' }, { sub: 'bob' }, { sub: '' }, { sub: ' alice' },
    { exp: 1700000000 }, { iat: 1700000031 }, { iat: 0 }, { auth_time: 1699999399 }, { auth_time: 1700000031 },
    { acr: 'weak' }, { amr: ['pwd'] }, { amr: ['pwd', 'otp', 'otp'] }, { amr: 'pwd otp' }, { auth_time: '1699999999' },
  ]) assert.throws(() => validateVerifiedProductionIdentity(policy, { ...claims(), ...change }, actor(), 1700000000), /denied/);
  for (const change of [{ issuer: 'https://other.example.test' }, { subject: 'bob' }, { user_id: '' }, { tenant_id: '' }, { delegation_id: null }, { permissions: ['document.read', 1] }, { permissions: ['document.read', 'document.read'] }]) {
    assert.throws(() => validateVerifiedProductionIdentity(policy, claims(), { ...actor(), ...change }, 1700000000), /denied/);
  }
});
