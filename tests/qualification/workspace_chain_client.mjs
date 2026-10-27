// Invoked only by the independent Go integration harness with ephemeral PKI.
import assert from 'node:assert/strict';
import dns from 'node:dns';
import { createRequire } from 'node:module';
const require = createRequire(new URL('../../apps/workspace/package.json', import.meta.url));
require('reflect-metadata');
const nativeLookup = dns.lookup;
dns.lookup = function(hostname, options, callback) {
  if (hostname !== 'control') return nativeLookup.apply(this, arguments);
  if (typeof options === 'function') { callback = options; options = {}; }
  queueMicrotask(() => options?.all ? callback(null, [{address:'127.0.0.1',family:4}]) : callback(null,'127.0.0.1',4));
};
const { verifiedRequest } = await import('../../apps/workspace/lib/trust.ts');
const base = new URL(process.env.CONTROL_URL);
const positive = await verifiedRequest(new URL('/positive',base),'control');
assert.equal(positive.status,200);
assert.equal(await positive.text(),'positive');
await assert.rejects(verifiedRequest(new URL('/held',base),'control'));
console.log('Workspace native PKIX positive and held intermediate expiry rejection passed.');
