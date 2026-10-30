// Isolated test adapter serving the real workspace route handlers. This is not
// a Next.js runtime and never belongs in a deployment image.
import dns from 'node:dns';
import https from 'node:https';
import { readFileSync } from 'node:fs';
if (process.env.NEX_SYNTHETIC_OIDC_WORKER !== 'yes' || process.env.NEX_PROFILE !== 'synthetic-qualification' || process.env.APP_ENV !== 'development') throw new Error('synthetic worker only');
const originalLookup = dns.lookup;
dns.lookup = function(host, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  if (host === 'issuer.nex.test' || host === 'control' || host === 'workspace.nex.test') {
    if (options?.all) return process.nextTick(callback, null, [{ address: '127.0.0.1', family: 4 }]);
    return process.nextTick(callback, null, '127.0.0.1', 4);
  }
  return originalLookup.call(dns, host, options, callback);
};
const { sessions } = await import('../lib/sessions.ts');
const { workspaceConfig } = await import('../lib/trust.ts');
const { configuredProductionOidcPolicy } = await import('../lib/production-oidc-config.ts');
const { GET: login } = await import('../app/auth/login/route.ts');
const { GET: callback } = await import('../app/auth/callback/route.ts');
const { GET: view } = await import('../app/api/session/route.ts');
const { POST: logout } = await import('../app/auth/logout/route.ts');
const config = workspaceConfig();
configuredProductionOidcPolicy(config);
const store = sessions();
if (!('readiness' in store)) throw new Error('Postgres fixture required');
await store.readiness();
const routes = { 'GET /auth/login': login, 'GET /auth/callback': callback, 'GET /api/session': view, 'POST /auth/logout': logout };
const server = https.createServer({ key: readFileSync(process.env.NEX_TLS_KEY_FILE), cert: readFileSync(process.env.NEX_TLS_CERT_FILE), minVersion: 'TLSv1.3' }, async (request, response) => {
  try {
    const key = `${request.method} ${new URL(request.url, config.origin).pathname}`;
    const route = routes[key];
    if (!route) { response.writeHead(404); response.end(); return; }
    const incoming = new Request(new URL(request.url, config.origin), { method: request.method, headers: request.headers });
    const result = await route(incoming);
    response.statusCode = result.status;
    for (const [name, value] of result.headers) if (name !== 'set-cookie') response.setHeader(name, value);
    const cookies = result.headers.getSetCookie(); if (cookies.length) response.setHeader('set-cookie', cookies);
    response.end(Buffer.from(await result.arrayBuffer()));
  } catch { response.writeHead(500); response.end('fixture handler error'); }
});
await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
process.send?.({ ready: true, port: server.address().port });
process.on('message', async message => {
  if (message === 'seed-legacy') {
    const actor = { issuer: config.issuerText, subject: 'alice', user_id: 'alice', tenant_id: 'tenant', delegation_id: 'delegation', permissions: ['document.read'] };
    const value = await store.open(actor, 'synthetic-legacy-token', Date.now() + 60_000, Date.now() + 60_000);
    process.send?.({ legacy: { id: value.id, csrf: value.csrf } });
  }
  if (message === 'stop') {
    server.close(); process.disconnect?.();
  }
});
