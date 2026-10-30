// Local test-only control peer. The workspace still performs its normal mTLS,
// certificate-chain and workload-identity checks against this fixture.
import dns from 'node:dns';
import https from 'node:https';
import * as x509 from '@peculiar/x509';

export async function startControlFixture(t, root, rootKeys, actor, expectedToken) {
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const certificate = await x509.X509CertificateGenerator.create({ subject: 'CN=control', issuer: root.subject, publicKey: keys.publicKey, signingKey: rootKeys.privateKey, notBefore: new Date(Date.now() - 60_000), notAfter: new Date(Date.now() + 3600_000), extensions: [new x509.BasicConstraintsExtension(false), new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: 'control' }, { type: 'url', value: 'spiffe://nex.local/service/control' }]), new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth])] });
  const der = Buffer.from(await crypto.subtle.exportKey('pkcs8', keys.privateKey));
  const key = `-----BEGIN PRIVATE KEY-----\n${der.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;
  const state = { actor: { ...actor, permissions: [...actor.permissions] }, status: 200, body: undefined, drop: false, requests: [], gate: null };
  const server = https.createServer({ key, cert: certificate.toString('pem'), ca: root.toString('pem'), requestCert: true, rejectUnauthorized: true, minVersion: 'TLSv1.3' }, async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    state.requests.push({ method: req.method, path: req.url, authenticated: req.socket.authorized, tokenMatches: req.headers.authorization === `Bearer ${expectedToken}`, body: Buffer.concat(chunks).toString() });
    if (state.gate) await state.gate;
    if (!req.socket.authorized || req.headers.authorization !== `Bearer ${expectedToken}`) { res.writeHead(401); res.end(); return; }
    if (state.drop) { req.socket.destroy(); return; }
    res.writeHead(state.status, { 'content-type': 'application/json' });
    res.end(state.body === undefined ? JSON.stringify(state.actor) : state.body);
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const originalLookup = dns.lookup;
  dns.lookup = function(host, options, callback) {
    if (typeof options === 'function') { callback = options; options = {}; }
    if (host === 'control') {
      if (options?.all) return process.nextTick(callback, null, [{ address: '127.0.0.1', family: 4 }]);
      return process.nextTick(callback, null, '127.0.0.1', 4);
    }
    return originalLookup.call(dns, host, options, callback);
  };
  t.after(async () => { dns.lookup = originalLookup; await new Promise(resolve => server.close(resolve)); });
  return { state, url: `https://control:${server.address().port}` };
}
