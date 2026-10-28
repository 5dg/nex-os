// Narrow diagnostic only: no login or application workflow is attempted.
import assert from 'node:assert/strict';
import {writeFile} from 'node:fs/promises';
import {listenerProbe, navigationProbe} from './tls-diagnostics.mjs';

const {chromium} = await import(process.env.NEX_PLAYWRIGHT_MODULE || '/fixture/node_modules/playwright-core/index.mjs');
const args = Object.fromEntries(process.argv.slice(2).map(value => {const [key, ...rest] = value.replace(/^--/, '').split('='); return [key, rest.join('=')];}));
assert(args['wrong-ca-url']);
const endpoints = {
  wrongRoot: args['wrong-ca-url'],
  workspace: (args['base-url'] || 'https://workspace.nex.test:9443') + '/workflow',
  issuer: 'https://issuer.nex.test:9444/.well-known/openid-configuration',
};
const result = {schema: 1, scope: 'diagnostic native-browser TLS probe only; no login, workflow or canonical qualification', probes: {}};
let browser;
try {
  browser = await chromium.connectOverCDP('http://127.0.0.1:9222');
  result.engine = browser.version();
  const context = await browser.newContext();
  for (const [name, endpoint] of Object.entries(endpoints)) {
    const page = await context.newPage();
    result.probes[name] = {listener: await listenerProbe(endpoint), navigation: await navigationProbe(page, endpoint)};
    await page.close();
  }
  result.status = result.probes.wrongRoot.navigation.code === 'ERR_CERT_AUTHORITY_INVALID'
    && result.probes.workspace.navigation.status === 200 && result.probes.issuer.navigation.status === 200 ? 'passed' : 'failed';
  if (result.status !== 'passed') process.exitCode = 1;
  await context.close();
} catch {result.status = 'failed'; result.failure = 'TLS_PROBE_UNAVAILABLE'; process.exitCode = 1;}
finally {
  await writeFile(args.output || '/results/browser-results.json', JSON.stringify(result, null, 2) + '\n', {mode: 0o600});
  if (browser) await browser.close();
  console.log(JSON.stringify(result));
}
