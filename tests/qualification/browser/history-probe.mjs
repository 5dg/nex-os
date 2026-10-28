// Diagnostic only: inspect an existing synthetic job's signed history and native
// Node/Playwright trust. The private job reference is never written to results.
import {readFile, writeFile} from 'node:fs/promises';
import https from 'node:https';
import {login, snapshot} from './workflow-fixture.mjs';

const {chromium} = await import(process.env.NEX_PLAYWRIGHT_MODULE || '/fixture/node_modules/playwright-core/index.mjs');
const args = Object.fromEntries(process.argv.slice(2).map(value => {const [key, ...rest] = value.replace(/^--/, '').split('='); return [key, rest.join('=')];}));
const base = args['base-url'] || 'https://workspace.nex.test:9443';
const result = {schema: 1, scope: 'diagnostic existing-job history and fixture trust only; no new job or candidate qualification', stage: 'initialization', history: {}};
const knownTLS = ['UNABLE_TO_VERIFY_LEAF_SIGNATURE','SELF_SIGNED_CERT_IN_CHAIN','DEPTH_ZERO_SELF_SIGNED_CERT','CERT_HAS_EXPIRED','ERR_TLS_CERT_ALTNAME_INVALID','ECONNREFUSED','ENOTFOUND','ETIMEDOUT'];
function typedTLS(error) {
  if (knownTLS.includes(error?.code)) return error.code;
  const text = String(error?.message || '');
  if (/unable to verify (?:the first certificate|leaf signature)/i.test(text)) return 'UNABLE_TO_VERIFY_LEAF_SIGNATURE';
  if (/self.signed certificate/i.test(text)) return 'SELF_SIGNED_CERT_IN_CHAIN';
  if (/certificate has expired/i.test(text)) return 'CERT_HAS_EXPIRED';
  return 'UNCLASSIFIED_REQUEST_FAILURE';
}
let browser, page;
try {
  const job = (await readFile(args['job-file'] || '/input/job-reference', 'utf8')).trim();
  if (!/^[A-Za-z0-9_-]{8,100}$/.test(job)) throw new Error('Private synthetic job reference required');
  result.stage = 'node public status trust';
  result.nodeTrust = await new Promise(resolve => {
    const request = https.get(base + '/api/status', {timeout: 5000}, response => {response.resume(); resolve({status: response.statusCode});});
    request.on('timeout', () => request.destroy(Object.assign(new Error('request budget'), {code:'ETIMEDOUT'})));
    request.on('error', error => resolve({code:typedTLS(error)}));
  });
  browser = await chromium.connectOverCDP('http://127.0.0.1:9222');
  result.engine = browser.version();
  const context = await browser.newContext();
  result.stage = 'playwright public status trust';
  try {const response = await context.request.get(base + '/api/status', {timeout:5000}); result.playwrightTrust = {status:response.status()};}
  catch(error) {result.playwrightTrust = {code:typedTLS(error)};}
  page = await context.newPage();
  page.setDefaultTimeout(10000);
  await page.goto(base + '/workflow');
  await login(page, 'alice');
  result.stage = 'existing signed history';
  await snapshot(page, job, result.history);
  result.stage = 'complete';
  result.status = 'diagnostic-complete';
} catch {result.status = 'failed'; result.failure = 'HISTORY_PROBE_ASSERTION_FAILED'; process.exitCode = 1;}
finally {
  if (page) {
    try {await page.getByRole('button', {name:'Sign out',exact:true}).click({timeout:3000}); await page.getByRole('link',{name:'Sign in →'}).waitFor({timeout:3000}); result.signedOut=true;}
    catch {result.signedOut=false;}
  }
  await writeFile(args.output || '/results/browser-results.json', JSON.stringify(result,null,2)+'\n', {mode:0o600});
  if (browser) await browser.close();
  console.log(JSON.stringify(result));
}
