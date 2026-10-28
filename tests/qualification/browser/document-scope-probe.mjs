// Diagnostic only: authenticate the synthetic fixture, inspect bounded boolean
// scope facts, then sign out. No job creation, approval or export is requested.
import {writeFile} from 'node:fs/promises';
import {login, responseFor} from './workflow-fixture.mjs';

const {chromium} = await import(process.env.NEX_PLAYWRIGHT_MODULE || '/fixture/node_modules/playwright-core/index.mjs');
const args = Object.fromEntries(process.argv.slice(2).map(value => {const [key, ...rest] = value.replace(/^--/, '').split('='); return [key, rest.join('=')];}));
const base = args['base-url'] || 'https://workspace.nex.test:9443';
const result = {schema: 1, scope: 'diagnostic document-selection facts only; no job or candidate qualification', facts: {}};
let browser, page;
try {
  browser = await chromium.connectOverCDP('http://127.0.0.1:9222');
  result.engine = browser.version();
  const context = await browser.newContext();
  page = await context.newPage();
  page.setDefaultTimeout(10000);
  result.facts.workspaceStatus = (await page.goto(base + '/workflow'))?.status() ?? null;
  const documents = page.waitForResponse(responseFor('documents'), {timeout: 10000}).then(response => response.status()).catch(() => null);
  await login(page, 'alice');
  result.facts.documentsResponseStatus = await documents;
  await page.locator('select option[value="review-alice"]').waitFor({state: 'attached', timeout: 3000}).catch(() => {});
  const facts = result.facts;
  facts.exactDocumentLabels = await page.getByLabel('Document', {exact: true}).count();
  facts.partialDocumentLabels = await page.getByLabel('Document', {exact: false}).count();
  facts.comboboxes = await page.getByRole('combobox').count();
  facts.documentPrefixComboboxes = await page.getByRole('combobox', {name: /^Document\b/}).count();
  facts.allowedOptionCount = await page.locator('select option[value="review-alice"]').count();
  facts.deniedOptionCount = await page.locator('select option[value="review-bob"]').count();
  facts.selectedAllowed = await page.locator('select').evaluateAll(selects => selects.some(select => select.value === 'review-alice'));
  facts.noArbitraryQuestion = (await page.locator('textarea').count()) === 0;
  facts.fixedQuestionVisible = await page.getByText('What access review and export controls apply?', {exact: false}).first().isVisible();
  facts.alertPresent = (await page.locator('main p[role="alert"]').count()) > 0;
  result.status = 'diagnostic-complete';
} catch {result.status = 'failed'; result.failure = 'DOCUMENT_SCOPE_PROBE_UNAVAILABLE'; process.exitCode = 1;}
finally {
  if (page) {
    try {
      await page.getByRole('button', {name: 'Sign out', exact: true}).click({timeout: 3000});
      await page.getByRole('link', {name: 'Sign in →'}).waitFor({timeout: 3000});
      result.signedOut = true;
    } catch {result.signedOut = false;}
  }
  await writeFile(args.output || '/results/browser-results.json', JSON.stringify(result, null, 2) + '\n', {mode: 0o600});
  if (browser) await browser.close();
  console.log(JSON.stringify(result));
}
