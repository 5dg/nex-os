// Actual React regressions using real authorized synthetic jobs and signed reads.
// Network faults delay or fail a response; they never fabricate a protected job.
import assert from 'node:assert/strict';
import {writeFile} from 'node:fs/promises';
import {budget, exactHistoryPrefix, historyPage, verifiedEvents} from './acceptance.mjs';
import {login, requestInput, responseFor, snapshot, workflowCall} from './workflow-fixture.mjs';

const {chromium} = await import(process.env.NEX_PLAYWRIGHT_MODULE || '/fixture/node_modules/playwright-core/index.mjs');
const args = Object.fromEntries(process.argv.slice(2).map(value => {const [key, ...rest] = value.replace(/^--/, '').split('='); return [key, rest.join('=')];}));
const base = args['base-url'] || 'https://workspace.nex.test:9443';
const output = args.output || '/results/browser-results.json';
assert.equal(new URL(base).protocol, 'https:');
const result = {schema: 1, scope: 'synthetic operator DOM regressions; genuine signed history; no protected-row fabrication', assertions: []};
let browser;
async function named(name, action) {
  try { await action(); result.assertions.push({name, status: 'passed'}); }
  catch { result.assertions.push({name, status: 'failed'}); throw new Error(name); }
}

try {
  browser = await chromium.connectOverCDP('http://127.0.0.1:9222');
  result.engine = browser.version();
  const context = await browser.newContext();
  const page = await context.newPage();
  page.setDefaultTimeout(15000);
  await page.goto(base + '/workflow');
  await login(page, 'alice');
  const documents = page.getByRole('combobox', {name: /^Document\b/});
  assert.equal(await documents.count(), 1);
  await documents.locator('option[value="review-alice"]').waitFor({state: 'attached'});
  assert.equal(await documents.locator('option[value="review-alice"]').count(), 1);
  assert.equal(await documents.inputValue(), 'review-alice');
  assert.equal(await documents.locator('option[value="review-bob"]').count(), 0);
  const jobInput = page.getByPlaceholder('Job reference');
  const load = page.getByRole('button', {name: 'Load job and evidence', exact: true});
  const displayedJob = page.getByTestId('current-job-id');
  async function create() {
    const pending = page.waitForResponse(responseFor('create'));
    await page.getByRole('button', {name: 'Start governed review →', exact: true}).click();
    const response = await pending;
    assert.equal(response.status(), 202);
    const created = await response.json();
    assert.equal(typeof created.id, 'string');
    await page.waitForFunction(id => document.querySelector('[data-testid="current-job-id"]')?.textContent === id, created.id);
    await page.locator('.effect').filter({hasText: /^completed$/}).waitFor({timeout: 45000});
    assert.equal(await jobInput.inputValue(), created.id);
    return created.id;
  }
  const first = await create();
  const second = await create();
  assert(first && second && first !== second);
  const routePattern = base + '/api/workflow';

  await named('terminal jobs stop automatic reads', async () => {
    let reads = 0;
    const observe = request => {const input = requestInput(request); if (input?.operation === 'job' && input.id === second) reads++;};
    // Drain the terminal transition's initial history request before observing.
    await page.waitForTimeout(250);
    page.on('request', observe);
    await page.waitForTimeout(2500);
    page.off('request', observe);
    assert.equal(reads, 0);
  });

  await named('history failure preserves newly loaded current job and can recover', async () => {
    const failHistory = async route => {
      const input = requestInput(route.request());
      if (input?.operation === 'event_page' && input.id === first) {
        await route.fulfill({status: 503, contentType: 'application/json', body: JSON.stringify({code: 'DEPENDENCY_UNAVAILABLE', message: 'Synthetic history dependency unavailable.'})});
      } else await route.continue();
    };
    await page.route(routePattern, failHistory);
    await jobInput.fill(first);
    await load.click();
    await page.waitForFunction(id => document.querySelector('[data-testid="current-job-id"]')?.textContent === id, first);
    assert.equal(await displayedJob.textContent(), first);
    await page.locator('#evidence [role="alert"]').waitFor();
    await page.unroute(routePattern, failHistory);
    await page.getByRole('button', {name: 'Refresh history', exact: true}).click();
    await page.locator('#evidence code').first().waitFor();
    assert.equal(await page.locator('#evidence [role="alert"]').count(), 0);
  });

  await named('old delayed job response cannot overwrite a newly selected job', async () => {
    let release;
    const held = new Promise(resolve => {release = resolve;});
    let admit;
    const admitted = new Promise(resolve => {admit = resolve;});
    let delayed = false;
    let delivered;
    const finished = new Promise(resolve => {delivered = resolve;});
    const delayOld = async route => {
      const input = requestInput(route.request());
      if (input?.operation !== 'job' || input.id !== first || delayed) {await route.continue(); return;}
      delayed = true;
      try {
        const response = await route.fetch();
        assert.equal(response.status(), 200);
        admit();
        await held;
        await route.fulfill({response});
      } catch {
        // A genuine aborted stale read is expected; no application write follows.
      } finally {delivered();}
    };
    await page.route(routePattern, delayOld);
    try {
      await jobInput.fill(first);
      await load.click();
      await Promise.race([admitted, new Promise((_, reject) => setTimeout(() => reject(new Error('old request not held')), 10000))]);
      await jobInput.fill(second);
      await load.click();
      await page.waitForFunction(id => document.querySelector('[data-testid="current-job-id"]')?.textContent === id, second);
      await page.evaluate(() => {
        window.__nexObservedJobWrites = [];
        const current = () => document.querySelector('[data-testid="current-job-id"]')?.textContent;
        window.__nexJobObserver = new MutationObserver(() => window.__nexObservedJobWrites.push(current()));
        window.__nexJobObserver.observe(document.querySelector('main'), {childList: true, subtree: true, characterData: true});
      });
      release();
      await finished;
      await page.waitForTimeout(250);
      const obsolete = await page.evaluate(id => {window.__nexJobObserver.disconnect(); return window.__nexObservedJobWrites.filter(value => value && value !== id).length;}, second);
      assert.equal(obsolete, 0);
      assert.equal(await displayedJob.textContent(), second);
      result.obsoleteJobWrites = obsolete;
    } finally {release(); await page.unroute(routePattern, delayOld);}
  });

  await named('large signed history traverses bounded stable pages and renders completely', async () => {
    let before = await snapshot(page, second);
    const original = before.events;
    let fixtureReads = 0;
    const until = Date.now() + 90000;
    while (before.bytes <= budget.legacyHistoryBytes) {
      assert(fixtureReads < budget.maxFixtureReads && Date.now() < until, 'signed history fixture budget exceeded');
      for (let i = 0; i < 16; i++) {
        const response = await workflowCall(page, {operation: 'job', id: second});
        assert.equal(response.status, 200);
        fixtureReads++;
      }
      before = await snapshot(page, second);
    }
    exactHistoryPrefix(original, before.events);
    // The previous snapshot is now larger than the whole BFF response bound.
    // Load it through rendered controls, retaining each bounded API page exactly.
    const rendered = [];
    const seenCursors = new Set();
    let pages = 0;
    const nextPage = async action => {
      const pending = page.waitForResponse(responseFor('event_page', second));
      await action();
      const response = await pending;
      assert.equal(response.status(), 200);
      const body = await response.body();
      const value = historyPage(JSON.parse(body.toString()), body.length);
      rendered.push(...value.events);
      pages++;
      assert(pages <= budget.maxHistoryPages);
      if (value.next_cursor) {
        assert(!seenCursors.has(value.next_cursor));
        seenCursors.add(value.next_cursor);
      }
      await page.waitForFunction(count => document.querySelectorAll('#evidence code').length === count, rendered.length);
      return value.next_cursor;
    };
    await jobInput.fill(second);
    let cursor = await nextPage(() => load.click());
    while (cursor) cursor = await nextPage(() => page.getByRole('button', {name: 'Load more history', exact: true}).click());
    verifiedEvents(rendered);
    exactHistoryPrefix(before.events, rendered);
    assert.deepEqual(await page.locator('#evidence code').allTextContents(), rendered.map(event => event.event_id));
    assert.equal(await page.getByRole('button', {name: 'Load more history', exact: true}).count(), 0);
    assert.equal(await displayedJob.textContent(), second);
    result.history = {fixtureReads, signedSnapshotBytes: before.bytes, renderedEvents: rendered.length, pages, maxPageBytes: budget.historyPageBytes, stableSnapshotFinished: true, exactOrderedPrefixPreserved: true};
  });

  await named('logout invalidates an in-flight history response and clears private state', async () => {
    let release, admit, finish;
    const hold = new Promise(resolve => {release = resolve;});
    const admitted = new Promise(resolve => {admit = resolve;});
    const finished = new Promise(resolve => {finish = resolve;});
    let delayed = false;
    const delayHistory = async route => {
      const input = requestInput(route.request());
      if (input?.operation !== 'event_page' || input.id !== second || delayed) {await route.continue(); return;}
      delayed = true;
      try {
        const response = await route.fetch();
        assert.equal(response.status(), 200);
        admit();
        await hold;
        await route.fulfill({response});
      } catch {
        // Logout may abort delivery after the real authorized read completed.
      } finally {finish();}
    };
    await page.route(routePattern, delayHistory);
    try {
      await page.getByRole('button', {name: 'Refresh history', exact: true}).click();
      await Promise.race([admitted, new Promise((_, reject) => setTimeout(() => reject(new Error('history request not held')), 10000))]);
      await page.getByRole('button', {name: 'Sign out', exact: true}).click();
      await page.getByRole('link', {name: 'Sign in →'}).waitFor();
      release();
      await finished;
      await page.waitForTimeout(250);
      assert.equal(await page.getByTestId('current-job-id').count(), 0);
      assert.equal(await page.locator('#evidence code').count(), 0);
      assert.equal(await page.locator('main p[role="alert"]').count(), 0);
    } finally {release(); await page.unroute(routePattern, delayHistory);}
  });
  result.status = 'passed';
  await context.close();
} catch {result.status = 'failed'; result.failure = 'Operator browser acceptance failed; no private diagnostics emitted'; process.exitCode = 1;}
finally {
  await writeFile(output, JSON.stringify(result, null, 2) + '\n', {mode: 0o600});
  if (browser) await browser.close();
  console.log(JSON.stringify({status: result.status, assertions: result.assertions.length, engine: result.engine}));
}
