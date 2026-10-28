// Coordinator-authorized settlement of one existing synthetic test request.
// Uses real independent Carol approval and Alice result reads; no SQL reset,
// fabricated completion, new job, or replacement export is permitted.
import assert from 'node:assert/strict';
import {readFile, writeFile} from 'node:fs/promises';
import {budget, historyPage} from './acceptance.mjs';
import {login, responseFor, snapshot} from './workflow-fixture.mjs';

const {chromium} = await import(process.env.NEX_PLAYWRIGHT_MODULE || '/fixture/node_modules/playwright-core/index.mjs');
const args = Object.fromEntries(process.argv.slice(2).map(value => {const [key, ...rest] = value.replace(/^--/, '').split('='); return [key, rest.join('=')];}));
const base = args['base-url'] || 'https://workspace.nex.test:9443';
const result = {schema: 1, scope: 'coordinator-authorized existing synthetic request settlement; not candidate qualification', stage: 'initialization'};
let browser, page;
try {
  const job = (await readFile(args['job-file'] || '/input/job-reference', 'utf8')).trim();
  assert(/^[A-Za-z0-9_-]{8,100}$/.test(job));
  browser = await chromium.connectOverCDP('http://127.0.0.1:9222');
  const context = await browser.newContext();
  page = await context.newPage();
  page.setDefaultTimeout(15000);
  await page.goto(base + '/workflow');
  result.stage = 'independent approver login';
  await login(page, 'carol');
  await page.getByRole('button', {name:'Refresh approvals',exact:true}).click();
  const approval = page.locator('#approvals .model').filter({hasText:job});
  await approval.getByRole('heading', {name:'Exact request digest',exact:true}).waitFor();
  assert.equal(await approval.count(),1);
  await approval.getByRole('heading', {name:/^pending · local-evidence$/}).waitFor();
  await approval.getByRole('heading', {name:'Requested by alice · review-alice@v1',exact:true}).waitFor();
  assert.match(await approval.innerText(),/SYNTHETIC/);
  const codes = await approval.locator('code').allTextContents();
  assert(codes.includes(job));
  assert.equal(codes.filter(value=>/^[a-f0-9]{64}$/.test(value)).length,1);
  result.stage = 'approve inspected exact request';
  const decision = page.waitForResponse(responseFor('decide'));
  await approval.getByRole('button', {name:'Approve this exact export',exact:true}).click();
  assert.equal((await decision).status(),200);
  result.independentExactApproval = true;
  await page.getByRole('button', {name:'Sign out',exact:true}).click();
  await page.getByRole('link', {name:'Sign in →'}).waitFor();
  result.stage = 'requester observes existing export';
  await login(page,'alice');
  await page.getByPlaceholder('Job reference').fill(job);
  await page.getByRole('button', {name:'Load job and evidence',exact:true}).click();
  await page.getByRole('heading', {name:'Controlled local export',exact:true}).waitFor({timeout:45000});
  assert.equal(await page.getByTestId('current-job-id').textContent(),job);
  assert.equal(await page.locator('.effect').textContent(),'completed');
  await page.locator('#evidence [role="status"]').filter({hasText:/history records loaded/}).waitFor();
  for(let pages=0;await page.getByRole('button',{name:'Load more history',exact:true}).count();pages++){
    assert(pages<budget.maxHistoryPages);
    const loaded=await page.locator('#evidence [data-event-id]').count();
    const pending=page.waitForResponse(responseFor('event_page',job));
    await page.getByRole('button',{name:'Load more history',exact:true}).click();
    const response=await pending;assert.equal(response.status(),200);
    const raw=await response.body();const value=historyPage(JSON.parse(raw.toString()),raw.length);
    await page.waitForFunction(count=>document.querySelectorAll('#evidence [data-event-id]').length===count,loaded+value.events.length);
  }
  await page.locator('#evidence').getByText('export.authorized',{exact:true}).waitFor();
  result.history={};
  const history=await snapshot(page,job,result.history);
  assert(history.events.some(event=>event.action==='export.authorized'));
  result.exportObserved=true;
  result.stage='complete';
  result.status='completed-existing-synthetic-export';
}catch{result.status='failed';result.failure='EXISTING_REQUEST_SETTLEMENT_FAILED';process.exitCode=1;}
finally{
  if(page){try{await page.getByRole('button',{name:'Sign out',exact:true}).click({timeout:3000});await page.getByRole('link',{name:'Sign in →'}).waitFor({timeout:3000});result.signedOut=true;}catch{result.signedOut=false;}}
  await writeFile(args.output||'/results/browser-results.json',JSON.stringify(result,null,2)+'\n',{mode:0o600});
  if(browser)await browser.close();
  console.log(JSON.stringify(result));
}
