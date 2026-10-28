// Actual browser-engine DOM qualification; synthetic fixture identities only.
// No callback URLs, network bodies, cookies, credentials, HAR or trace are logged.
import assert from 'node:assert/strict';
import {writeFile} from 'node:fs/promises';
import {budget, exactHistoryPrefix, historyPage, pollingAcceptance, signedReadGrowthBound} from './acceptance.mjs';
import {requestInput, responseFor, snapshot} from './workflow-fixture.mjs';
const {chromium} = await import(process.env.NEX_PLAYWRIGHT_MODULE || '/fixture/node_modules/playwright-core/index.mjs');
const args = Object.fromEntries(process.argv.slice(2).map(value => {const [key,...rest]=value.replace(/^--/,'').split('=');return [key,rest.join('=')];}));
const base=args['base-url'] || 'https://workspace.nex.test:9443';
const output=args.output || '/results/browser-results.json';
assert.equal(new URL(base).protocol,'https:');
assert(args['wrong-ca-url'],'A real wrong-CA negative URL is required');
const result={schema:1,scope:'synthetic DOM workflow; no customer identity, CUI or compliance claim',assertions:[]};
let browser;
function passed(name,details={}) {result.assertions.push({name,status:'passed',...details});}
async function named(name,action){try{await action();passed(name);}catch{result.assertions.push({name,status:'failed'});throw new Error(name);}}
try {
 browser=await chromium.connectOverCDP('http://127.0.0.1:9222');
 result.engine=browser.version();
 if(process.env.NEX_BROWSER_BINARY_SHA256){assert.match(process.env.NEX_BROWSER_BINARY_SHA256,/^[a-f0-9]{64}$/);result.engineBinarySha256=process.env.NEX_BROWSER_BINARY_SHA256;}
 // A new browser context uses the platform/NSS trust prepared by the fixture.
 // There is intentionally no ignoreHTTPSErrors or certificate exception.
 const context=await browser.newContext();
 const page=await context.newPage();
 page.setDefaultTimeout(15000);
 await named('untrusted CA fails browser TLS validation',async()=>{const bad=await context.newPage();let rejected=false;try{await bad.goto(args['wrong-ca-url'],{timeout:8000});}catch(error){rejected=String(error).includes('ERR_CERT_AUTHORITY_INVALID');}await bad.close();assert(rejected);});
 await named('trusted TLS and rendered React workspace',async()=>{const r=await page.goto(base+'/workflow');assert.equal(r.status(),200);await page.getByRole('heading',{name:'One workflow. Accountable actions.'}).waitFor();await page.getByRole('link',{name:'Sign in →'}).waitFor();});
 async function login(subject){await page.getByRole('link',{name:'Sign in →'}).click();await page.getByLabel('Username',{exact:true}).fill(subject);await page.getByLabel('Password',{exact:true}).fill('fixture-'+subject+'-password');await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.getByText('Signed in as',{exact:false}).waitFor();assert.equal(await page.locator('strong').filter({hasText:subject}).count(),1);}
 await named('OIDC login via rendered fixture and callback',()=>login('alice'));
 await named('document scope and fixed question rendered',async()=>{const documents=page.getByLabel('Document',{exact:true});await documents.locator('option[value="review-alice"]').waitFor();assert.equal(await documents.locator('option[value="review-bob"]').count(),0);assert.equal(await page.locator('textarea').count(),0);await page.getByText('What access review and export controls apply?',{exact:false}).first().waitFor();});
 let job;
 await named('DOM review submit and durable completion',async()=>{await page.getByRole('button',{name:'Start governed review →'}).click();await page.locator('.effect').filter({hasText:/^completed$/}).waitFor({timeout:45000});job=await page.getByPlaceholder('Job reference').inputValue();assert(job);});
 await named('DOM exact export approval request',async()=>{await page.getByRole('button',{name:'Request export approval',exact:true}).click();await page.locator('.effect').filter({hasText:/^approval_required$/}).waitFor();});
 if(args['measure-polling']==='true') {
  let auditedAttempts=0;
  const countReads=request=>{const input=requestInput(request);if(input?.id===job&&['job','event_page'].includes(input.operation))auditedAttempts++;};
  page.on('request',countReads);
  const before=await snapshot(page,job);
  let active=0,maxActive=0,completed=0,errors=0;const attempts=[];const started=Date.now();
  const routePattern=base+'/api/workflow';
  const delayed=async route=>{const body=requestInput(route.request());if(body?.operation!=='job'||body.id!==job){await route.continue();return;}attempts.push(Date.now()-started);active++;maxActive=Math.max(maxActive,active);try{const response=await route.fetch();if(!response.ok())errors++;await new Promise(resolve=>setTimeout(resolve,budget.responseDelayMs));await route.fulfill({response});completed++;}catch{errors++;}finally{active--;}};
  await page.route(routePattern,delayed);
  await page.waitForTimeout(budget.observationMs);
  const drainStarted=Date.now();let drainTimer;
  try{await Promise.race([page.unrouteAll({behavior:'wait'}),new Promise((_,reject)=>{drainTimer=setTimeout(()=>reject(new Error('poll drain budget exceeded')),budget.drainMs);})]);}finally{clearTimeout(drainTimer);}
  const drainMs=Date.now()-drainStarted;
  const after=await snapshot(page,job);
  page.off('request',countReads);
  exactHistoryPrefix(before.events,after.events);
  const reads=events=>events.filter(event=>event.action==='document.read').length;
  result.polling={delayMs:budget.responseDelayMs,observedMs:budget.observationMs,drainBudgetMs:budget.drainMs,drainMs,maxConcurrentJobResponses:maxActive,attempts:attempts.length,attemptOffsetsMs:attempts,completedJobReads:completed,errors,auditedAttempts,signedReadEventsBefore:reads(before.events),signedReadEventsAfter:reads(after.events),signedReadGrowth:reads(after.events)-reads(before.events),signedReadGrowthBound:signedReadGrowthBound(auditedAttempts),measurementPageReads:before.pages+after.pages,historyPrefixPreserved:true,scope:'actual authorized API reads and bounded browser response latency; every measurement page is included in the request-derived audit bound'};
  pollingAcceptance(result.polling);
  passed('single-flight healthy polling and bounded signed-read growth');
 }
 await named('DOM sign out removes requester session' ,async()=>{await page.getByRole('button',{name:'Sign out',exact:true}).click();await page.getByRole('link',{name:'Sign in →'}).waitFor();});
 await named('independent approver OIDC login',()=>login('carol'));
 let digest;
 await named('exact preview and bound digest visible to approver',async()=>{await page.getByRole('button',{name:'Refresh approvals',exact:true}).click();const approval=page.locator('#approvals .model').filter({hasText:job});await approval.getByRole('heading',{name:'Exact request digest',exact:true}).waitFor();await approval.getByRole('heading',{name:/Requested by alice · review-alice@v1/}).waitFor();const codes=await approval.locator('code').allTextContents();digest=codes.find(x=>/^[a-f0-9]{64}$/.test(x));assert(digest);assert.match(await approval.innerText(),/SYNTHETIC/);await approval.getByRole('button',{name:'Approve this exact export',exact:true}).click();});
 await named('requester resumes job and observes controlled export',async()=>{
  await page.getByRole('button',{name:'Sign out',exact:true}).click();await page.getByRole('link',{name:'Sign in →'}).waitFor();await login('alice');await page.getByPlaceholder('Job reference').fill(job);await page.getByRole('button',{name:'Load job and evidence',exact:true}).click();await page.getByRole('heading',{name:'Controlled local export',exact:true}).waitFor({timeout:45000});
  // Terminal job state may render before its first history page arrives.
  await page.locator('#evidence [role="status"]').filter({hasText:/history records loaded/}).waitFor();
  for(let pages=0;await page.getByRole('button',{name:'Load more history',exact:true}).count();pages++){
   assert(pages<budget.maxHistoryPages);const loaded=await page.locator('#evidence [data-event-id]').count();const pending=page.waitForResponse(responseFor('event_page',job));await page.getByRole('button',{name:'Load more history',exact:true}).click();const response=await pending;assert.equal(response.status(),200);const raw=await response.body();const value=historyPage(JSON.parse(raw.toString()),raw.length);await page.waitForFunction(count=>document.querySelectorAll('#evidence [data-event-id]').length===count,loaded+value.events.length);
  }
  await page.locator('#evidence').getByText('export.authorized',{exact:true}).waitFor();assert((await page.locator('#evidence .good').count())>0);
 });
 // No identifiers or digest contents are emitted: evidence system retains them.
 result.status='passed';
 await context.close();
} catch(error) {result.status='failed';result.failure='Browser qualification assertion failed; no sensitive diagnostics emitted';process.exitCode=1;}
finally {await writeFile(output,JSON.stringify(result,null,2)+'\n',{mode:0o600});if(browser)await browser.close();console.log(JSON.stringify({status:result.status,assertions:result.assertions.length,engine:result.engine}));}
