// Actual browser-engine DOM qualification; synthetic fixture identities only.
// No callback URLs, network bodies, cookies, credentials, HAR or trace are logged.
import assert from 'node:assert/strict';
import {writeFile} from 'node:fs/promises';
import {budget, exactHistoryPrefix, historyPage, pollingAcceptance, signedReadGrowthBound} from './acceptance.mjs';
import {requestInput, responseFor, snapshot} from './workflow-fixture.mjs';
import {listenerProbe, navigationProbe, requestTLSFailure} from './tls-diagnostics.mjs';
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
 page.on('response',response=>{if(requestInput(response.request())?.operation==='documents')result.documentsResponseStatus=response.status();});
 page.setDefaultTimeout(15000);
 await named('untrusted CA fails browser TLS validation',async()=>{
  const bad=await context.newPage();
  result.wrongRoot={listener:await listenerProbe(args['wrong-ca-url']),navigation:await navigationProbe(bad,args['wrong-ca-url'])};
  await bad.close();
  assert.equal(result.wrongRoot.listener.tcp,'connected');
  assert.equal(result.wrongRoot.navigation.code,'ERR_CERT_AUTHORITY_INVALID');
 });
 await named('request client accepts intended and rejects foreign fixture root',async()=>{
  result.requestTrust={};
  try{const positive=await context.request.get(base+'/api/status',{timeout:8000});result.requestTrust.intendedRootStatus=positive.status();}
  catch(error){result.requestTrust.intendedRootCode=requestTLSFailure(error);}
  try{const negative=await context.request.get(args['wrong-ca-url'],{timeout:8000});result.requestTrust.foreignRootStatus=negative.status();}
  catch(error){result.requestTrust.foreignRootCode=requestTLSFailure(error);}
  assert.equal(result.requestTrust.intendedRootStatus,200);
  assert(['UNABLE_TO_VERIFY_LEAF_SIGNATURE','SELF_SIGNED_CERT_IN_CHAIN','DEPTH_ZERO_SELF_SIGNED_CERT','UNABLE_TO_GET_ISSUER_CERT_LOCALLY'].includes(result.requestTrust.foreignRootCode));
 });
 await named('trusted TLS and rendered React workspace',async()=>{const r=await page.goto(base+'/workflow');assert.equal(r.status(),200);await page.getByRole('heading',{name:'One workflow. Accountable actions.'}).waitFor();await page.getByRole('link',{name:'Sign in →'}).waitFor();});
 async function login(subject){await page.getByRole('link',{name:'Sign in →'}).click();await page.getByLabel('Username',{exact:true}).fill(subject);await page.getByLabel('Password',{exact:true}).fill('fixture-'+subject+'-password');await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.getByText('Signed in as',{exact:false}).waitFor();assert.equal(await page.locator('strong').filter({hasText:subject}).count(),1);}
 await named('OIDC login via rendered fixture and callback',()=>login('alice'));
 await named('document scope and fixed question rendered',async()=>{
  const documents=page.getByRole('combobox',{name:/^Document\b/});
  try {
   // Options in a collapsed native select are attached but not individually
   // visible. Verify admitted data and selection without opening the popup.
   assert.equal(await documents.count(),1);
   await documents.locator('option[value="review-alice"]').waitFor({state:'attached'});
   assert.equal(await documents.locator('option[value="review-alice"]').count(),1);
   assert.equal(await documents.inputValue(),'review-alice');
   assert.equal(await documents.locator('option[value="review-bob"]').count(),0);
   assert.equal(await page.locator('textarea').count(),0);
   await page.getByText('What access review and export controls apply?',{exact:false}).first().waitFor();
  } finally {
   // A missing accessible-name match must not make the diagnostics themselves
   // wait or throw. Counts/evaluateAll return immediately for absent elements.
   const scope=result.documentScope={};
   scope.exactDocumentLabels=await page.getByLabel('Document',{exact:true}).count();
   scope.partialDocumentLabels=await page.getByLabel('Document',{exact:false}).count();
   scope.documentPrefixComboboxes=await documents.count();
   scope.selectCount=await page.locator('select').count();
   scope.allowedOptionAttached=(await page.locator('select option[value="review-alice"]').count())===1;
   scope.selectedAllowed=await page.locator('select').evaluateAll(selects=>selects.some(select=>select.value==='review-alice'));
   scope.deniedOptionAbsent=(await page.locator('select option[value="review-bob"]').count())===0;
   scope.noArbitraryQuestion=(await page.locator('textarea').count())===0;
   scope.fixedQuestionVisible=await page.getByText('What access review and export controls apply?',{exact:false}).first().isVisible();
   scope.alertPresent=(await page.locator('main p[role="alert"]').count())>0;
  }
 });
 let job;
 await named('DOM review submit and durable completion',async()=>{await page.getByRole('button',{name:'Start governed review →'}).click();await page.locator('.effect').filter({hasText:/^completed$/}).waitFor({timeout:45000});job=await page.getByPlaceholder('Job reference').inputValue();assert(job);});
 await named('DOM exact export approval request',async()=>{await page.getByRole('button',{name:'Request export approval',exact:true}).click();await page.locator('.effect').filter({hasText:/^approval_required$/}).waitFor();});
 if(args['measure-polling']==='true') {
  await named('single-flight healthy polling and bounded signed-read growth',async()=>{
  result.polling={stage:'baseline snapshot',delayMs:budget.responseDelayMs,observedMs:budget.observationMs,drainBudgetMs:budget.drainMs,before:{},after:{}};
  let auditedAttempts=0;
  const countReads=request=>{const input=requestInput(request);if(input?.id===job&&['job','event_page'].includes(input.operation))auditedAttempts++;};
  page.on('request',countReads);
  const before=await snapshot(page,job,result.polling.before);
  result.polling.stage='delayed automatic reads';
  let active=0,maxActive=0,completed=0,errors=0;const attempts=[];const started=Date.now();
  const routePattern=base+'/api/workflow';
  const delayed=async route=>{const body=requestInput(route.request());if(body?.operation!=='job'||body.id!==job){await route.continue();return;}attempts.push(Date.now()-started);active++;maxActive=Math.max(maxActive,active);try{const response=await route.fetch();if(!response.ok())errors++;await new Promise(resolve=>setTimeout(resolve,budget.responseDelayMs));await route.fulfill({response});completed++;}catch{errors++;await route.abort('failed').catch(()=>{});}finally{active--;}};
  await page.route(routePattern,delayed);
  await page.waitForTimeout(budget.observationMs);
  result.polling.stage='drain';
  const drainStarted=Date.now();let drainTimer;
  try{await Promise.race([page.unrouteAll({behavior:'wait'}),new Promise((_,reject)=>{drainTimer=setTimeout(()=>reject(new Error('poll drain budget exceeded')),budget.drainMs);})]);}finally{clearTimeout(drainTimer);}
  const drainMs=Date.now()-drainStarted;
  Object.assign(result.polling,{drainMs,maxConcurrentJobResponses:maxActive,attempts:attempts.length,completedJobReads:completed,errors});
  result.polling.stage='after snapshot';
  const after=await snapshot(page,job,result.polling.after);
  page.off('request',countReads);
  result.polling.stage='exact signed history prefix';
  result.polling.priorEventIdsRemainPrefix=before.events.every((event,index)=>after.events[index]?.event_id===event.event_id);
  exactHistoryPrefix(before.events,after.events);
  const reads=events=>events.filter(event=>event.action==='document.read').length;
  Object.assign(result.polling,{stage:'budget acceptance',attemptOffsetsMs:attempts,auditedAttempts,signedReadEventsBefore:reads(before.events),signedReadEventsAfter:reads(after.events),signedReadGrowth:reads(after.events)-reads(before.events),signedReadGrowthBound:signedReadGrowthBound(auditedAttempts),measurementPageReads:before.pages+after.pages,historyPrefixPreserved:true,scope:'actual authorized API reads and bounded browser response latency; every measurement page is included in the request-derived audit bound'});
  pollingAcceptance(result.polling);
  result.polling.stage='complete';
  });
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
  await page.locator('#evidence').getByText('export.authorized',{exact:true}).waitFor();
  const signatures=await page.locator('#evidence [data-event-id] .good').allTextContents();
  assert(signatures.length>0 && signatures.every(label=>/^Signature valid · (control|kernel)$/.test(label)), 'history must identify per-record signatures clearly');
  assert.match(await page.locator('#evidence').innerText(),/does not confirm that the history is complete or independently retained/);
 });
 // No identifiers or digest contents are emitted: evidence system retains them.
 result.status='passed';
 await context.close();
} catch(error) {result.status='failed';result.failure='Browser qualification assertion failed; no sensitive diagnostics emitted';process.exitCode=1;}
finally {await writeFile(output,JSON.stringify(result,null,2)+'\n',{mode:0o600});if(browser)await browser.close();console.log(JSON.stringify({status:result.status,assertions:result.assertions.length,engine:result.engine}));}
