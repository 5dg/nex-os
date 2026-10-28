// E coordinates only committed synthetic DB mutations through public markers.
// No browser credentials, cookies, CSRF values or callback URLs are persisted.
import assert from 'node:assert/strict';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
const {chromium}=await import(process.env.NEX_PLAYWRIGHT_MODULE||'/fixture/node_modules/playwright-core/index.mjs');
const args=Object.fromEntries(process.argv.slice(2).map(x=>{const [k,...v]=x.replace(/^--/,'').split('=');return[k,v.join('=')];}));
const base=args['base-url']||'https://workspace.nex.test:9443',directory=args.directory||'/results/revocation';
await mkdir(directory,{recursive:true,mode:0o700});
const report={schema:1,scope:'same unexpired synthetic BFF session; externally committed DB revocation before next create',assertions:[]};
let browser;
try{
 browser=await chromium.connectOverCDP('http://127.0.0.1:9222');report.engine=browser.version();if(process.env.NEX_BROWSER_BINARY_SHA256){assert.match(process.env.NEX_BROWSER_BINARY_SHA256,/^[a-f0-9]{64}$/);report.engineBinarySha256=process.env.NEX_BROWSER_BINARY_SHA256;}const context=await browser.newContext();const page=await context.newPage();page.setDefaultTimeout(15000);
 await page.goto(base+'/workflow');await page.getByRole('link',{name:'Sign in →'}).click();await page.getByLabel('Username',{exact:true}).fill('alice');await page.getByLabel('Password',{exact:true}).fill('fixture-alice-password');await page.getByRole('button',{name:'Sign in',exact:true}).click();await page.getByText('Signed in as',{exact:false}).waitFor();await page.getByLabel('Document',{exact:true}).locator('option[value="review-alice"]').waitFor();
 await page.getByRole('button',{name:'Start governed review →'}).click();await page.locator('.effect').filter({hasText:/^completed$/}).waitFor({timeout:45000});
 report.assertions.push({name:'healthy DOM review before revocation',status:'passed'});
 for(const kind of ['permission','delegation']){
  const before=await page.evaluate(async()=>{const r=await fetch('/api/session',{cache:'no-store'});const v=await r.json();return {authenticated:v.authenticated,expires:v.expires_at};});
  assert(before.authenticated&&Date.parse(before.expires)-Date.now()>30000,'Fresh, unexpired session required before mutation');
  await writeFile(directory+'/'+kind+'-ready.json',JSON.stringify({stage:kind,ready:true})+'\n',{mode:0o600});
  let ack;const until=Date.now()+20000;
  while(Date.now()<until){try{ack=JSON.parse(await readFile(directory+'/'+kind+'-committed.json','utf8'));break;}catch{await new Promise(r=>setTimeout(r,100));}}
  assert(ack?.committed===true&&ack?.stage===kind,'External mutation must commit before next authoritative request');
  const responsePromise=page.waitForResponse(response=>{if(!response.url().endsWith('/api/workflow'))return false;try{return response.request().postDataJSON()?.operation==='create';}catch{return false;}});
  await page.getByRole('button',{name:'Start governed review →'}).click();const response=await responsePromise;const value=await response.json();assert.equal(response.status(),403);assert.equal(value.code,'DENIED_BY_POLICY');
  const after=await page.evaluate(async()=>{const r=await fetch('/api/session',{cache:'no-store'});const v=await r.json();return {authenticated:v.authenticated,expires:v.expires_at};});assert(after.authenticated&&after.expires===before.expires&&Date.parse(after.expires)>Date.now());
  report.assertions.push({name:kind+' revocation denies create with same unexpired session',status:'passed'});
  await writeFile(directory+'/'+kind+'-denied.json',JSON.stringify({stage:kind,denied:true,status:403})+'\n',{mode:0o600});
 }
 report.status='passed';await context.close();
}catch{report.status='failed';process.exitCode=1;}
finally{await writeFile(directory+'/browser-results.json',JSON.stringify(report,null,2)+'\n',{mode:0o600});if(browser)await browser.close();console.log(JSON.stringify({status:report.status,assertions:report.assertions.length}));}
