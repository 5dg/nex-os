// Dependency startup only. This does not exercise application DOM, TLS, identity,
// APIs or governance and cannot satisfy the dom-browser qualification gate.
import assert from 'node:assert/strict';
import {writeFile} from 'node:fs/promises';
const {chromium}=await import(process.env.NEX_PLAYWRIGHT_MODULE || '/fixture/node_modules/playwright-core/index.mjs');
const report={schema_version:1,scope:'browser dependency startup only; not DOM qualification',status:'failed'};
let browser;
try {
  assert.equal(process.env.NEX_BROWSER_EFFECTIVE_SANDBOX,'native');
  browser=await chromium.connectOverCDP('http://127.0.0.1:9222');
  report.engine=browser.version();
  const context=await browser.newContext();
  const page=await context.newPage();
  assert.equal(page.url(),'about:blank');
  await context.close();
  report.status='passed';
} catch {report.failure='DEPENDENCY_DRIVER_FAILED';process.exitCode=1;}
finally {
  await writeFile('/results/dependency-driver.json',JSON.stringify(report)+'\n',{mode:0o600});
  if(browser)await browser.close();
  console.log(JSON.stringify({scope:report.scope,status:report.status}));
}
