import assert from 'node:assert/strict';
import {budget, historyPage, verifiedEvents} from './acceptance.mjs';

export async function workflowCall(page, input) {
  return page.evaluate(async body => {
    const sessionResponse = await fetch('/api/session', {cache: 'no-store'});
    const session = await sessionResponse.json();
    if (!sessionResponse.ok || !session.authenticated) throw new Error('fixture session unavailable');
    const response = await fetch('/api/workflow', {
      method: 'POST', headers: {'Content-Type': 'application/json', 'X-Nex-CSRF': session.csrf_token},
      body: JSON.stringify(body),
    });
    const text = await response.text();
    return {status: response.status, bytes: new TextEncoder().encode(text).length, value: JSON.parse(text)};
  }, input);
}

export async function snapshot(page, id, diagnostics = {}) {
  const events = [], cursors = new Set();
  let cursor = '', pages = 0;
  do {
    diagnostics.step = 'request';
    diagnostics.pagesCompleted = pages;
    assert(pages < budget.maxHistoryPages, 'history traversal did not terminate');
    const response = await workflowCall(page, {operation: 'event_page', id, ...(cursor ? {cursor} : {})});
    diagnostics.lastStatus = response.status;
    diagnostics.lastPageBytes = response.bytes;
    const codes = new Set(['INVALID_REQUEST','DEPENDENCY_UNAVAILABLE','DENIED_BY_POLICY','UNAUTHENTICATED','SESSION_OR_CSRF_DENIED','INVALID_HISTORY_CURSOR','HISTORY_PAGINATION_REQUIRED','HISTORY_EVENT_TOO_LARGE']);
    if (response.value?.code) diagnostics.lastCode = codes.has(response.value.code) ? response.value.code : 'OTHER_APPLICATION_ERROR';
    diagnostics.step = 'page acceptance';
    diagnostics.lastEventCount = Array.isArray(response.value?.events) ? response.value.events.length : null;
    diagnostics.lastUnverifiedEvents = Array.isArray(response.value?.events) ? response.value.events.filter(event => event.integrity_verified !== true).length : null;
    diagnostics.cursorIsString = typeof response.value?.next_cursor === 'string';
    assert.equal(response.status, 200, 'history page request failed');
    const value = historyPage(response.value, response.bytes);
    events.push(...value.events);
    cursor = value.next_cursor;
    if (cursor) {
      assert(!cursors.has(cursor), 'history cursor repeated');
      cursors.add(cursor);
    }
    pages++;
  } while (cursor);
  diagnostics.step = 'combined history acceptance';
  diagnostics.pagesCompleted = pages;
  diagnostics.events = events.length;
  diagnostics.duplicateEvents = events.length - new Set(events.map(event => event.event_id)).size;
  verifiedEvents(events);
  diagnostics.step = 'complete';
  diagnostics.bytes = Buffer.byteLength(JSON.stringify(events));
  return {events, pages, bytes: diagnostics.bytes};
}

export function requestInput(request) {
  if (!request.url().endsWith('/api/workflow')) return undefined;
  try { return request.postDataJSON(); } catch { return undefined; }
}

export function responseFor(operation, id) {
  return response => {
    const input = requestInput(response.request());
    return input?.operation === operation && (!id || input.id === id);
  };
}

export async function login(page, subject) {
  await page.getByRole('link', {name: 'Sign in →'}).click();
  await page.getByLabel('Username', {exact: true}).fill(subject);
  await page.getByLabel('Password', {exact: true}).fill('fixture-' + subject + '-password');
  await page.getByRole('button', {name: 'Sign in', exact: true}).click();
  await page.getByText('Signed in as', {exact: false}).waitFor();
  assert.equal(await page.locator('strong').filter({hasText: subject}).count(), 1);
}
