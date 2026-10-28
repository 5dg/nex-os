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

export async function snapshot(page, id) {
  const events = [], cursors = new Set();
  let cursor = '', pages = 0;
  do {
    assert(pages < budget.maxHistoryPages, 'history traversal did not terminate');
    const response = await workflowCall(page, {operation: 'event_page', id, ...(cursor ? {cursor} : {})});
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
  verifiedEvents(events);
  return {events, pages, bytes: Buffer.byteLength(JSON.stringify(events))};
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
