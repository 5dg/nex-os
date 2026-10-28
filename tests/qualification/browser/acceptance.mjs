// Independent browser acceptance limits. Freeze these before a measured run.
import assert from 'node:assert/strict';

export const budget = Object.freeze({
  responseDelayMs: 2500,
  observationMs: 7500,
  drainMs: 5000,
  maxConcurrentAutomaticReads: 1,
  historyPageBytes: 96 * 1024,
  historyPageItems: 32,
  legacyHistoryBytes: 128 * 1024,
  maxHistoryPages: 64,
  maxFixtureReads: 512,
});

export function verifiedEvents(events) {
  assert(Array.isArray(events), 'history events must be an array');
  assert(events.every(event => event.integrity_verified === true), 'every history event must verify');
  assert.equal(new Set(events.map(event => event.event_id)).size, events.length, 'duplicate history event');
  return events;
}

export function exactHistoryPrefix(before, after) {
  verifiedEvents(before);
  verifiedEvents(after);
  assert(after.length >= before.length, 'history cannot shrink');
  assert.deepEqual(after.slice(0, before.length), before, 'ordered signed history prefix changed');
}

export function historyPage(value, rawBytes) {
  assert(rawBytes <= budget.historyPageBytes, 'history page exceeds byte budget');
  assert.equal(typeof value?.next_cursor, 'string', 'history cursor must be explicit');
  verifiedEvents(value.events);
  assert(value.events.length <= budget.historyPageItems, 'history page exceeds item budget');
  assert(value.events.length || !value.next_cursor, 'empty continuation cannot advance traversal');
  return value;
}

// Each successful job or event_page request writes one signed document.read.
// Count all job/event_page request attempts from BEFORE the first snapshot fetch
// until AFTER the last snapshot fetch, including every measurement page read.
// The first baseline page and after-snapshot continuations cannot increase the
// observed difference, but remain counted for a conservative bound. At most one
// pre-observation automatic read can still be in flight at the first boundary.
// Therefore growth <= all observed audited request attempts + 1 boundary read.
// Counting attempts rather than successful responses is conservative under
// transport cancellation; zero unexpected errors is a separate healthy-run gate.
export function signedReadGrowthBound(auditedAttempts) {
  assert(Number.isSafeInteger(auditedAttempts) && auditedAttempts >= 0);
  return auditedAttempts + 1;
}

export function pollingAcceptance(metrics) {
  assert(metrics.attempts > 0, 'polling fixture exercised no automatic reads');
  assert(metrics.maxConcurrentJobResponses <= budget.maxConcurrentAutomaticReads, 'automatic job reads overlapped');
  assert.equal(metrics.errors, 0, 'healthy delayed-response polling failed');
  assert(metrics.drainMs <= budget.drainMs, 'polling exceeded drain budget');
  assert(metrics.signedReadGrowth >= 0, 'signed reads disappeared');
  assert(metrics.signedReadGrowth <= signedReadGrowthBound(metrics.auditedAttempts), 'signed read growth exceeded request-derived budget');
}
