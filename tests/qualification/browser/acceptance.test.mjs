import assert from 'node:assert/strict';
import test from 'node:test';
import {budget, exactHistoryPrefix, historyPage, pollingAcceptance, signedReadGrowthBound} from './acceptance.mjs';

const event = id => ({event_id: id, integrity_verified: true, action: 'document.read', integrity_reference: {signature: 'signed-' + id}});

test('history acceptance rejects reordered, substituted, missing and duplicate signed events', () => {
  const before = [event('a'), event('b')];
  exactHistoryPrefix(before, [...before, event('c')]);
  for (const after of [[before[1], before[0]], [before[0]], [before[0], {...before[1], action: 'export.authorized'}], [before[0], before[0]]]) {
    assert.throws(() => exactHistoryPrefix(before, after));
  }
});

test('page acceptance enforces both actual bytes and cardinality', () => {
  historyPage({events: [event('a')], next_cursor: ''}, 200);
  assert.throws(() => historyPage({events: [event('a')], next_cursor: ''}, budget.historyPageBytes + 1));
  assert.throws(() => historyPage({events: Array.from({length: 33}, (_, i) => event(String(i))), next_cursor: ''}, 200));
  assert.throws(() => historyPage({events: [], next_cursor: 'stuck'}, 200));
});

test('predeclared polling budget rejects overlap, healthy errors and excessive audit growth', () => {
  assert.equal(signedReadGrowthBound(5), 6);
  const healthy = {attempts: 2, maxConcurrentJobResponses: 1, errors: 0, drainMs: 2500, signedReadGrowth: 5, auditedAttempts: 5};
  pollingAcceptance(healthy);
  for (const changes of [{attempts: 0}, {maxConcurrentJobResponses: 2}, {errors: 1}, {drainMs: 5001}, {signedReadGrowth: 7}, {signedReadGrowth: -1}]) {
    assert.throws(() => pollingAcceptance({...healthy, ...changes}));
  }
});
