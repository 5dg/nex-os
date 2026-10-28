import test from 'node:test';
import assert from 'node:assert/strict';
import { pollJob, historyPage, appendHistory } from '../lib/workflow-client.ts';

const flush = () => new Promise(resolve => setImmediate(resolve));
function clock() {
  const pending = [];
  return {
    pending,
    schedule(callback, milliseconds) { const timer = { callback, milliseconds }; pending.push(timer); return timer; },
    cancel(timer) { const index = pending.indexOf(timer); if (index >= 0) pending.splice(index, 1); },
    async advance() { const timer = pending.shift(); assert.ok(timer, 'a timer must be scheduled'); timer.callback(); await flush(); return timer.milliseconds; },
  };
}

test('slow reads have one refresh cycle in flight and terminal state stops scheduling', async () => {
  const timers = clock();
  let release, active = 0, maximum = 0, pending = true, calls = 0;
  const stop = pollJob({ ...timers, pending: () => pending, error: assert.fail, refresh: async () => {
    calls++; active++; maximum = Math.max(maximum, active);
    await new Promise(resolve => { release = resolve; });
    active--;
  } });
  await flush();
  assert.equal(calls, 1); assert.equal(timers.pending.length, 0, 'no timer runs while response is held');
  release(); await flush();
  assert.equal(timers.pending[0].milliseconds, 2000);
  await timers.advance();
  assert.equal(calls, 2); assert.equal(maximum, 1);
  pending = false; release(); await flush();
  assert.equal(timers.pending.length, 0, 'completed jobs do not poll again');
  stop();
});

test('failures back off within a fixed bound and successful response resets delay', async () => {
  const timers = clock();
  let fail = true, errors = 0;
  const stop = pollJob({ ...timers, pending: () => true, error: () => errors++, refresh: async () => { if (fail) throw new Error('dependency unavailable'); } });
  await flush();
  const delays = [];
  for (let i = 0; i < 6; i++) delays.push(await timers.advance());
  assert.deepEqual(delays, [2000, 4000, 8000, 16000, 30000, 30000]);
  assert.equal(errors, 7);
  fail = false; await timers.advance();
  assert.equal(timers.pending[0].milliseconds, 2000);
  stop(); assert.equal(timers.pending.length, 0);
});

test('stopping aborts an in-flight read without retry or stale error callbacks', async () => {
  const timers = clock();
  let reject, signal, errors = 0;
  const stop = pollJob({ ...timers, pending: () => true, error: () => errors++, refresh: async value => {
    signal = value; await new Promise((_, fail) => { reject = fail; });
  } });
  stop(); assert.equal(signal.aborted, true);
  reject(new Error('late disconnected response')); await flush();
  assert.equal(errors, 0); assert.equal(timers.pending.length, 0);
});

test('history continuation preserves exact ordered objects and rejects repeated pages', () => {
  const first = [{ event_id: 'first', integrity_reference: { signature: 'original' } }, { event_id: 'second', detail: { reason: 'original' } }];
  const serialized = JSON.stringify(first);
  const page = historyPage({ events: [{ event_id: 'third', integrity_reference: { signature: 'next' } }], next_cursor: '' });
  const complete = appendHistory(first, page);
  assert.equal(JSON.stringify(complete.slice(0, first.length)), serialized);
  assert.equal(complete[0], first[0]); assert.deepEqual(complete.map(event => event.event_id), ['first', 'second', 'third']);
  assert.throws(() => appendHistory(complete, page), /repeated an event/);
  assert.throws(() => historyPage({ events: [{ event_id: 'one' }, { event_id: 'one' }], next_cursor: '' }));
  assert.throws(() => historyPage({ events: [], next_cursor: null }));
});
