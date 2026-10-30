import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, randomBytes } from 'node:crypto';
import { SessionKeyring } from '../lib/session-keyring.ts';

function legacy(key, plain, aad) {
  const nonce = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aad); return Buffer.concat([nonce, cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
}
test('two-key overlap preserves legacy records and supports phased rotation', () => {
  const oldKey = randomBytes(32), newKey = randomBytes(32), aad = Buffer.from('bound-record'), message = Buffer.from('private-session');
  const oldRecord = legacy(oldKey, message, aad);
  const oldOnly = new SessionKeyring(oldKey), prepared = new SessionKeyring(oldKey, newKey), rotated = new SessionKeyring(newKey, oldKey), retired = new SessionKeyring(newKey);
  oldKey.fill(0); newKey.fill(0); // Constructor copies both keys.
  const newRecord = rotated.seal(message, aad);
  for (const ring of [prepared, rotated]) for (const record of [oldRecord, newRecord]) assert.deepEqual(ring.unseal(record, aad), message);
  assert.throws(() => oldOnly.unseal(newRecord, aad), /invalid/);
  assert.throws(() => retired.unseal(oldRecord, aad), /invalid/);
  assert.deepEqual(retired.unseal(newRecord, aad), message);
  for (const index of [0, 12, oldRecord.length - 1]) {
    const tampered = Buffer.from(oldRecord); tampered[index] ^= 1;
    assert.throws(() => rotated.unseal(tampered, aad), /invalid/);
  }
  assert.throws(() => rotated.unseal(oldRecord, Buffer.from('other-record')), /invalid/);
});
test('keyring rejects zero, malformed, duplicate and oversized inputs', () => {
  const key = randomBytes(32);
  for (const pair of [[Buffer.alloc(0)], [Buffer.alloc(32)], [key, Buffer.alloc(0)], [key, Buffer.alloc(32)], [key, key]]) assert.throws(() => new SessionKeyring(...pair), /invalid/);
  const ring = new SessionKeyring(key);
  assert.throws(() => ring.seal(Buffer.alloc(32769), Buffer.alloc(0)), /limit/);
  assert.throws(() => ring.unseal(Buffer.alloc(27), Buffer.alloc(0)), /invalid/);
  assert.throws(() => ring.unseal(Buffer.alloc(32797), Buffer.alloc(0)), /invalid/);
});
