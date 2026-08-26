import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { sign, timingSafeCompare, createSessionToken, verifySessionToken } from '../src/session.js';

test('sign produces a deterministic base64url HMAC-SHA256 signature for the same payload+secret', () => {
  const payload = Buffer.from('hello-payload', 'utf8').toString('base64url');
  const secret = 'sign-test-secret';
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  assert.equal(sign(payload, secret), expected);
  assert.equal(sign(payload, secret), sign(payload, secret));
});

test('sign produces different signatures for different payloads or different secrets', () => {
  const secret = 'sign-test-secret';
  const a = sign('payload-a', secret);
  const b = sign('payload-b', secret);
  assert.notEqual(a, b);

  const c = sign('payload-a', 'other-secret');
  assert.notEqual(a, c);
});

test('timingSafeCompare returns true for two equal strings', () => {
  assert.equal(timingSafeCompare('same-value', 'same-value'), true);
});

test('timingSafeCompare returns false for two different strings of the same length', () => {
  assert.equal(timingSafeCompare('aaaaaaaaaa', 'bbbbbbbbbb'), false);
});

test('timingSafeCompare returns false (not throw) for strings of different lengths', () => {
  assert.doesNotThrow(() => {
    assert.equal(timingSafeCompare('short', 'a-much-longer-value'), false);
  });
});

test('timingSafeCompare returns false for empty vs. non-empty strings', () => {
  assert.equal(timingSafeCompare('', 'non-empty'), false);
});

test('createSessionToken/verifySessionToken round-trip still works after the timingSafeCompare extraction', () => {
  const secret = 'session-round-trip-secret';
  const token = createSessionToken({ uid: 7 }, secret);
  const payload = verifySessionToken(token, secret);
  assert.deepEqual(payload, { uid: 7 });
});

test('verifySessionToken rejects a token with a tampered signature after the extraction', () => {
  const secret = 'session-tamper-secret';
  const token = createSessionToken({ uid: 1 }, secret);
  const [payloadPart] = token.split('.');
  const tampered = `${payloadPart}.not-the-real-signature`;
  assert.equal(verifySessionToken(tampered, secret), null);
});
