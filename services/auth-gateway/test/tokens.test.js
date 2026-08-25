import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { hashToken, tokensMatch, hashPassword, verifyPassword } from '../src/tokens.js';

test('hashToken produces a deterministic SHA-256 hex digest', () => {
  const token = 'a-known-gateway-token-value';
  const expected = crypto.createHash('sha256').update(token, 'utf8').digest('hex');
  assert.equal(hashToken(token), expected);
});

test('hashToken produces different digests for different tokens', () => {
  assert.notEqual(hashToken('token-one'), hashToken('token-two'));
});

test('tokensMatch returns true for a token that hashes to the stored value', () => {
  const token = 'gw-token-abc123';
  const storedHash = hashToken(token);
  assert.equal(tokensMatch(token, storedHash), true);
});

test('tokensMatch returns false for a token that does not match the stored hash', () => {
  const storedHash = hashToken('gw-token-abc123');
  assert.equal(tokensMatch('a-completely-different-token', storedHash), false);
});

test('tokensMatch returns false (not throw) when the stored hash has a different length', () => {
  assert.equal(tokensMatch('gw-token-abc123', 'deadbeef'), false);
});

test('hashPassword + verifyPassword round-trip succeeds with bcrypt', async () => {
  const hash = await hashPassword('correct horse battery staple');
  assert.notEqual(hash, 'correct horse battery staple');
  assert.match(hash, /^\$2[aby]\$/);
  assert.equal(await verifyPassword('correct horse battery staple', hash), true);
});

test('verifyPassword rejects an incorrect password', async () => {
  const hash = await hashPassword('the-real-password');
  assert.equal(await verifyPassword('a-wrong-guess', hash), false);
});
