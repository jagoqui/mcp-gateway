import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ADMIN_LOGIN_MAX_ATTEMPTS,
  ADMIN_LOGIN_WINDOW_SECONDS,
  ADMIN_THROTTLE_MAX_ENTRIES,
  createLoginThrottle,
} from '../src/admin-throttle.js';

test('ADMIN_LOGIN_MAX_ATTEMPTS is 5, ADMIN_LOGIN_WINDOW_SECONDS is 900, ADMIN_THROTTLE_MAX_ENTRIES is 1000', () => {
  assert.equal(ADMIN_LOGIN_MAX_ATTEMPTS, 5);
  assert.equal(ADMIN_LOGIN_WINDOW_SECONDS, 900);
  assert.equal(ADMIN_THROTTLE_MAX_ENTRIES, 1000);
});

test('an unknown key is never locked', () => {
  const throttle = createLoginThrottle();
  assert.equal(throttle.isLocked('nobody'), false);
});

// A9 — 6th+ attempt inside the window returns locked, even with correct
// credentials (the caller checks isLocked before verifying credentials).
test('the 6th failure within the window locks the key; the first 5 do not', () => {
  const throttle = createLoginThrottle();
  const now = Date.now();
  for (let i = 0; i < ADMIN_LOGIN_MAX_ATTEMPTS; i += 1) {
    assert.equal(throttle.isLocked('jagoqui', now), false);
    throttle.recordFailure('jagoqui', now);
  }
  assert.equal(throttle.isLocked('jagoqui', now), true);
});

test('the lock releases once the fixed window elapses', () => {
  const throttle = createLoginThrottle();
  const start = Date.now();
  for (let i = 0; i < ADMIN_LOGIN_MAX_ATTEMPTS; i += 1) {
    throttle.recordFailure('jagoqui', start);
  }
  assert.equal(throttle.isLocked('jagoqui', start), true);
  const afterWindow = start + ADMIN_LOGIN_WINDOW_SECONDS * 1000;
  assert.equal(throttle.isLocked('jagoqui', afterWindow), false);
});

test('a failure after the window elapsed opens a fresh window instead of accumulating', () => {
  const throttle = createLoginThrottle();
  const start = Date.now();
  for (let i = 0; i < ADMIN_LOGIN_MAX_ATTEMPTS; i += 1) {
    throttle.recordFailure('jagoqui', start);
  }
  const afterWindow = start + ADMIN_LOGIN_WINDOW_SECONDS * 1000 + 1;
  throttle.recordFailure('jagoqui', afterWindow);
  assert.equal(throttle.isLocked('jagoqui', afterWindow), false);
});

test('reset clears a key immediately, independent of the window', () => {
  const throttle = createLoginThrottle();
  const now = Date.now();
  for (let i = 0; i < ADMIN_LOGIN_MAX_ATTEMPTS; i += 1) {
    throttle.recordFailure('jagoqui', now);
  }
  assert.equal(throttle.isLocked('jagoqui', now), true);
  throttle.reset('jagoqui');
  assert.equal(throttle.isLocked('jagoqui', now), false);
});

test('failures for different keys never affect each other', () => {
  const throttle = createLoginThrottle();
  const now = Date.now();
  for (let i = 0; i < ADMIN_LOGIN_MAX_ATTEMPTS; i += 1) {
    throttle.recordFailure('jagoqui', now);
  }
  assert.equal(throttle.isLocked('jagoqui', now), true);
  assert.equal(throttle.isLocked('someone-else', now), false);
});

// A17 — bounded entry count guards against memory exhaustion from many
// distinct usernames.
test('size() never exceeds a small configured maxEntries, evicting the oldest entry', () => {
  const throttle = createLoginThrottle({ maxEntries: 3 });
  const now = Date.now();
  throttle.recordFailure('user-1', now);
  throttle.recordFailure('user-2', now);
  throttle.recordFailure('user-3', now);
  throttle.recordFailure('user-4', now);
  assert.equal(throttle.size(), 3);
});

test('a custom maxAttempts/windowSeconds is honored', () => {
  const throttle = createLoginThrottle({ maxAttempts: 2, windowSeconds: 60 });
  const now = Date.now();
  throttle.recordFailure('jagoqui', now);
  assert.equal(throttle.isLocked('jagoqui', now), false);
  throttle.recordFailure('jagoqui', now);
  assert.equal(throttle.isLocked('jagoqui', now), true);
});
