import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ADMIN_SESSION_COOKIE_NAME,
  ADMIN_SESSION_MAX_AGE_SECONDS,
  getAdminSessionSecret,
  createAdminSessionToken,
  verifyAdminSessionToken,
  serializeAdminSessionCookie,
  clearAdminSessionCookie,
} from '../src/admin-session.js';

const ADMIN_SECRET = 'admin-session-test-secret';
const UID = 7;

test('ADMIN_SESSION_COOKIE_NAME is the __Host- prefixed name', () => {
  assert.equal(ADMIN_SESSION_COOKIE_NAME, '__Host-admin_session');
});

test('ADMIN_SESSION_MAX_AGE_SECONDS is 28800 (8h)', () => {
  assert.equal(ADMIN_SESSION_MAX_AGE_SECONDS, 28800);
});

test('getAdminSessionSecret reads AUTH_GATEWAY_ADMIN_SESSION_SECRET and throws when unset', () => {
  const original = process.env.AUTH_GATEWAY_ADMIN_SESSION_SECRET;
  try {
    delete process.env.AUTH_GATEWAY_ADMIN_SESSION_SECRET;
    assert.throws(() => getAdminSessionSecret());

    process.env.AUTH_GATEWAY_ADMIN_SESSION_SECRET = 'from-env-secret';
    assert.equal(getAdminSessionSecret(), 'from-env-secret');
  } finally {
    if (original === undefined) {
      delete process.env.AUTH_GATEWAY_ADMIN_SESSION_SECRET;
    } else {
      process.env.AUTH_GATEWAY_ADMIN_SESSION_SECRET = original;
    }
  }
});

test('createAdminSessionToken/verifyAdminSessionToken round-trip succeeds', () => {
  const now = Date.now();
  const token = createAdminSessionToken(UID, ADMIN_SECRET, now);
  const payload = verifyAdminSessionToken(token, ADMIN_SECRET, now);
  assert.deepEqual(payload, { uid: UID });
});

test('verifyAdminSessionToken rejects a token older than 28800s', () => {
  const issuedAt = Date.now();
  const token = createAdminSessionToken(UID, ADMIN_SECRET, issuedAt);
  const verifyNow = issuedAt + (ADMIN_SESSION_MAX_AGE_SECONDS + 1) * 1000;
  assert.equal(verifyAdminSessionToken(token, ADMIN_SECRET, verifyNow), null);
});

test('verifyAdminSessionToken accepts a token right at the max-age boundary', () => {
  const issuedAt = Date.now();
  const token = createAdminSessionToken(UID, ADMIN_SECRET, issuedAt);
  const verifyNow = issuedAt + ADMIN_SESSION_MAX_AGE_SECONDS * 1000;
  assert.deepEqual(verifyAdminSessionToken(token, ADMIN_SECRET, verifyNow), { uid: UID });
});

test('verifyAdminSessionToken rejects a future-dated token beyond -60s clock skew', () => {
  const issuedAt = Date.now();
  const token = createAdminSessionToken(UID, ADMIN_SECRET, issuedAt);
  const verifyNow = issuedAt - 61_000;
  assert.equal(verifyAdminSessionToken(token, ADMIN_SECRET, verifyNow), null);
});

test('verifyAdminSessionToken accepts a token right at the -60s clock skew boundary', () => {
  const issuedAt = Date.now();
  const token = createAdminSessionToken(UID, ADMIN_SECRET, issuedAt);
  const verifyNow = issuedAt - 60_000;
  assert.deepEqual(verifyAdminSessionToken(token, ADMIN_SECRET, verifyNow), { uid: UID });
});

test('verifyAdminSessionToken rejects a tampered signature', () => {
  const token = createAdminSessionToken(UID, ADMIN_SECRET);
  const [payloadPart] = token.split('.');
  const tampered = `${payloadPart}.not-the-real-signature`;
  assert.equal(verifyAdminSessionToken(tampered, ADMIN_SECRET), null);
});

test('verifyAdminSessionToken never throws on malformed input', () => {
  assert.doesNotThrow(() => {
    assert.equal(verifyAdminSessionToken(undefined, ADMIN_SECRET), null);
    assert.equal(verifyAdminSessionToken(null, ADMIN_SECRET), null);
    assert.equal(verifyAdminSessionToken('no-separator', ADMIN_SECRET), null);
  });
});

// --- serializeAdminSessionCookie / clearAdminSessionCookie (A3) ---

test('serializeAdminSessionCookie sets Secure, Path=/, SameSite=Strict, Max-Age=28800, HttpOnly, and no Domain attribute', () => {
  const token = createAdminSessionToken(UID, ADMIN_SECRET);
  const cookie = serializeAdminSessionCookie(token);
  assert.ok(cookie.startsWith(`${ADMIN_SESSION_COOKIE_NAME}=${token}`));
  assert.ok(cookie.includes('Secure'));
  assert.ok(cookie.includes('Path=/'));
  assert.ok(cookie.includes('SameSite=Strict'));
  assert.ok(cookie.includes('Max-Age=28800'));
  assert.ok(cookie.includes('HttpOnly'));
  assert.ok(!/Domain=/i.test(cookie));
});

test('serializeAdminSessionCookie omits Secure when { secure: false } is passed, but still has no Domain=', () => {
  const token = createAdminSessionToken(UID, ADMIN_SECRET);
  const cookie = serializeAdminSessionCookie(token, { secure: false });
  assert.ok(!cookie.includes('Secure'));
  assert.ok(!/Domain=/i.test(cookie));
});

test('clearAdminSessionCookie sets Max-Age=0 and carries no Domain= attribute', () => {
  const cookie = clearAdminSessionCookie();
  assert.ok(cookie.startsWith(`${ADMIN_SESSION_COOKIE_NAME}=`));
  assert.ok(cookie.includes('Max-Age=0'));
  assert.ok(!/Domain=/i.test(cookie));
});
