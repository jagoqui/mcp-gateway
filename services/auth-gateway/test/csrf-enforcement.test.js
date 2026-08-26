import { test, before, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { openDb } from '../src/db.js';
import { hashToken } from '../src/tokens.js';
import { encrypt } from '../src/crypto.js';
import { createSessionToken } from '../src/session.js';
import { issueCsrfToken } from '../src/csrf.js';
import { createServer } from '../src/app.js';

const DOMAIN = 'test.example';
const SESSION_SECRET = 'csrf-enforcement-test-session-secret';
const ORIGIN = `https://${DOMAIN}`;

before(() => {
  process.env.ATLASSIAN_ENC_KEY = crypto.randomBytes(32).toString('base64');
  process.env.AUTH_GATEWAY_SESSION_SECRET = SESSION_SECRET;
});

/** @type {import('better-sqlite3').Database} */
let db;
/** @type {import('node:http').Server} */
let server;
/** @type {string} */
let baseUrl;

beforeEach(async () => {
  db = openDb(':memory:');
  server = createServer(db, { domain: DOMAIN, sessionSecret: SESSION_SECRET });
  await new Promise((resolve) => server.listen(0, () => resolve(undefined)));
  const address = /** @type {import('node:net').AddressInfo} */ (server.address());
  baseUrl = `http://127.0.0.1:${address.port}`;
});

afterEach(async () => {
  await new Promise((resolve) => server.close(() => resolve(undefined)));
  db.close();
});

/**
 * @param {{ username?: string }} [opts]
 * @returns {{ userId: number, rawToken: string }}
 */
function insertUserWithToken(opts = {}) {
  const { username = 'alice' } = opts;
  const info = db
    .prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)')
    .run(username, 'bcrypt-placeholder');
  const userId = Number(info.lastInsertRowid);
  const rawToken = `raw-token-${username}`;
  db.prepare('INSERT INTO tokens (user_id, token_hash) VALUES (?, ?)').run(
    userId,
    hashToken(rawToken),
  );
  return { userId, rawToken };
}

/**
 * @param {number} userId
 * @returns {string}
 */
function sessionCookieFor(userId) {
  const token = createSessionToken({ uid: userId }, SESSION_SECRET);
  return `session=${token}`;
}

// --- POST /me/atlassian, cookie-authenticated: CSRF token enforcement ---

test('POST /me/atlassian (cookie auth) with no CSRF token is rejected 403 csrf_token_invalid', async () => {
  const { userId } = insertUserWithToken({ username: 'alice' });
  const res = await fetch(`${baseUrl}/me/atlassian`, {
    method: 'POST',
    headers: {
      Cookie: sessionCookieFor(userId),
      'Content-Type': 'application/json',
      Origin: ORIGIN,
    },
    body: JSON.stringify({ token: 'my-pat', scheme: 'Token' }),
  });
  assert.equal(res.status, 403);
  const body = await res.json();
  assert.equal(body.error, 'csrf_token_invalid');
});

test('POST /me/atlassian (cookie auth) with a forged CSRF token is rejected 403', async () => {
  const { userId } = insertUserWithToken({ username: 'bob' });
  const token = issueCsrfToken(userId, SESSION_SECRET);
  const forged = `${token.slice(0, -2)}zz`;
  const res = await fetch(`${baseUrl}/me/atlassian`, {
    method: 'POST',
    headers: {
      Cookie: sessionCookieFor(userId),
      'Content-Type': 'application/json',
      Origin: ORIGIN,
      'X-CSRF-Token': forged,
    },
    body: JSON.stringify({ token: 'my-pat', scheme: 'Token' }),
  });
  assert.equal(res.status, 403);
  const body = await res.json();
  assert.equal(body.error, 'csrf_token_invalid');
});

test("POST /me/atlassian (cookie auth) with another user's valid CSRF token is rejected 403", async () => {
  const { userId } = insertUserWithToken({ username: 'carol' });
  const other = insertUserWithToken({ username: 'dave' });
  const otherToken = issueCsrfToken(other.userId, SESSION_SECRET);
  const res = await fetch(`${baseUrl}/me/atlassian`, {
    method: 'POST',
    headers: {
      Cookie: sessionCookieFor(userId),
      'Content-Type': 'application/json',
      Origin: ORIGIN,
      'X-CSRF-Token': otherToken,
    },
    body: JSON.stringify({ token: 'my-pat', scheme: 'Token' }),
  });
  assert.equal(res.status, 403);
  const body = await res.json();
  assert.equal(body.error, 'csrf_token_invalid');
});

test('POST /me/atlassian (cookie auth) with a valid CSRF token succeeds 200', async () => {
  const { userId } = insertUserWithToken({ username: 'erin' });
  const token = issueCsrfToken(userId, SESSION_SECRET);
  const res = await fetch(`${baseUrl}/me/atlassian`, {
    method: 'POST',
    headers: {
      Cookie: sessionCookieFor(userId),
      'Content-Type': 'application/json',
      Origin: ORIGIN,
      'X-CSRF-Token': token,
    },
    body: JSON.stringify({ token: 'my-pat', scheme: 'Token' }),
  });
  assert.equal(res.status, 200);
});

test('POST /me/atlassian (Bearer auth) with no CSRF token still succeeds 200', async () => {
  const { rawToken } = insertUserWithToken({ username: 'frank' });
  const res = await fetch(`${baseUrl}/me/atlassian`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${rawToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ token: 'my-pat', scheme: 'Token' }),
  });
  assert.equal(res.status, 200);
});

// D2/R4 bypass: a garbage Bearer header must not let a cookie-authenticated
// write skip CSRF enforcement — authenticateWithMethod() must still report
// 'cookie' here, not 'bearer'.
test('threat: POST /me/atlassian with a garbage Bearer header + valid cookie still requires CSRF (D2/R4)', async () => {
  const { userId } = insertUserWithToken({ username: 'grace' });
  const res = await fetch(`${baseUrl}/me/atlassian`, {
    method: 'POST',
    headers: {
      Authorization: 'Bearer garbage-does-not-exist',
      Cookie: sessionCookieFor(userId),
      'Content-Type': 'application/json',
      Origin: ORIGIN,
    },
    body: JSON.stringify({ token: 'my-pat', scheme: 'Token' }),
  });
  assert.equal(res.status, 403);
  const body = await res.json();
  assert.equal(body.error, 'csrf_token_invalid');
});

// --- DELETE /me/atlassian, cookie-authenticated, header-only transport ---

test('DELETE /me/atlassian (cookie auth) with a valid CSRF token in X-CSRF-Token succeeds 200 and clears the caller row', async () => {
  const { userId } = insertUserWithToken({ username: 'heidi' });
  db.prepare(
    "INSERT INTO atlassian_credentials (user_id, scheme, ciphertext, updated_at) VALUES (?, ?, ?, datetime('now'))",
  ).run(userId, 'Token', encrypt('secret-pat'));
  const token = issueCsrfToken(userId, SESSION_SECRET);
  const res = await fetch(`${baseUrl}/me/atlassian`, {
    method: 'DELETE',
    headers: {
      Cookie: sessionCookieFor(userId),
      Origin: ORIGIN,
      'X-CSRF-Token': token,
    },
  });
  assert.equal(res.status, 200);
  const row = db.prepare('SELECT * FROM atlassian_credentials WHERE user_id = ?').get(userId);
  assert.equal(row, undefined);
});

test('DELETE /me/atlassian (cookie auth) with no CSRF token is rejected 403 csrf_token_invalid', async () => {
  const { userId } = insertUserWithToken({ username: 'ivan' });
  const res = await fetch(`${baseUrl}/me/atlassian`, {
    method: 'DELETE',
    headers: { Cookie: sessionCookieFor(userId), Origin: ORIGIN },
  });
  assert.equal(res.status, 403);
  const body = await res.json();
  assert.equal(body.error, 'csrf_token_invalid');
});

test('DELETE /me/atlassian (Bearer auth) with no CSRF token succeeds 200', async () => {
  const { userId, rawToken } = insertUserWithToken({ username: 'jack' });
  db.prepare(
    "INSERT INTO atlassian_credentials (user_id, scheme, ciphertext, updated_at) VALUES (?, ?, ?, datetime('now'))",
  ).run(userId, 'Token', encrypt('secret-pat'));
  const res = await fetch(`${baseUrl}/me/atlassian`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${rawToken}` },
  });
  assert.equal(res.status, 200);
});

// --- Origin checks (R2), strict mode: mismatch AND absent are both rejected ---

test('POST /me/atlassian (cookie auth) with a cross-site Origin is rejected 403 csrf_origin_rejected', async () => {
  const { userId } = insertUserWithToken({ username: 'judy' });
  const token = issueCsrfToken(userId, SESSION_SECRET);
  const res = await fetch(`${baseUrl}/me/atlassian`, {
    method: 'POST',
    headers: {
      Cookie: sessionCookieFor(userId),
      'Content-Type': 'application/json',
      Origin: 'https://evil.example',
      'X-CSRF-Token': token,
    },
    body: JSON.stringify({ token: 'my-pat', scheme: 'Token' }),
  });
  assert.equal(res.status, 403);
  const body = await res.json();
  assert.equal(body.error, 'csrf_origin_rejected');
});

test('POST /me/atlassian (cookie auth) with an absent Origin/Referer is rejected 403 csrf_origin_rejected', async () => {
  const { userId } = insertUserWithToken({ username: 'karl' });
  const token = issueCsrfToken(userId, SESSION_SECRET);
  const res = await fetch(`${baseUrl}/me/atlassian`, {
    method: 'POST',
    headers: {
      Cookie: sessionCookieFor(userId),
      'Content-Type': 'application/json',
      'X-CSRF-Token': token,
    },
    body: JSON.stringify({ token: 'my-pat', scheme: 'Token' }),
  });
  assert.equal(res.status, 403);
  const body = await res.json();
  assert.equal(body.error, 'csrf_origin_rejected');
});

test('DELETE /me/atlassian (cookie auth) with a cross-site Origin is rejected 403 csrf_origin_rejected', async () => {
  const { userId } = insertUserWithToken({ username: 'liam' });
  const token = issueCsrfToken(userId, SESSION_SECRET);
  const res = await fetch(`${baseUrl}/me/atlassian`, {
    method: 'DELETE',
    headers: {
      Cookie: sessionCookieFor(userId),
      Origin: 'https://evil.example',
      'X-CSRF-Token': token,
    },
  });
  assert.equal(res.status, 403);
  const body = await res.json();
  assert.equal(body.error, 'csrf_origin_rejected');
});
