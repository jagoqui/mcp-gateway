import { test, before, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { openDb } from '../src/db.js';
import { hashToken } from '../src/tokens.js';
import { encrypt } from '../src/crypto.js';
import { createSessionToken } from '../src/session.js';
import { verifyCsrfToken, issueCsrfToken } from '../src/csrf.js';
import { createServer } from '../src/app.js';

const DOMAIN = 'test.example';
const SESSION_SECRET = 'panel-test-session-secret';
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
  delete process.env.CONTEXT7_API_KEY;
  delete process.env.ENGRAM_API_KEY;
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

// --- GET /credentials access control ---

test('GET /credentials returns 200 text/html for an authenticated caller', async () => {
  const { userId } = insertUserWithToken({ username: 'alice' });
  const res = await fetch(`${baseUrl}/credentials`, {
    headers: { Cookie: sessionCookieFor(userId) },
  });
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type') ?? '', /text\/html/);
});

test('GET /credentials with Accept: text/html and no auth redirects 302 to /login?next=%2Fcredentials', async () => {
  const res = await fetch(`${baseUrl}/credentials`, {
    headers: { Accept: 'text/html,application/xhtml+xml' },
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/login?next=%2Fcredentials');
});

test('GET /credentials with no auth and a non-html Accept returns 401 JSON', async () => {
  const res = await fetch(`${baseUrl}/credentials`, {
    headers: { Accept: 'application/json' },
  });
  assert.equal(res.status, 401);
  const body = await res.json();
  assert.equal(body.error, 'unauthenticated');
});

// --- Rendering ---

test('GET /credentials renders all three registry MCPs by label', async () => {
  const { userId } = insertUserWithToken({ username: 'bob' });
  const res = await fetch(`${baseUrl}/credentials`, {
    headers: { Cookie: sessionCookieFor(userId) },
  });
  const body = await res.text();
  assert.match(body, /Atlassian \(Jira \/ Confluence\)/);
  assert.match(body, /Context7/);
  assert.match(body, /Engram/);
});

test('GET /credentials renders no <form> for the shared-credential MCP rows', async () => {
  const { userId } = insertUserWithToken({ username: 'carol' });
  const res = await fetch(`${baseUrl}/credentials`, {
    headers: { Cookie: sessionCookieFor(userId) },
  });
  const body = await res.text();
  const context7Section = body.slice(body.indexOf('Context7'), body.indexOf('Engram'));
  assert.ok(!context7Section.includes('<form'), 'the Context7 (shared) row must render no form');
});

test('GET /credentials body contains no <script> tag', async () => {
  const { userId } = insertUserWithToken({ username: 'dave' });
  const res = await fetch(`${baseUrl}/credentials`, {
    headers: { Cookie: sessionCookieFor(userId) },
  });
  const body = await res.text();
  assert.ok(!body.includes('<script'), 'the panel body must contain no <script> tag');
});

test('GET /credentials headers carry the CSP + no-store + nosniff header set', async () => {
  const { userId } = insertUserWithToken({ username: 'erin' });
  const res = await fetch(`${baseUrl}/credentials`, {
    headers: { Cookie: sessionCookieFor(userId) },
  });
  assert.equal(
    res.headers.get('content-security-policy'),
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  );
  assert.equal(res.headers.get('cache-control'), 'no-store');
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
});

// --- CSRF token embedding ---

test('GET /credentials embeds a hidden csrf field that verifies for the caller uid', async () => {
  const { userId } = insertUserWithToken({ username: 'frank' });
  const res = await fetch(`${baseUrl}/credentials`, {
    headers: { Cookie: sessionCookieFor(userId) },
  });
  const body = await res.text();
  const match = body.match(/name="csrf" value="([^"]*)"/);
  assert.ok(match, 'expected a hidden csrf field in the rendered panel');
  const csrfValue = match?.[1] ?? '';
  const valid = verifyCsrfToken(csrfValue, { uid: userId, sessionSecret: SESSION_SECRET });
  assert.equal(valid, true);
});

// --- R6: malicious cloudId is escaped, never live markup ---

test('threat: a malicious cloudId is HTML-escaped in the rendered panel, not live markup (R6)', async () => {
  const { userId } = insertUserWithToken({ username: 'grace' });
  db.prepare(
    "INSERT INTO atlassian_credentials (user_id, scheme, ciphertext, cloud_id, updated_at) VALUES (?, ?, ?, ?, datetime('now'))",
  ).run(userId, 'Token', encrypt('secret-pat'), '<script>alert(1)</script>');
  const res = await fetch(`${baseUrl}/credentials`, {
    headers: { Cookie: sessionCookieFor(userId) },
  });
  const body = await res.text();
  assert.ok(!body.includes('<script>alert(1)</script>'), 'raw script tag must never appear');
  assert.match(body, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
});

// --- R7: unknown ?error= renders no banner ---

test('GET /credentials?error=<unknown> renders no error banner (R7)', async () => {
  const { userId } = insertUserWithToken({ username: 'heidi' });
  const res = await fetch(`${baseUrl}/credentials?error=totally-unknown-value`, {
    headers: { Cookie: sessionCookieFor(userId) },
  });
  const body = await res.text();
  assert.ok(!body.includes('class="error"'), 'an unrecognized error code must render no banner');
});

test('GET /credentials?error=csrf renders the allow-listed CSRF error banner', async () => {
  const { userId } = insertUserWithToken({ username: 'ivan' });
  const res = await fetch(`${baseUrl}/credentials?error=csrf`, {
    headers: { Cookie: sessionCookieFor(userId) },
  });
  const body = await res.text();
  assert.match(body, /class="error"/);
  assert.match(body, /Your page expired\. Reload and try again\./);
});

// --- 5.3: form POST /me/atlassian and /me/atlassian/delete redirect to the panel ---

test('form POST /me/atlassian (cookie auth, valid CSRF) redirects 302 to /credentials', async () => {
  const { userId } = insertUserWithToken({ username: 'judy' });
  const token = issueCsrfToken(userId, SESSION_SECRET);
  const res = await fetch(`${baseUrl}/me/atlassian`, {
    method: 'POST',
    headers: {
      Cookie: sessionCookieFor(userId),
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: ORIGIN,
    },
    body: new URLSearchParams({ token: 'a-pat', scheme: 'Token', cloudId: 'cloud-1', csrf: token }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/credentials');

  const row = db.prepare('SELECT * FROM atlassian_credentials WHERE user_id = ?').get(userId);
  assert.ok(row, 'expected the credential row to have been written');
});

test('form POST /me/atlassian/delete (cookie auth, valid CSRF) redirects 302 and deletes only the caller row', async () => {
  const { userId: aliceId } = insertUserWithToken({ username: 'kate' });
  const { userId: bobId } = insertUserWithToken({ username: 'liam' });
  db.prepare(
    "INSERT INTO atlassian_credentials (user_id, scheme, ciphertext, updated_at) VALUES (?, ?, ?, datetime('now'))",
  ).run(aliceId, 'Token', encrypt('alice-pat'));
  db.prepare(
    "INSERT INTO atlassian_credentials (user_id, scheme, ciphertext, updated_at) VALUES (?, ?, ?, datetime('now'))",
  ).run(bobId, 'Token', encrypt('bob-pat'));

  const token = issueCsrfToken(aliceId, SESSION_SECRET);
  const res = await fetch(`${baseUrl}/me/atlassian/delete`, {
    method: 'POST',
    headers: {
      Cookie: sessionCookieFor(aliceId),
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: ORIGIN,
    },
    body: new URLSearchParams({ csrf: token }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/credentials');

  const aliceRow = db.prepare('SELECT * FROM atlassian_credentials WHERE user_id = ?').get(aliceId);
  assert.equal(aliceRow, undefined, "alice's row must be gone");
  const bobRow = db.prepare('SELECT * FROM atlassian_credentials WHERE user_id = ?').get(bobId);
  assert.ok(bobRow, "bob's row must be unaffected");
});

test('form POST /me/atlassian/delete without a CSRF token redirects 302 to /credentials?error=csrf', async () => {
  const { userId } = insertUserWithToken({ username: 'mallory' });
  const res = await fetch(`${baseUrl}/me/atlassian/delete`, {
    method: 'POST',
    headers: {
      Cookie: sessionCookieFor(userId),
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: ORIGIN,
    },
    body: new URLSearchParams({}),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/credentials?error=csrf');
});

test('form POST /me/atlassian with valid CSRF but a missing token field redirects 302 to /credentials?error=invalid', async () => {
  const { userId } = insertUserWithToken({ username: 'nate' });
  const token = issueCsrfToken(userId, SESSION_SECRET);
  const res = await fetch(`${baseUrl}/me/atlassian`, {
    method: 'POST',
    headers: {
      Cookie: sessionCookieFor(userId),
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: ORIGIN,
    },
    body: new URLSearchParams({ scheme: 'Token', csrf: token }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/credentials?error=invalid');
});
