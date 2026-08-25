import { test, before, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { openDb } from '../src/db.js';
import { hashToken } from '../src/tokens.js';
import { decrypt } from '../src/crypto.js';
import { createServer } from '../src/app.js';

const DOMAIN = 'test.example';
const SESSION_SECRET = 'test-session-secret';

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

test('POST /me/atlassian stores an encrypted credential for the authenticated user', async () => {
  const { userId, rawToken } = insertUserWithToken({ username: 'alice' });
  const res = await fetch(`${baseUrl}/me/atlassian`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${rawToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ token: 'my-atlassian-pat', scheme: 'Token', cloudId: 'cloud-123' }),
  });
  assert.equal(res.status, 200);

  const row = /** @type {any} */ (
    db.prepare('SELECT * FROM atlassian_credentials WHERE user_id = ?').get(userId)
  );
  assert.ok(row, 'expected an atlassian_credentials row to be inserted');
  assert.equal(row.scheme, 'Token');
  assert.equal(row.cloud_id, 'cloud-123');
  assert.notEqual(row.ciphertext, 'my-atlassian-pat');
  assert.equal(decrypt(row.ciphertext), 'my-atlassian-pat');
});

test('POST /me/atlassian upserts (re-enrolling replaces the previous credential)', async () => {
  const { userId, rawToken } = insertUserWithToken({ username: 'bob' });
  const headers = {
    Authorization: `Bearer ${rawToken}`,
    'Content-Type': 'application/json',
  };
  await fetch(`${baseUrl}/me/atlassian`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ token: 'first-pat', scheme: 'Token' }),
  });
  const res = await fetch(`${baseUrl}/me/atlassian`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ token: 'second-pat', scheme: 'Bearer' }),
  });
  assert.equal(res.status, 200);

  const rows = db.prepare('SELECT * FROM atlassian_credentials WHERE user_id = ?').all(userId);
  assert.equal(rows.length, 1);
  const row = /** @type {any} */ (rows[0]);
  assert.equal(row.scheme, 'Bearer');
  assert.equal(decrypt(row.ciphertext), 'second-pat');
});

test('POST /me/atlassian requires authentication (401 without a valid Bearer/cookie)', async () => {
  const res = await fetch(`${baseUrl}/me/atlassian`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: 'x', scheme: 'Token' }),
  });
  assert.equal(res.status, 401);
});

test('POST /me/atlassian rejects a request missing the required token field with 400', async () => {
  const { rawToken } = insertUserWithToken({ username: 'carol' });
  const res = await fetch(`${baseUrl}/me/atlassian`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${rawToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ scheme: 'Token' }),
  });
  assert.equal(res.status, 400);
});

test('threat: POST /me/atlassian never trusts a client-supplied user id — it always writes to the authenticated caller', async () => {
  const alice = insertUserWithToken({ username: 'alice2' });
  const bob = insertUserWithToken({ username: 'bob2' });
  await fetch(`${baseUrl}/me/atlassian`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${alice.rawToken}`,
      'Content-Type': 'application/json',
    },
    // even if a client tried to smuggle a target user id in the body, it
    // must be ignored — identity comes only from the Bearer/cookie.
    body: JSON.stringify({ token: 'alices-pat', scheme: 'Token', userId: bob.userId }),
  });
  const bobRow = db
    .prepare('SELECT * FROM atlassian_credentials WHERE user_id = ?')
    .get(bob.userId);
  assert.equal(bobRow, undefined, "bob's credential row must not have been written");
  const aliceRow = /** @type {any} */ (
    db.prepare('SELECT * FROM atlassian_credentials WHERE user_id = ?').get(alice.userId)
  );
  assert.equal(decrypt(aliceRow.ciphertext), 'alices-pat');
});
