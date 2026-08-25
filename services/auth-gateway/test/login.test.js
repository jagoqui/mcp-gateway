import { test, before, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { openDb } from '../src/db.js';
import { hashPassword } from '../src/tokens.js';
import { verifySessionToken, SESSION_COOKIE_NAME } from '../src/session.js';
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
 * @param {{ username?: string, password: string, disabled?: boolean }} opts
 * @returns {Promise<number>}
 */
async function insertUser(opts) {
  const { username = 'alice', password, disabled = false } = opts;
  const passwordHash = await hashPassword(password);
  const info = db
    .prepare('INSERT INTO users (username, password_hash, disabled_at) VALUES (?, ?, ?)')
    .run(username, passwordHash, disabled ? '2024-01-01T00:00:00Z' : null);
  return Number(info.lastInsertRowid);
}

test('POST /login with valid credentials sets an HttpOnly signed session cookie', async () => {
  const userId = await insertUser({ username: 'alice', password: 'correct horse battery staple' });
  const res = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'alice', password: 'correct horse battery staple' }),
  });
  assert.equal(res.status, 200);

  const setCookie = res.headers.get('set-cookie');
  assert.ok(setCookie, 'expected a Set-Cookie header');
  assert.match(setCookie ?? '', new RegExp(`^${SESSION_COOKIE_NAME}=`));
  assert.match(setCookie ?? '', /HttpOnly/i);
  assert.match(setCookie ?? '', /Path=\//i);

  const cookieValue = (setCookie ?? '').split(';')[0].split('=').slice(1).join('=');
  const payload = verifySessionToken(cookieValue, SESSION_SECRET);
  assert.ok(payload, 'expected the session cookie to be a valid signed token');
  assert.equal(payload?.uid, userId);
});

test('POST /login is case-insensitive on username (matches users.username COLLATE NOCASE)', async () => {
  await insertUser({ username: 'BobUser', password: 'a-strong-password' });
  const res = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'bobuser', password: 'a-strong-password' }),
  });
  assert.equal(res.status, 200);
  assert.ok(res.headers.get('set-cookie'));
});

test('POST /login rejects an incorrect password with 401 and sets no cookie', async () => {
  await insertUser({ username: 'carol', password: 'the-real-password' });
  const res = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'carol', password: 'a-wrong-guess' }),
  });
  assert.equal(res.status, 401);
  assert.equal(res.headers.get('set-cookie'), null);
});

test('POST /login rejects an unknown username with 401', async () => {
  const res = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'nobody', password: 'irrelevant' }),
  });
  assert.equal(res.status, 401);
});

test('POST /login rejects a disabled user with 401 even with the correct password', async () => {
  await insertUser({ username: 'dave', password: 'still-the-real-password', disabled: true });
  const res = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'dave', password: 'still-the-real-password' }),
  });
  assert.equal(res.status, 401);
  assert.equal(res.headers.get('set-cookie'), null);
});

test('POST /login rejects a malformed JSON body with 400', async () => {
  const res = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{not valid json',
  });
  assert.equal(res.status, 400);
});
