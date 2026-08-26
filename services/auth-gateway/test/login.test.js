import { test, before, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { openDb } from '../src/db.js';
import { hashPassword } from '../src/tokens.js';
import { verifySessionToken, SESSION_COOKIE_NAME } from '../src/session.js';
import { createServer } from '../src/app.js';
import { sanitizeNext } from '../src/login-page.js';

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

// --- sanitizeNext (R1) ---

test('sanitizeNext rejects protocol-relative, backslash, and absolute-URL open-redirect attempts', () => {
  assert.equal(sanitizeNext('//evil.example'), '/credentials');
  assert.equal(sanitizeNext('/\\evil.example'), '/credentials');
  assert.equal(sanitizeNext('https://evil.example'), '/credentials');
  assert.equal(sanitizeNext(''), '/credentials');
  assert.equal(sanitizeNext(undefined), '/credentials');
  assert.equal(sanitizeNext(null), '/credentials');
});

// R1 (CRITICAL, RDD-review Unit 4): the WHATWG URL parser strips embedded
// ASCII tab/CR/LF before scheme/host resolution, so a leading-slash value
// with a control character embedded before a second slash previously passed
// sanitizeNext's prefix checks unmodified and was re-parsed by the browser
// as a protocol-relative redirect to the attacker-controlled host.
test('threat: sanitizeNext rejects a tab/CR/LF-smuggled protocol-relative bypass (R1)', () => {
  assert.equal(sanitizeNext('/\t/evil.example'), '/credentials');
  assert.equal(sanitizeNext('/\r/evil.example'), '/credentials');
  assert.equal(sanitizeNext('/\n/evil.example'), '/credentials');
  assert.equal(sanitizeNext('/cre\tdentials'), '/credentials');
});

test('sanitizeNext accepts a safe single-leading-slash path unchanged', () => {
  assert.equal(sanitizeNext('/credentials'), '/credentials');
  assert.equal(sanitizeNext('/foo/bar?x=1'), '/foo/bar?x=1');
});

// --- GET /login ---

test('GET /login renders a 200 html form with no <script> and the required security headers', async () => {
  const res = await fetch(`${baseUrl}/login?next=%2Fcredentials`);
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type') ?? '', /text\/html/);
  assert.equal(
    res.headers.get('content-security-policy'),
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  );
  assert.equal(res.headers.get('cache-control'), 'no-store');
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');

  const body = await res.text();
  assert.ok(!body.includes('<script'), 'login page body must contain no <script> tag');
  assert.match(body, /name="username"/);
  assert.match(body, /name="password"/);
  assert.match(body, /action="\/login"/);
});

test('GET /login preserves and escapes the next value in the hidden field', async () => {
  const res = await fetch(`${baseUrl}/login?next=${encodeURIComponent('/foo"bar')}`);
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.match(body, /name="next" value="\/foo&quot;bar"/);
});

test('GET /login falls back to /credentials in the hidden next field for an unsafe next value', async () => {
  const res = await fetch(`${baseUrl}/login?next=${encodeURIComponent('https://evil.example')}`);
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.match(body, /name="next" value="\/credentials"/);
});

// --- POST /login (form) ---

test('form POST /login success redirects to next and sets a fresh session cookie (no fixation)', async () => {
  const userId = await insertUser({ username: 'erin', password: 'erin-pw-12345' });
  const attackerCookie = `${SESSION_COOKIE_NAME}=some-attacker-planted-value`;
  const res = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Cookie: attackerCookie,
    },
    body: new URLSearchParams({
      username: 'erin',
      password: 'erin-pw-12345',
      next: '/credentials',
    }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/credentials');

  const setCookie = res.headers.get('set-cookie');
  assert.ok(setCookie, 'expected a fresh Set-Cookie header');
  assert.notEqual(
    setCookie?.split(';')[0],
    attackerCookie,
    'must not reuse a client-supplied pre-existing cookie value',
  );

  const cookieValue = (setCookie ?? '').split(';')[0].split('=').slice(1).join('=');
  const payload = verifySessionToken(cookieValue, SESSION_SECRET);
  assert.ok(payload, 'expected a validly signed fresh session token');
  assert.equal(payload?.uid, userId);
});

test('form POST /login failure re-renders 401 html with a generic error, username preserved, password not echoed', async () => {
  await insertUser({ username: 'frank', password: 'the-real-password' });
  const res = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      username: 'frank',
      password: 'wrong-guess',
      next: '/credentials',
    }),
  });
  assert.equal(res.status, 401);
  assert.match(res.headers.get('content-type') ?? '', /text\/html/);
  assert.equal(res.headers.get('set-cookie'), null);

  const body = await res.text();
  assert.match(body, /Invalid username or password\./);
  assert.match(body, /value="frank"/);
  assert.ok(!body.includes('wrong-guess'), 'password must never be echoed back');
});

test('JSON POST /login behavior is unchanged after form support was added', async () => {
  const userId = await insertUser({ username: 'grace', password: 'grace-pw-2026' });
  const res = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'grace', password: 'grace-pw-2026' }),
  });
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type') ?? '', /application\/json/);
  const json = await res.json();
  assert.equal(json.ok, true);

  const setCookie = res.headers.get('set-cookie');
  const cookieValue = (setCookie ?? '').split(';')[0].split('=').slice(1).join('=');
  const payload = verifySessionToken(cookieValue, SESSION_SECRET);
  assert.equal(payload?.uid, userId);
});

// --- POST /login Origin check (R5, D5) ---

test('POST /login with a cross-site Origin is rejected with 403 csrf_origin_rejected (R5)', async () => {
  await insertUser({ username: 'henry', password: 'henry-pw-2026' });
  const res = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example' },
    body: JSON.stringify({ username: 'henry', password: 'henry-pw-2026' }),
  });
  assert.equal(res.status, 403);
  const json = await res.json();
  assert.equal(json.error, 'csrf_origin_rejected');
  assert.equal(res.headers.get('set-cookie'), null);
});

test('POST /login without an Origin header still succeeds (CLI/curl unaffected, D5 allow-on-absent)', async () => {
  await insertUser({ username: 'iris', password: 'iris-pw-2026' });
  const res = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'iris', password: 'iris-pw-2026' }),
  });
  assert.equal(res.status, 200);
  assert.ok(res.headers.get('set-cookie'));
});
