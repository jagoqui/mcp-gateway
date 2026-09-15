import { test, before, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { openDb } from '../src/db.js';
import { createServer } from '../src/app.js';
import { createAdminSessionToken } from '../src/admin-session.js';
import { createSessionToken } from '../src/session.js';

const DOMAIN = 'test.example';
const SESSION_SECRET = 'test-session-secret';
const ADMIN_SECRET = 'test-admin-session-secret';

before(() => {
  process.env.ATLASSIAN_ENC_KEY = crypto.randomBytes(32).toString('base64');
  process.env.AUTH_GATEWAY_SESSION_SECRET = SESSION_SECRET;
  process.env.AUTH_GATEWAY_ADMIN_SESSION_SECRET = ADMIN_SECRET;
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
 * @param {{ username?: string, isAdmin?: boolean, disabled?: boolean }} [opts]
 */
function insertUser(opts = {}) {
  const { username = 'root-admin', isAdmin = true, disabled = false } = opts;
  const info = db
    .prepare(
      'INSERT INTO users (username, password_hash, is_admin, disabled_at) VALUES (?, ?, ?, ?)',
    )
    .run(username, 'bcrypt-placeholder', isAdmin ? 1 : 0, disabled ? '2024-01-01T00:00:00Z' : null);
  return Number(info.lastInsertRowid);
}

// 5.3 — GET /admin/verify: valid admin cookie -> 204.
test('GET /admin/verify returns 204 for a valid admin session cookie', async () => {
  const userId = insertUser({ username: 'root-admin' });
  const token = createAdminSessionToken(userId, ADMIN_SECRET);
  const res = await fetch(`${baseUrl}/admin/verify`, {
    headers: { Cookie: `__Host-admin_session=${token}` },
  });
  assert.equal(res.status, 204);
});

// 5.3 — no cookie -> 401 (plain JSON caller, no Accept: text/html).
test('GET /admin/verify returns 401 with no admin cookie and a non-browser Accept header', async () => {
  const res = await fetch(`${baseUrl}/admin/verify`, {
    headers: { Accept: 'application/json' },
  });
  assert.equal(res.status, 401);
});

// 5.3 — no cookie, Accept: text/html -> 302 (mirrors wantsHtml()'s dual-mode idiom).
test('GET /admin/verify redirects to the admin login page for a browser request with no admin cookie', async () => {
  const res = await fetch(`${baseUrl}/admin/verify`, {
    headers: { Accept: 'text/html,application/xhtml+xml' },
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  // Relative, not a separate admin.{domain} host: the admin session cookie
  // has no Domain= (host-only by design), so login must happen on
  // whichever host is actually protecting this resource.
  assert.equal(res.headers.get('location'), '/admin/login');
});

// 5.3/A1 — a regular, valid (non-admin-secret) session cookie never
// authenticates GET /admin/verify.
test('threat: a valid regular session cookie does not authenticate GET /admin/verify (A1)', async () => {
  const userId = insertUser({ username: 'root-admin' });
  const regularToken = createSessionToken({ uid: userId }, SESSION_SECRET);
  const res = await fetch(`${baseUrl}/admin/verify`, {
    headers: { Cookie: `session=${regularToken}` },
  });
  assert.equal(res.status, 401);
});

// 5.3/A2 — cross-panel non-reuse, both directions: an admin session cookie
// never authenticates GET /me/credentials.
test('threat: a valid admin session cookie does not authenticate GET /me/credentials (A2)', async () => {
  const userId = insertUser({ username: 'root-admin' });
  const adminToken = createAdminSessionToken(userId, ADMIN_SECRET);
  const res = await fetch(`${baseUrl}/me/credentials`, {
    headers: { Cookie: `__Host-admin_session=${adminToken}` },
  });
  assert.equal(res.status, 401);
  const body = /** @type {any} */ (await res.json());
  assert.equal(body.error, 'unauthenticated');
});

// 5.3/A7 — a forged Host/X-Forwarded-Host header with no admin cookie is
// still the standard unauthenticated response, never a bypass. The
// path-prefix boundary never reads Host (D2).
test('threat: a forged Host/X-Forwarded-Host header with no admin cookie never bypasses GET /admin/verify (A7)', async () => {
  const res = await fetch(`${baseUrl}/admin/verify`, {
    headers: {
      Host: 'admin.attacker-controlled.example',
      'X-Forwarded-Host': 'admin.attacker-controlled.example',
      Accept: 'application/json',
    },
  });
  assert.equal(res.status, 401);
});

// 5.5 — confirm an unrelated /admin/* path still 404s (dispatcher skeleton),
// and every existing route on app.js is unaffected by the new branch.
test('an unimplemented /admin/* path returns 404, not a crash', async () => {
  const res = await fetch(`${baseUrl}/admin/users`);
  assert.equal(res.status, 404);
});

// engram-unified-console Unit 1 — GET /admin/login

test('GET /admin/login renders a zero-JS form with no admin session required', async () => {
  const res = await fetch(`${baseUrl}/admin/login`);
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.ok(body.includes('<form'));
  assert.ok(!body.includes('<script'));
});

test('GET /admin/login preserves and escapes the next param', async () => {
  const res = await fetch(
    `${baseUrl}/admin/login?next=${encodeURIComponent('/monitor"><script>')}`,
  );
  const body = await res.text();
  assert.ok(!body.includes('<script>'));
});

// engram-unified-console Unit 1 — POST /admin/login

test('POST /admin/login with correct credentials for an is_admin user sets the admin cookie and redirects', async () => {
  const password = 'correct-horse-battery-staple';
  const { hashPassword } = await import('../src/tokens.js');
  const passwordHash = await hashPassword(password);
  db.prepare('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)').run(
    'jagoqui',
    passwordHash,
  );

  const res = await fetch(`${baseUrl}/admin/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username: 'jagoqui', password, next: '/monitor' }),
    redirect: 'manual',
  });

  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/monitor');
  const setCookie = res.headers.get('set-cookie') ?? '';
  assert.ok(setCookie.includes('__Host-admin_session='));
});

test('POST /admin/login with correct credentials for a non-admin user is rejected with the same generic failure as a wrong password', async () => {
  const password = 'correct-horse-battery-staple';
  const { hashPassword } = await import('../src/tokens.js');
  const passwordHash = await hashPassword(password);
  db.prepare('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 0)').run(
    'regular-user',
    passwordHash,
  );

  const res = await fetch(`${baseUrl}/admin/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username: 'regular-user', password }),
    redirect: 'manual',
  });

  assert.equal(res.status, 401);
  assert.equal(res.headers.get('set-cookie'), null);
  const body = await res.text();
  assert.ok(body.includes('Invalid username or password'));
});

test('POST /admin/login with the real monitor.{domain} Origin (where the form is actually served) succeeds', async () => {
  const password = 'correct-horse-battery-staple';
  const { hashPassword } = await import('../src/tokens.js');
  const passwordHash = await hashPassword(password);
  db.prepare('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)').run(
    'kevin',
    passwordHash,
  );

  const res = await fetch(`${baseUrl}/admin/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: `https://monitor.${DOMAIN}`,
    },
    body: new URLSearchParams({ username: 'kevin', password }),
    redirect: 'manual',
  });

  assert.equal(res.status, 302);
  assert.ok((res.headers.get('set-cookie') ?? '').includes('__Host-admin_session='));
});

test('POST /admin/login with the real engram-cloud.{domain} Origin (the other admin-gated host) also succeeds', async () => {
  const password = 'correct-horse-battery-staple';
  const { hashPassword } = await import('../src/tokens.js');
  const passwordHash = await hashPassword(password);
  db.prepare('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)').run(
    'laura',
    passwordHash,
  );

  const res = await fetch(`${baseUrl}/admin/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: `https://engram-cloud.${DOMAIN}`,
    },
    body: new URLSearchParams({ username: 'laura', password }),
    redirect: 'manual',
  });

  assert.equal(res.status, 302);
  assert.ok((res.headers.get('set-cookie') ?? '').includes('__Host-admin_session='));
});

test('POST /admin/login from a cross-site Origin is rejected before touching the database', async () => {
  const res = await fetch(`${baseUrl}/admin/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: 'https://attacker.example',
    },
    body: new URLSearchParams({ username: 'jagoqui', password: 'whatever' }),
  });
  assert.equal(res.status, 403);
});

test('POST /admin/login with a wrong password is rejected with no cookie set', async () => {
  const { hashPassword } = await import('../src/tokens.js');
  const passwordHash = await hashPassword('the-real-password');
  db.prepare('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)').run(
    'jagoqui',
    passwordHash,
  );

  const res = await fetch(`${baseUrl}/admin/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username: 'jagoqui', password: 'wrong-password' }),
    redirect: 'manual',
  });

  assert.equal(res.status, 401);
  assert.equal(res.headers.get('set-cookie'), null);
});
