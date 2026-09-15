import { test, before, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { openDb } from '../src/db.js';
import { createServer } from '../src/app.js';
import { createAdminSessionToken } from '../src/admin-session.js';
import { createSessionToken } from '../src/session.js';
import { issueAdminCsrfToken } from '../src/csrf.js';
import { ADMIN_LOGIN_MAX_ATTEMPTS } from '../src/admin-throttle.js';

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
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: `https://monitor.${DOMAIN}`,
    },
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
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: `https://monitor.${DOMAIN}`,
    },
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

// D7 — strict Origin: unlike the regular /login (app.js, strict: false, no
// CLI use case here), an admin-login POST with neither Origin nor Referer
// is rejected outright rather than allowed through.
test('POST /admin/login with no Origin and no Referer at all is rejected (D7, strict)', async () => {
  const res = await fetch(`${baseUrl}/admin/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username: 'jagoqui', password: 'whatever' }),
  });
  assert.equal(res.status, 403);
  const body = /** @type {any} */ (await res.json());
  assert.equal(body.error, 'csrf_origin_rejected');
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
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: `https://monitor.${DOMAIN}`,
    },
    body: new URLSearchParams({ username: 'jagoqui', password: 'wrong-password' }),
    redirect: 'manual',
  });

  assert.equal(res.status, 401);
  assert.equal(res.headers.get('set-cookie'), null);
});

// Phase 6 — admin login throttle (A9/D12/D13)

/** @returns {any[]} */
function allAuditRows() {
  return db.prepare('SELECT * FROM admin_audit_log ORDER BY id').all();
}

/**
 * POST /admin/login with a fresh URLSearchParams body every call — sending
 * one URLSearchParams instance twice silently posts an empty body the
 * second time (fetch consumes it as a stream). Always carries a real
 * monitor.{domain} Origin: strict Origin checking (D7) now rejects an
 * absent Origin/Referer outright, so every test exercising past-the-Origin-
 * gate behavior needs one.
 * @param {{ username: string, password: string }} creds
 */
function postAdminLogin(creds) {
  return fetch(`${baseUrl}/admin/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: `https://monitor.${DOMAIN}`,
    },
    body: new URLSearchParams(creds),
    redirect: 'manual',
  });
}

test('the 6th failed attempt for one username within the window is 429, even with the correct password', async () => {
  const username = 'throttle-lockout-test';
  const password = 'correct-horse-battery-staple';
  const { hashPassword } = await import('../src/tokens.js');
  const passwordHash = await hashPassword(password);
  db.prepare('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)').run(
    username,
    passwordHash,
  );

  for (let i = 0; i < ADMIN_LOGIN_MAX_ATTEMPTS; i += 1) {
    const res = await postAdminLogin({ username, password: 'wrong-password' });
    assert.equal(res.status, 401);
  }

  const res = await postAdminLogin({ username, password });
  assert.equal(res.status, 429);
  assert.equal(res.headers.get('set-cookie'), null);
});

test('the throttle key folds case — 6th attempt with a different-case username is still 429', async () => {
  const username = 'Throttle-Case-Test';
  const { hashPassword } = await import('../src/tokens.js');
  db.prepare('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)').run(
    username,
    await hashPassword('whatever'),
  );

  for (let i = 0; i < ADMIN_LOGIN_MAX_ATTEMPTS; i += 1) {
    await postAdminLogin({ username, password: 'wrong-password' });
  }

  const res = await postAdminLogin({ username: username.toUpperCase(), password: 'whatever' });
  assert.equal(res.status, 429);
});

test('a successful login resets the throttle for that username', async () => {
  const username = 'throttle-reset-test';
  const password = 'correct-horse-battery-staple';
  const { hashPassword } = await import('../src/tokens.js');
  db.prepare('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)').run(
    username,
    await hashPassword(password),
  );

  await postAdminLogin({ username, password: 'wrong-password' });
  await postAdminLogin({ username, password: 'wrong-password' });
  const successRes = await postAdminLogin({ username, password });
  assert.equal(successRes.status, 302);

  // Below the 5-failure threshold again right after the reset.
  await postAdminLogin({ username, password: 'wrong-password' });
  const stillOkRes = await postAdminLogin({ username, password });
  assert.equal(stillOkRes.status, 302);
});

test('every POST /admin/login outcome writes one audit row with the right reason', async () => {
  const username = 'audit-outcomes-test';
  const password = 'correct-horse-battery-staple';
  const { hashPassword } = await import('../src/tokens.js');
  db.prepare('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 0)').run(
    username,
    await hashPassword(password),
  );

  await postAdminLogin({ username, password: 'wrong-password' });
  await postAdminLogin({ username, password }); // correct password, but is_admin = 0

  const rows = allAuditRows();
  assert.equal(rows.length, 2);
  assert.equal(rows[0].action, 'login');
  assert.equal(rows[0].outcome, 'failure');
  assert.equal(JSON.parse(rows[0].detail).reason, 'bad_credentials');
  assert.equal(rows[0].actor_user_id, null);
  assert.equal(rows[1].outcome, 'failure');
  assert.equal(JSON.parse(rows[1].detail).reason, 'not_admin');
});

test('a successful POST /admin/login audits action=login outcome=success with the real actorUserId', async () => {
  const username = 'audit-success-test';
  const password = 'correct-horse-battery-staple';
  const { hashPassword } = await import('../src/tokens.js');
  const info = db
    .prepare('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)')
    .run(username, await hashPassword(password));

  await postAdminLogin({ username, password });

  const rows = allAuditRows();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].action, 'login');
  assert.equal(rows[0].outcome, 'success');
  assert.equal(rows[0].actor_user_id, Number(info.lastInsertRowid));
});

// Phase 7 — POST /admin/logout (full 5-step admin write guard)

test('POST /admin/logout with no admin cookie returns 401', async () => {
  const res = await fetch(`${baseUrl}/admin/logout`, { method: 'POST' });
  assert.equal(res.status, 401);
});

test('POST /admin/logout with a mismatched Origin returns 403, before touching CSRF', async () => {
  const userId = insertUser({ username: 'logout-origin-test' });
  const token = createAdminSessionToken(userId, ADMIN_SECRET);
  const res = await fetch(`${baseUrl}/admin/logout`, {
    method: 'POST',
    headers: {
      Cookie: `__Host-admin_session=${token}`,
      Origin: 'https://attacker.example',
    },
  });
  assert.equal(res.status, 403);
});

test('POST /admin/logout as JSON with a missing CSRF token returns 403 csrf_token_invalid', async () => {
  const userId = insertUser({ username: 'logout-csrf-json-test' });
  const token = createAdminSessionToken(userId, ADMIN_SECRET);
  const res = await fetch(`${baseUrl}/admin/logout`, {
    method: 'POST',
    headers: {
      Cookie: `__Host-admin_session=${token}`,
      Origin: `https://monitor.${DOMAIN}`,
    },
  });
  assert.equal(res.status, 403);
  const body = /** @type {any} */ (await res.json());
  assert.equal(body.error, 'csrf_token_invalid');
});

test('POST /admin/logout as a form with a missing CSRF token redirects to /admin/login, cookie untouched', async () => {
  const userId = insertUser({ username: 'logout-csrf-form-test' });
  const token = createAdminSessionToken(userId, ADMIN_SECRET);
  const res = await fetch(`${baseUrl}/admin/logout`, {
    method: 'POST',
    headers: {
      Cookie: `__Host-admin_session=${token}`,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({}),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/login');
  assert.equal(res.headers.get('set-cookie'), null);
});

test('POST /admin/logout with a valid CSRF header clears the cookie and audits logout', async () => {
  const userId = insertUser({ username: 'logout-success-json-test' });
  const token = createAdminSessionToken(userId, ADMIN_SECRET);
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const res = await fetch(`${baseUrl}/admin/logout`, {
    method: 'POST',
    headers: {
      Cookie: `__Host-admin_session=${token}`,
      Origin: `https://monitor.${DOMAIN}`,
      'X-CSRF-Token': csrf,
    },
  });
  assert.equal(res.status, 200);
  const setCookie = res.headers.get('set-cookie') ?? '';
  assert.ok(setCookie.includes('__Host-admin_session='));
  assert.ok(setCookie.includes('Max-Age=0'));

  const rows = allAuditRows();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].action, 'logout');
  assert.equal(rows[0].outcome, 'success');
  assert.equal(rows[0].actor_user_id, userId);
});

test('POST /admin/logout as a form with a valid CSRF field redirects to /admin/login and clears the cookie', async () => {
  const userId = insertUser({ username: 'logout-success-form-test' });
  const token = createAdminSessionToken(userId, ADMIN_SECRET);
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const res = await fetch(`${baseUrl}/admin/logout`, {
    method: 'POST',
    headers: {
      Cookie: `__Host-admin_session=${token}`,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/login');
  const setCookie = res.headers.get('set-cookie') ?? '';
  assert.ok(setCookie.includes('Max-Age=0'));
});

test('a regular (non-admin) session cookie never authenticates POST /admin/logout', async () => {
  const userId = insertUser({ username: 'logout-regular-cookie-test' });
  const regularToken = createSessionToken({ uid: userId }, SESSION_SECRET);
  const res = await fetch(`${baseUrl}/admin/logout`, {
    method: 'POST',
    headers: { Cookie: `session=${regularToken}` },
  });
  assert.equal(res.status, 401);
});
