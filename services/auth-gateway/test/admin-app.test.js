import { test, before, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { openDb } from '../src/db.js';
import { createServer } from '../src/app.js';
import { createAdminSessionToken } from '../src/admin-session.js';
import { createSessionToken } from '../src/session.js';
import { issueAdminCsrfToken } from '../src/csrf.js';
import { ADMIN_LOGIN_MAX_ATTEMPTS } from '../src/admin-throttle.js';
import { encrypt } from '../src/crypto.js';
import http from 'node:http';

const DOMAIN = 'test.example';
const SESSION_SECRET = 'test-session-secret';
const ADMIN_SECRET = 'test-admin-session-secret';
const INTERNAL_SECRET = 'test-engram-router-internal-secret';

before(() => {
  process.env.ATLASSIAN_ENC_KEY = crypto.randomBytes(32).toString('base64');
  process.env.AUTH_GATEWAY_SESSION_SECRET = SESSION_SECRET;
  process.env.AUTH_GATEWAY_ADMIN_SESSION_SECRET = ADMIN_SECRET;
  process.env.ENGRAM_ROUTER_INTERNAL_SECRET = INTERNAL_SECRET;
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
 * @param {{ username?: string, isAdmin?: boolean, disabled?: boolean, role?: string }} [opts]
 */
function insertUser(opts = {}) {
  const { username = 'root-admin', isAdmin = true, disabled = false, role = 'admin' } = opts;
  const info = db
    .prepare(
      'INSERT INTO users (username, password_hash, is_admin, disabled_at, role) VALUES (?, ?, ?, ?, ?)',
    )
    .run(username, 'bcrypt-placeholder', isAdmin ? 1 : 0, disabled ? '2024-01-01T00:00:00Z' : null, role);
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
// Every named /admin/* route is implemented as of Unit 11 (only Unit 12's
// Caddyfile wiring remains) — a made-up path is the only genuinely
// unimplemented example left.
test('an unimplemented /admin/* path returns 404, not a crash', async () => {
  const res = await fetch(`${baseUrl}/admin/does-not-exist`);
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

// Regression (found live on the VPS, 2026-09-16): admin-login-page.js's
// renderAdminLoginPage imports sanitizeNext from login-page.js, whose
// default fallback is '/credentials' (the REGULAR user panel) — an admin
// landing on /admin/login directly with no ?next= (the common case) was
// getting a hidden `next` field of '/credentials', not '/admin/users'.
test('GET /admin/login with no next param defaults the hidden next field to /admin/users, not /credentials', async () => {
  const res = await fetch(`${baseUrl}/admin/login`);
  const body = await res.text();
  assert.ok(body.includes('name="next" value="/admin/users"'));
});

// Regression (found live on the VPS, 2026-09-16): GET/POST /admin/login
// must NOT carry Referrer-Policy: no-referrer. Chrome ties a top-level
// navigation's Origin header to the page's referrer policy — with
// no-referrer set, it sends Origin: null on the login form's POST instead
// of the real same-origin value, which isAcceptableOrigin correctly (and
// unavoidably) rejects as an opaque origin (A6/R5), 403ing every real
// browser login. No secret is ever rendered on this page, so
// Referrer-Policy bought nothing here — only the authenticated pages
// (users/tokens) keep it.
test('GET /admin/login carries CSP/no-store/nosniff but NOT Referrer-Policy', async () => {
  const res = await fetch(`${baseUrl}/admin/login`);
  assert.ok(res.headers.get('content-security-policy'));
  assert.equal(res.headers.get('cache-control'), 'no-store');
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('referrer-policy'), null);
});

test('POST /admin/login failure response does not carry Referrer-Policy either', async () => {
  const res = await fetch(`${baseUrl}/admin/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: `https://monitor.${DOMAIN}`,
    },
    body: new URLSearchParams({ username: 'nobody', password: 'wrong' }),
  });
  assert.equal(res.headers.get('referrer-policy'), null);
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

// Regression (found live on the VPS, 2026-09-16): same bug as the GET
// /admin/login test above, on the POST success redirect this time — a real
// admin login with no next field (the common case) was landing on
// /credentials instead of /admin/users.
test('POST /admin/login with no next field redirects to /admin/users, not /credentials', async () => {
  const password = 'correct-horse-battery-staple';
  const { hashPassword } = await import('../src/tokens.js');
  const passwordHash = await hashPassword(password);
  db.prepare('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)').run(
    'kellan',
    passwordHash,
  );

  const res = await fetch(`${baseUrl}/admin/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: `https://monitor.${DOMAIN}`,
    },
    body: new URLSearchParams({ username: 'kellan', password }),
    redirect: 'manual',
  });

  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/users');
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

// Phase 8 — GET /admin/users + POST /admin/users

/** @returns {{ userId: number, cookie: string, adminSecret: string }} */
function loginAsAdmin(username = 'unit8-admin') {
  const userId = insertUser({ username });
  const token = createAdminSessionToken(userId, ADMIN_SECRET);
  return { userId, cookie: `__Host-admin_session=${token}` };
}

/** @returns {{ userId: number, cookie: string }} */
function loginAsMember(username = 'unit-member') {
  const userId = insertUser({ username, role: 'member' });
  const token = createAdminSessionToken(userId, ADMIN_SECRET);
  return { userId, cookie: `__Host-admin_session=${token}` };
}

test('GET /admin/users with no admin cookie and a non-html Accept returns 401 JSON', async () => {
  const res = await fetch(`${baseUrl}/admin/users`, { headers: { Accept: 'application/json' } });
  assert.equal(res.status, 401);
});

test('GET /admin/users with Accept: text/html and no admin cookie redirects to /admin/login?next=%2Fadmin%2Fusers', async () => {
  const res = await fetch(`${baseUrl}/admin/users`, {
    headers: { Accept: 'text/html' },
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/login?next=%2Fadmin%2Fusers');
});

test('a regular (non-admin) session cookie never authenticates GET /admin/users', async () => {
  const userId = insertUser({ username: 'users-regular-cookie-test' });
  const regularToken = createSessionToken({ uid: userId }, SESSION_SECRET);
  const res = await fetch(`${baseUrl}/admin/users`, {
    headers: { Cookie: `session=${regularToken}`, Accept: 'application/json' },
  });
  assert.equal(res.status, 401);
});

test('GET /admin/users renders 200 html with the CSP/no-store/nosniff/same-origin-referrer header set and no <script>', async () => {
  const { cookie } = loginAsAdmin();
  const res = await fetch(`${baseUrl}/admin/users`, { headers: { Cookie: cookie } });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-type'), 'text/html; charset=utf-8');
  assert.ok(res.headers.get('content-security-policy'));
  assert.equal(res.headers.get('cache-control'), 'no-store');
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  // same-origin (not no-referrer): the earlier no-referrer value made Chrome
  // send Origin: null on this page's own top-level form POSTs (logout,
  // create-user, disable/enable, grants, tokens) — the same Chromium quirk
  // already fixed on the login page, found live (2026-09-16) via logout.
  // same-origin still sends Referer for requests to this same host (so the
  // strict Origin/Referer CSRF check keeps working) while still never
  // leaking it to a third party the URL might be pasted into (D10).
  assert.equal(res.headers.get('referrer-policy'), 'same-origin');
  const body = await res.text();
  assert.ok(!body.includes('<script'));
});

// User-requested (2026-09-17): admin-panel accounts (admin/member, the
// ones created via login/import/bin/admin.js --admin) and their role
// were invisible anywhere in the UI — GET /admin/users now also lists
// them, distinct from the regular-gateway-users table already there.
test('GET /admin/users also lists admin-panel accounts with their role', async () => {
  const { cookie } = loginAsAdmin('roles-list-viewer');
  db.prepare("INSERT INTO users (username, password_hash, is_admin, role) VALUES ('some-member', 'hash', 1, 'member')").run();

  const res = await fetch(`${baseUrl}/admin/users`, { headers: { Cookie: cookie } });
  const body = await res.text();
  assert.ok(body.includes('roles-list-viewer'));
  assert.ok(body.includes('some-member'));
  assert.ok(body.includes('member'));
});

// User-requested (2026-09-18): the two separate tables this page used to
// have (regular gateway users vs admin-panel accounts) were confusing —
// merged into ONE table, admin-panel accounts also showing their linked
// Cloud principal (or a clear "not linked" note) and a link to their own
// Profile page instead of the regular /tokens page.
test('GET /admin/users renders regular users and admin-panel accounts in the SAME table, admin accounts showing their Cloud principal', async () => {
  const { cookie } = loginAsAdmin('unified-table-viewer');
  insertUser({ username: 'unified-table-regular', isAdmin: false });
  const memberId = insertUser({ username: 'unified-table-member', role: 'member' });
  db.prepare(
    "INSERT INTO engram_cloud_credentials (user_id, principal_id, ciphertext, updated_at) VALUES (?, 'p-unified-1', 'irrelevant', datetime('now'))",
  ).run(memberId);

  const res = await fetch(`${baseUrl}/admin/users`, { headers: { Cookie: cookie } });
  const body = await res.text();
  // Exactly one <table> on the page — both kinds of rows share it.
  assert.equal((body.match(/<table>/g) ?? []).length, 1);
  assert.ok(body.includes('unified-table-regular'));
  assert.ok(body.includes('unified-table-member'));
  assert.ok(body.includes('p-unified-1'));
  assert.ok(body.includes(`href="/admin/profile?userId=${memberId}"`));
});

// Found live (2026-09-16): POST /admin/logout has existed since Unit 7,
// but no rendered page ever offered a way to trigger it, nor a way to
// reach /dashboard or /monitor without leaving the admin panel first.
test('GET /admin/users renders a nav with Users/Dashboard/Monitor links and a Log out form', async () => {
  const { cookie } = loginAsAdmin();
  const res = await fetch(`${baseUrl}/admin/users`, { headers: { Cookie: cookie } });
  const body = await res.text();
  // Phase 5: these now route through the console shell (SSO + shared
  // header/sidebar/main), not straight to /dashboard or /monitor.
  assert.ok(body.includes('href="/admin/console?view=cloud"'));
  assert.ok(body.includes('href="/admin/console?view=monitor"'));
  assert.ok(body.includes('action="/admin/logout"'));
});

test('GET /admin/users lists only is_admin=0 users in the regular-users table, with disabled state and token counts', async () => {
  const { cookie } = loginAsAdmin('roles-not-in-regular-list-viewer');
  const regularId = insertUser({ username: 'regular-listed', isAdmin: false });
  insertUser({ username: 'disabled-listed', isAdmin: false, disabled: true });
  db.prepare('INSERT INTO tokens (user_id, token_hash) VALUES (?, ?)').run(
    regularId,
    'hash-active',
  );
  db.prepare(
    "INSERT INTO tokens (user_id, token_hash, revoked_at) VALUES (?, ?, datetime('now'))",
  ).run(regularId, 'hash-revoked');

  const res = await fetch(`${baseUrl}/admin/users`, { headers: { Cookie: cookie } });
  const body = await res.text();
  assert.ok(body.includes('regular-listed'));
  assert.ok(body.includes('disabled-listed'));
  // The logged-in admin's own username now legitimately appears twice —
  // once in the "Logged in as" nav banner, once in the separate "Admin
  // panel accounts" table (below) — never in the regular-users table
  // this test is actually scoped to (which would make it three).
  const occurrences = body.split('roles-not-in-regular-list-viewer').length - 1;
  assert.equal(occurrences, 2);
});

test('threat: a malicious username is HTML-escaped in the rendered users list, not live markup (A12)', async () => {
  const { cookie } = loginAsAdmin();
  insertUser({ username: '<img src=x onerror=alert(1)>', isAdmin: false });
  const res = await fetch(`${baseUrl}/admin/users`, { headers: { Cookie: cookie } });
  const body = await res.text();
  assert.ok(!body.includes('<img src=x onerror'));
  assert.ok(body.includes('&lt;img'));
});

test('GET /admin/users?error=<unknown> renders no error banner', async () => {
  const { cookie } = loginAsAdmin();
  const res = await fetch(`${baseUrl}/admin/users?error=not-a-real-code`, {
    headers: { Cookie: cookie },
  });
  const body = await res.text();
  assert.ok(!body.includes('class="error"'));
});

test('GET /admin/users embeds a hidden csrf field that verifies for the caller uid', async () => {
  const { cookie, userId } = loginAsAdmin();
  const res = await fetch(`${baseUrl}/admin/users`, { headers: { Cookie: cookie } });
  const body = await res.text();
  const match = body.match(/name="csrf" value="([^"]+)"/);
  assert.ok(match, 'expected a hidden csrf field');
  const { verifyAdminCsrfToken } = await import('../src/csrf.js');
  assert.equal(verifyAdminCsrfToken(match[1], { uid: userId, adminSecret: ADMIN_SECRET }), true);
});

test('POST /admin/users with valid admin cookie, Origin, and CSRF creates an is_admin=0 user and redirects', async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const res = await fetch(`${baseUrl}/admin/users`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      username: 'brand-new-user',
      password: 'a-strong-password',
      passwordConfirm: 'a-strong-password',
      csrf,
    }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/users');

  const row = /** @type {any} */ (
    db.prepare('SELECT * FROM users WHERE username = ?').get('brand-new-user')
  );
  assert.ok(row);
  assert.equal(row.is_admin, 0);
});

test('POST /admin/users cannot set is_admin via the body — a spoofed isAdmin field is ignored', async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  await fetch(`${baseUrl}/admin/users`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      username: 'spoofed-admin-attempt',
      password: 'a-strong-password',
      passwordConfirm: 'a-strong-password',
      isAdmin: 'true',
      csrf,
    }),
    redirect: 'manual',
  });
  const row = /** @type {any} */ (
    db.prepare('SELECT * FROM users WHERE username = ?').get('spoofed-admin-attempt')
  );
  assert.equal(row.is_admin, 0);
});

test('POST /admin/users with a duplicate username redirects to /admin/users?error=duplicate, no row created', async () => {
  const { cookie, userId } = loginAsAdmin();
  insertUser({ username: 'already-taken', isAdmin: false });
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const res = await fetch(`${baseUrl}/admin/users`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      username: 'already-taken',
      password: 'a-strong-password',
      passwordConfirm: 'a-strong-password',
      csrf,
    }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/users?error=duplicate');
  const count = /** @type {any} */ (
    db.prepare('SELECT COUNT(*) AS n FROM users WHERE username = ?').get('already-taken')
  ).n;
  assert.equal(count, 1);
});

test('POST /admin/users with a password/passwordConfirm mismatch redirects to /admin/users?error=mismatch, no row created', async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const res = await fetch(`${baseUrl}/admin/users`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      username: 'mismatch-attempt',
      password: 'a-strong-password',
      passwordConfirm: 'a-different-password',
      csrf,
    }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/users?error=mismatch');
  const row = db.prepare('SELECT * FROM users WHERE username = ?').get('mismatch-attempt');
  assert.equal(row, undefined);
});

test('POST /admin/users as JSON is not required to send passwordConfirm', async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const res = await fetch(`${baseUrl}/admin/users`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ username: 'json-caller-user', password: 'a-strong-password', csrf }),
  });
  assert.equal(res.status, 200);
});

test('POST /admin/users with a missing password redirects to /admin/users?error=invalid', async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const res = await fetch(`${baseUrl}/admin/users`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ username: 'no-password-user', csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/users?error=invalid');
});

test('POST /admin/users with a mismatched Origin returns 403, before touching the database', async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const res = await fetch(`${baseUrl}/admin/users`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: 'https://attacker.example',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ username: 'never-created', password: 'whatever', csrf }),
  });
  assert.equal(res.status, 403);
  const row = db.prepare('SELECT * FROM users WHERE username = ?').get('never-created');
  assert.equal(row, undefined);
});

test('POST /admin/users with a missing CSRF token (form) redirects to /admin/users?error=csrf', async () => {
  const { cookie } = loginAsAdmin();
  const res = await fetch(`${baseUrl}/admin/users`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ username: 'csrf-missing-user', password: 'whatever' }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/users?error=csrf');
});

test('POST /admin/users with no admin cookie returns 401', async () => {
  const res = await fetch(`${baseUrl}/admin/users`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username: 'nope', password: 'whatever' }),
  });
  assert.equal(res.status, 401);
});

test('a successful POST /admin/users writes one user.create audit row', async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  await fetch(`${baseUrl}/admin/users`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      username: 'audited-new-user',
      password: 'a-strong-password',
      passwordConfirm: 'a-strong-password',
      csrf,
    }),
  });
  const rows = db.prepare('SELECT * FROM admin_audit_log').all();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].action, 'user.create');
  assert.equal(rows[0].outcome, 'success');
  assert.equal(rows[0].actor_user_id, userId);
});

// Phase 9 — POST /admin/users/disable + POST /admin/users/enable

test('POST /admin/users/disable with a valid target sets disabled_at, leaves tokens untouched, redirects, and audits', async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const targetId = insertUser({ username: 'disable-target', isAdmin: false });
  db.prepare('INSERT INTO tokens (user_id, token_hash) VALUES (?, ?)').run(targetId, 'hash-1');

  const res = await fetch(`${baseUrl}/admin/users/disable`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: String(targetId), csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/users');

  const row = /** @type {any} */ (db.prepare('SELECT * FROM users WHERE id = ?').get(targetId));
  assert.ok(row.disabled_at);
  const tokenRow = /** @type {any} */ (
    db.prepare('SELECT * FROM tokens WHERE user_id = ?').get(targetId)
  );
  assert.equal(tokenRow.revoked_at, null);

  const auditRows = db.prepare('SELECT * FROM admin_audit_log').all();
  assert.equal(auditRows.length, 1);
  assert.equal(auditRows[0].action, 'user.disable');
});

test('POST /admin/users/enable clears disabled_at and audits user.enable', async () => {
  const { cookie, userId } = loginAsAdmin();
  const targetId = insertUser({ username: 'enable-target', isAdmin: false, disabled: true });
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);

  const res = await fetch(`${baseUrl}/admin/users/enable`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: String(targetId), csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  const row = /** @type {any} */ (db.prepare('SELECT * FROM users WHERE id = ?').get(targetId));
  assert.equal(row.disabled_at, null);

  const auditRows = db.prepare('SELECT * FROM admin_audit_log').all();
  assert.equal(auditRows.length, 1);
  assert.equal(auditRows[0].action, 'user.enable');
});

test("threat: POST /admin/users/disable targeting the admin's own id fails, no mutation, no audit row (A14)", async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);

  const res = await fetch(`${baseUrl}/admin/users/disable`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: String(userId), csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/users?error=not_found');

  const row = /** @type {any} */ (db.prepare('SELECT * FROM users WHERE id = ?').get(userId));
  assert.equal(row.disabled_at, null);
  assert.equal(db.prepare('SELECT * FROM admin_audit_log').all().length, 0);
});

test('POST /admin/users/disable with an unknown userId redirects to /admin/users?error=not_found', async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const res = await fetch(`${baseUrl}/admin/users/disable`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: '999999', csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/users?error=not_found');
});

test('POST /admin/users/disable with a non-numeric userId redirects to /admin/users?error=invalid', async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const res = await fetch(`${baseUrl}/admin/users/disable`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: 'not-a-number', csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/users?error=invalid');
});

test('POST /admin/users/disable with a mismatched Origin returns 403, before touching the database', async () => {
  const { cookie, userId } = loginAsAdmin();
  const targetId = insertUser({ username: 'origin-guard-target', isAdmin: false });
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const res = await fetch(`${baseUrl}/admin/users/disable`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: 'https://attacker.example',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: String(targetId), csrf }),
  });
  assert.equal(res.status, 403);
  const row = /** @type {any} */ (db.prepare('SELECT * FROM users WHERE id = ?').get(targetId));
  assert.equal(row.disabled_at, null);
});

test('POST /admin/users/disable with a missing CSRF token redirects to /admin/users?error=csrf', async () => {
  const { cookie } = loginAsAdmin();
  const targetId = insertUser({ username: 'csrf-guard-target', isAdmin: false });
  const res = await fetch(`${baseUrl}/admin/users/disable`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: String(targetId) }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/users?error=csrf');
});

test('POST /admin/users/disable and /admin/users/enable with no admin cookie return 401', async () => {
  const disableRes = await fetch(`${baseUrl}/admin/users/disable`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ userId: '1' }),
  });
  assert.equal(disableRes.status, 401);

  const enableRes = await fetch(`${baseUrl}/admin/users/enable`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ userId: '1' }),
  });
  assert.equal(enableRes.status, 401);
});

test('a regular (non-admin) session cookie never authenticates POST /admin/users/disable', async () => {
  const regularId = insertUser({ username: 'disable-regular-cookie-test', isAdmin: false });
  const regularToken = createSessionToken({ uid: regularId }, SESSION_SECRET);
  const res = await fetch(`${baseUrl}/admin/users/disable`, {
    method: 'POST',
    headers: {
      Cookie: `session=${regularToken}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: String(regularId) }),
  });
  assert.equal(res.status, 401);
});

test('GET /admin/users renders a per-row Disable button for an active user and an Enable button for a disabled one', async () => {
  const { cookie } = loginAsAdmin();
  insertUser({ username: 'row-active', isAdmin: false });
  insertUser({ username: 'row-disabled', isAdmin: false, disabled: true });

  const res = await fetch(`${baseUrl}/admin/users`, { headers: { Cookie: cookie } });
  const body = await res.text();
  assert.ok(body.includes('action="/admin/users/disable"'));
  assert.ok(body.includes('action="/admin/users/enable"'));
});

// Phase 10 — GET /admin/users/tokens + POST /admin/tokens/issue

test('GET /admin/users/tokens?userId=N with no admin cookie and a non-html Accept returns 401 JSON', async () => {
  const res = await fetch(`${baseUrl}/admin/users/tokens?userId=1`, {
    headers: { Accept: 'application/json' },
  });
  assert.equal(res.status, 401);
});

test('GET /admin/users/tokens?userId=N with Accept: text/html and no admin cookie redirects to /admin/login?next=…', async () => {
  const res = await fetch(`${baseUrl}/admin/users/tokens?userId=42`, {
    headers: { Accept: 'text/html' },
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(
    res.headers.get('location'),
    `/admin/login?next=${encodeURIComponent('/admin/users/tokens?userId=42')}`,
  );
});

test("GET /admin/users/tokens lists a target user's tokens by label/created/last_used/revoked, never a raw or hashed value", async () => {
  const { cookie } = loginAsAdmin();
  const targetId = insertUser({ username: 'token-target', isAdmin: false });
  db.prepare('INSERT INTO tokens (user_id, token_hash, label) VALUES (?, ?, ?)').run(
    targetId,
    'active-hash-value',
    'phone',
  );
  db.prepare(
    "INSERT INTO tokens (user_id, token_hash, label, revoked_at) VALUES (?, ?, ?, datetime('now'))",
  ).run(targetId, 'revoked-hash-value', 'old-laptop');

  const res = await fetch(`${baseUrl}/admin/users/tokens?userId=${targetId}`, {
    headers: { Cookie: cookie },
  });
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.ok(body.includes('href="/admin/console?view=cloud"'));
  assert.ok(body.includes('href="/admin/console?view=monitor"'));
  assert.ok(body.includes('action="/admin/logout"'));
  assert.ok(body.includes('Tokens for token-target'));
  assert.ok(body.includes('phone'));
  assert.ok(body.includes('old-laptop'));
  assert.ok(!body.includes('active-hash-value'));
  assert.ok(!body.includes('revoked-hash-value'));
});

test('GET /admin/users/tokens with a non-numeric userId redirects to /admin/users?error=invalid', async () => {
  const { cookie } = loginAsAdmin();
  const res = await fetch(`${baseUrl}/admin/users/tokens?userId=not-a-number`, {
    headers: { Cookie: cookie, Accept: 'text/html' },
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/users?error=invalid');
});

test("GET /admin/users/tokens targeting the admin's own id redirects to /admin/users?error=not_found (A14-equivalent)", async () => {
  const { cookie, userId } = loginAsAdmin();
  const res = await fetch(`${baseUrl}/admin/users/tokens?userId=${userId}`, {
    headers: { Cookie: cookie, Accept: 'text/html' },
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/users?error=not_found');
});

test('GET /admin/users/tokens with an unknown userId redirects to /admin/users?error=not_found', async () => {
  const { cookie } = loginAsAdmin();
  const res = await fetch(`${baseUrl}/admin/users/tokens?userId=999999`, {
    headers: { Cookie: cookie, Accept: 'text/html' },
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/users?error=not_found');
});

test('GET /admin/users/tokens embeds a hidden csrf field that verifies for the caller uid', async () => {
  const { cookie, userId } = loginAsAdmin();
  const targetId = insertUser({ username: 'tokens-csrf-target', isAdmin: false });
  const res = await fetch(`${baseUrl}/admin/users/tokens?userId=${targetId}`, {
    headers: { Cookie: cookie },
  });
  const body = await res.text();
  const match = body.match(/name="csrf" value="([^"]+)"/);
  assert.ok(match, 'expected a hidden csrf field');
  const { verifyAdminCsrfToken } = await import('../src/csrf.js');
  assert.equal(verifyAdminCsrfToken(match[1], { uid: userId, adminSecret: ADMIN_SECRET }), true);
});

test('POST /admin/tokens/issue with valid admin cookie, Origin, and CSRF renders the raw token exactly once', async () => {
  const { cookie, userId } = loginAsAdmin();
  const targetId = insertUser({ username: 'issue-target', isAdmin: false });
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);

  const res = await fetch(`${baseUrl}/admin/tokens/issue`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: String(targetId), label: 'ci-runner', csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.ok(body.includes('Copy this token now'));

  const row = /** @type {any} */ (
    db.prepare('SELECT * FROM tokens WHERE user_id = ?').get(targetId)
  );
  assert.equal(row.label, 'ci-runner');
  assert.ok(!body.includes(row.token_hash));

  const auditRows = db.prepare('SELECT * FROM admin_audit_log').all();
  assert.equal(auditRows.length, 1);
  assert.equal(auditRows[0].action, 'token.issue');
});

test('POST /admin/tokens/issue as JSON returns the raw token in the response body', async () => {
  const { cookie, userId } = loginAsAdmin();
  const targetId = insertUser({ username: 'issue-json-target', isAdmin: false });
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);

  const res = await fetch(`${baseUrl}/admin/tokens/issue`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ userId: targetId, csrf }),
  });
  assert.equal(res.status, 200);
  const responseBody = /** @type {any} */ (await res.json());
  assert.equal(typeof responseBody.rawToken, 'string');
  assert.ok(responseBody.rawToken.length >= 32);
});

test("POST /admin/tokens/issue targeting the admin's own id redirects to /admin/users?error=not_found, no token row", async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const res = await fetch(`${baseUrl}/admin/tokens/issue`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: String(userId), csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/users?error=not_found');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM tokens').get().n, 0);
});

test('POST /admin/tokens/issue with a mismatched Origin returns 403, before touching the database', async () => {
  const { cookie, userId } = loginAsAdmin();
  const targetId = insertUser({ username: 'issue-origin-target', isAdmin: false });
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const res = await fetch(`${baseUrl}/admin/tokens/issue`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: 'https://attacker.example',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: String(targetId), csrf }),
  });
  assert.equal(res.status, 403);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM tokens').get().n, 0);
});

test('POST /admin/tokens/issue with a missing CSRF token redirects to /admin/users?error=csrf', async () => {
  const { cookie } = loginAsAdmin();
  const targetId = insertUser({ username: 'issue-csrf-target', isAdmin: false });
  const res = await fetch(`${baseUrl}/admin/tokens/issue`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: String(targetId) }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/users?error=csrf');
});

test('POST /admin/tokens/issue with no admin cookie returns 401', async () => {
  const res = await fetch(`${baseUrl}/admin/tokens/issue`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ userId: '1' }),
  });
  assert.equal(res.status, 401);
});

test('a regular (non-admin) session cookie never authenticates GET /admin/users/tokens', async () => {
  const targetId = insertUser({ username: 'tokens-regular-cookie-target', isAdmin: false });
  const regularToken = createSessionToken({ uid: targetId }, SESSION_SECRET);
  const res = await fetch(`${baseUrl}/admin/users/tokens?userId=${targetId}`, {
    headers: { Cookie: `session=${regularToken}`, Accept: 'application/json' },
  });
  assert.equal(res.status, 401);
});

// Phase 11 — POST /admin/tokens/revoke + POST /admin/tokens/regenerate

/**
 * @param {number} userId
 * @returns {number} the inserted token's id
 */
function insertActiveToken(userId, label = null) {
  const info = db
    .prepare('INSERT INTO tokens (user_id, token_hash, label) VALUES (?, ?, ?)')
    .run(userId, `hash-${crypto.randomUUID()}`, label);
  return Number(info.lastInsertRowid);
}

test('POST /admin/tokens/revoke with a valid target sets revoked_at, redirects to the token list, and audits', async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const targetId = insertUser({ username: 'revoke-target', isAdmin: false });
  const tokenId = insertActiveToken(targetId, 'phone');

  const res = await fetch(`${baseUrl}/admin/tokens/revoke`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: String(targetId), tokenId: String(tokenId), csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), `/admin/users/tokens?userId=${targetId}`);

  const row = /** @type {any} */ (db.prepare('SELECT * FROM tokens WHERE id = ?').get(tokenId));
  assert.ok(row.revoked_at);

  const auditRows = db.prepare('SELECT * FROM admin_audit_log').all();
  assert.equal(auditRows.length, 1);
  assert.equal(auditRows[0].action, 'token.revoke');
});

test("POST /admin/tokens/revoke has no side effect on the target user's other tokens", async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const targetId = insertUser({ username: 'revoke-sibling-target', isAdmin: false });
  const tokenId = insertActiveToken(targetId, 'one');
  const siblingId = insertActiveToken(targetId, 'two');

  await fetch(`${baseUrl}/admin/tokens/revoke`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: String(targetId), tokenId: String(tokenId), csrf }),
  });

  const sibling = /** @type {any} */ (
    db.prepare('SELECT * FROM tokens WHERE id = ?').get(siblingId)
  );
  assert.equal(sibling.revoked_at, null);
});

test('threat: POST /admin/tokens/revoke targeting a token owned by a different user fails (A15), token untouched', async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const owner = insertUser({ username: 'revoke-owner', isAdmin: false });
  const stranger = insertUser({ username: 'revoke-stranger', isAdmin: false });
  const tokenId = insertActiveToken(owner, 'desktop');

  const res = await fetch(`${baseUrl}/admin/tokens/revoke`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: String(stranger), tokenId: String(tokenId), csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(
    res.headers.get('location'),
    `/admin/users/tokens?userId=${stranger}&error=not_found`,
  );
  const row = /** @type {any} */ (db.prepare('SELECT * FROM tokens WHERE id = ?').get(tokenId));
  assert.equal(row.revoked_at, null);
});

test('POST /admin/tokens/revoke with an unknown tokenId redirects with error=not_found', async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const targetId = insertUser({ username: 'revoke-unknown-token-target', isAdmin: false });

  const res = await fetch(`${baseUrl}/admin/tokens/revoke`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: String(targetId), tokenId: '999999', csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(
    res.headers.get('location'),
    `/admin/users/tokens?userId=${targetId}&error=not_found`,
  );
});

test("POST /admin/tokens/revoke targeting the admin's own id as userId redirects to /admin/users?error=not_found", async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const res = await fetch(`${baseUrl}/admin/tokens/revoke`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: String(userId), tokenId: '1', csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/users?error=not_found');
});

test('POST /admin/tokens/revoke with a mismatched Origin returns 403, before touching the database', async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const targetId = insertUser({ username: 'revoke-origin-target', isAdmin: false });
  const tokenId = insertActiveToken(targetId);

  const res = await fetch(`${baseUrl}/admin/tokens/revoke`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: 'https://attacker.example',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: String(targetId), tokenId: String(tokenId), csrf }),
  });
  assert.equal(res.status, 403);
  const row = /** @type {any} */ (db.prepare('SELECT * FROM tokens WHERE id = ?').get(tokenId));
  assert.equal(row.revoked_at, null);
});

test('POST /admin/tokens/revoke with a missing CSRF token redirects to /admin/users?error=csrf', async () => {
  const { cookie } = loginAsAdmin();
  const targetId = insertUser({ username: 'revoke-csrf-target', isAdmin: false });
  const tokenId = insertActiveToken(targetId);
  const res = await fetch(`${baseUrl}/admin/tokens/revoke`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: String(targetId), tokenId: String(tokenId) }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/users?error=csrf');
});

test('POST /admin/tokens/revoke with no admin cookie returns 401', async () => {
  const res = await fetch(`${baseUrl}/admin/tokens/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ userId: '1', tokenId: '1' }),
  });
  assert.equal(res.status, 401);
});

test('POST /admin/tokens/regenerate replaces the token atomically and renders the new raw value exactly once', async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const targetId = insertUser({ username: 'regenerate-target', isAdmin: false });
  const oldTokenId = insertActiveToken(targetId, 'ci-runner');

  const res = await fetch(`${baseUrl}/admin/tokens/regenerate`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: String(targetId), tokenId: String(oldTokenId), csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.ok(body.includes('Copy this token now'));

  const oldRow = /** @type {any} */ (
    db.prepare('SELECT * FROM tokens WHERE id = ?').get(oldTokenId)
  );
  assert.ok(oldRow.revoked_at);
  const activeCount = /** @type {any} */ (
    db
      .prepare('SELECT COUNT(*) AS n FROM tokens WHERE user_id = ? AND revoked_at IS NULL')
      .get(targetId)
  ).n;
  assert.equal(activeCount, 1);

  const auditRows = db.prepare('SELECT * FROM admin_audit_log').all();
  assert.equal(auditRows.length, 1);
  assert.equal(auditRows[0].action, 'token.regenerate');
});

test('POST /admin/tokens/regenerate as JSON returns the new raw token in the response body', async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const targetId = insertUser({ username: 'regenerate-json-target', isAdmin: false });
  const oldTokenId = insertActiveToken(targetId);

  const res = await fetch(`${baseUrl}/admin/tokens/regenerate`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ userId: targetId, tokenId: oldTokenId, csrf }),
  });
  assert.equal(res.status, 200);
  const responseBody = /** @type {any} */ (await res.json());
  assert.equal(typeof responseBody.rawToken, 'string');
  assert.ok(responseBody.rawToken.length >= 32);
});

test('POST /admin/tokens/regenerate on an already-revoked token fails cleanly, no new token created', async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const targetId = insertUser({ username: 'regenerate-revoked-target', isAdmin: false });
  const tokenId = insertActiveToken(targetId);
  db.prepare("UPDATE tokens SET revoked_at = datetime('now') WHERE id = ?").run(tokenId);

  const res = await fetch(`${baseUrl}/admin/tokens/regenerate`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: String(targetId), tokenId: String(tokenId), csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(
    res.headers.get('location'),
    `/admin/users/tokens?userId=${targetId}&error=not_found`,
  );
  const count = /** @type {any} */ (
    db.prepare('SELECT COUNT(*) AS n FROM tokens WHERE user_id = ?').get(targetId)
  ).n;
  assert.equal(count, 1);
});

test('POST /admin/tokens/regenerate with a mismatched Origin returns 403, before touching the database', async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const targetId = insertUser({ username: 'regenerate-origin-target', isAdmin: false });
  const tokenId = insertActiveToken(targetId);

  const res = await fetch(`${baseUrl}/admin/tokens/regenerate`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: 'https://attacker.example',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: String(targetId), tokenId: String(tokenId), csrf }),
  });
  assert.equal(res.status, 403);
  const count = /** @type {any} */ (
    db.prepare('SELECT COUNT(*) AS n FROM tokens WHERE user_id = ?').get(targetId)
  ).n;
  assert.equal(count, 1);
});

test('POST /admin/tokens/regenerate with a missing CSRF token redirects to /admin/users?error=csrf', async () => {
  const { cookie } = loginAsAdmin();
  const targetId = insertUser({ username: 'regenerate-csrf-target', isAdmin: false });
  const tokenId = insertActiveToken(targetId);
  const res = await fetch(`${baseUrl}/admin/tokens/regenerate`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: String(targetId), tokenId: String(tokenId) }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/users?error=csrf');
});

test('POST /admin/tokens/regenerate with no admin cookie returns 401', async () => {
  const res = await fetch(`${baseUrl}/admin/tokens/regenerate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ userId: '1', tokenId: '1' }),
  });
  assert.equal(res.status, 401);
});

test('a regular (non-admin) session cookie never authenticates POST /admin/tokens/revoke or /regenerate', async () => {
  const targetId = insertUser({ username: 'tokens-regular-cookie-revoke', isAdmin: false });
  const regularToken = createSessionToken({ uid: targetId }, SESSION_SECRET);
  const tokenId = insertActiveToken(targetId);

  const revokeRes = await fetch(`${baseUrl}/admin/tokens/revoke`, {
    method: 'POST',
    headers: {
      Cookie: `session=${regularToken}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: String(targetId), tokenId: String(tokenId) }),
  });
  assert.equal(revokeRes.status, 401);

  const regenerateRes = await fetch(`${baseUrl}/admin/tokens/regenerate`, {
    method: 'POST',
    headers: {
      Cookie: `session=${regularToken}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ userId: String(targetId), tokenId: String(tokenId) }),
  });
  assert.equal(regenerateRes.status, 401);
});

test('GET /admin/users/tokens renders a per-row Revoke/Regenerate form for an active token and none for a revoked one', async () => {
  const { cookie } = loginAsAdmin();
  const targetId = insertUser({ username: 'tokens-actions-render-target', isAdmin: false });
  insertActiveToken(targetId, 'active-one');
  const revokedTokenId = insertActiveToken(targetId, 'revoked-one');
  db.prepare("UPDATE tokens SET revoked_at = datetime('now') WHERE id = ?").run(revokedTokenId);

  const res = await fetch(`${baseUrl}/admin/users/tokens?userId=${targetId}`, {
    headers: { Cookie: cookie },
  });
  const body = await res.text();
  assert.ok(body.includes('action="/admin/tokens/revoke"'));
  assert.ok(body.includes('action="/admin/tokens/regenerate"'));
  // Exactly one active token → exactly one Revoke form, none for the revoked one.
  assert.equal(body.split('action="/admin/tokens/revoke"').length - 1, 1);
});

// Phase 3 (engram-unified-console) — /admin/engram-cloud/* proxy routes.
// Unlike every other admin route above, these are a pure JSON relay for
// Monitor's own SPA (Phase 4, external repo) to call — no HTML rendering,
// no zero-JS form. ENGRAM_CLOUD_ADMIN_TOKEN/ENGRAM_CLOUD_SERVER point at a
// local stub server standing in for `engram cloud serve` itself.

const ENGRAM_CLOUD_ADMIN_TOKEN = 'test-engram-cloud-admin-token';

/** @type {http.Server} */
let engramCloudStub;
/** @type {{ method?: string, url?: string, headers?: any, body?: string }} */
let lastEngramCloudRequest;
/** @type {{ status: number, body: any }} */
let nextEngramCloudResponse;
// SSO tests (Phase 5) exercise multiple distinct upstream calls in one
// request (create user → issue token → dashboard login) — keyed here by
// "METHOD path" so each gets its own canned response instead of sharing
// nextEngramCloudResponse's single slot.
/** @type {Record<string, { status: number, body?: any, headers?: Record<string, string> }>} */
let engramCloudResponsesByRoute;
/** @type {{ method?: string, url?: string, headers?: any, body?: string }[]} */
let engramCloudRequestLog;

before(() => {
  process.env.ENGRAM_CLOUD_ADMIN_TOKEN = ENGRAM_CLOUD_ADMIN_TOKEN;
});

beforeEach(async () => {
  lastEngramCloudRequest = undefined;
  nextEngramCloudResponse = { status: 200, body: {} };
  engramCloudResponsesByRoute = {};
  engramCloudRequestLog = [];
  engramCloudStub = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
    });
    req.on('end', () => {
      lastEngramCloudRequest = {
        method: req.method,
        url: req.url,
        headers: req.headers,
        body: raw,
      };
      engramCloudRequestLog.push(lastEngramCloudRequest);
      const routeKey = `${req.method} ${req.url?.split('?')[0]}`;
      const routed = engramCloudResponsesByRoute[routeKey];
      const response = routed ?? nextEngramCloudResponse;
      res.writeHead(response.status, {
        'Content-Type': 'application/json',
        ...response.headers,
      });
      res.end(response.body !== undefined ? JSON.stringify(response.body) : '');
    });
  });
  await new Promise((resolve) => engramCloudStub.listen(0, '127.0.0.1', resolve));
  const address = /** @type {any} */ (engramCloudStub.address());
  process.env.ENGRAM_CLOUD_SERVER = `http://127.0.0.1:${address.port}`;
});

afterEach(async () => {
  await new Promise((resolve) => engramCloudStub.close(resolve));
});

test('GET /admin/engram-cloud/users with no admin cookie returns 401, stub never hit', async () => {
  const res = await fetch(`${baseUrl}/admin/engram-cloud/users`, {
    headers: { Accept: 'application/json' },
  });
  assert.equal(res.status, 401);
  assert.equal(lastEngramCloudRequest, undefined);
});

test('GET /admin/engram-cloud/users relays the list and includes a fresh csrfToken for subsequent writes', async () => {
  const { cookie, userId } = loginAsAdmin();
  nextEngramCloudResponse = {
    status: 200,
    body: [{ principal_id: 'p1', username: 'alice', role: 'member' }],
  };
  const res = await fetch(`${baseUrl}/admin/engram-cloud/users`, { headers: { Cookie: cookie } });
  assert.equal(res.status, 200);
  const responseBody = /** @type {any} */ (await res.json());
  assert.deepEqual(responseBody.users, [{ principal_id: 'p1', username: 'alice', role: 'member' }]);
  assert.equal(typeof responseBody.csrfToken, 'string');
  const { verifyAdminCsrfToken } = await import('../src/csrf.js');
  assert.equal(
    verifyAdminCsrfToken(responseBody.csrfToken, { uid: userId, adminSecret: ADMIN_SECRET }),
    true,
  );
  assert.equal(lastEngramCloudRequest.url, '/admin/users');
});

test('POST /admin/engram-cloud/users with no admin cookie returns 401, stub never hit', async () => {
  const res = await fetch(`${baseUrl}/admin/engram-cloud/users`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'bob' }),
  });
  assert.equal(res.status, 401);
  assert.equal(lastEngramCloudRequest, undefined);
});

test('POST /admin/engram-cloud/users with valid admin cookie, Origin, and CSRF relays the create call and its response', async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  nextEngramCloudResponse = {
    status: 201,
    body: { principal_id: 'p2', username: 'bob', role: 'member', enabled: true },
  };
  const res = await fetch(`${baseUrl}/admin/engram-cloud/users`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrf,
    },
    body: JSON.stringify({ username: 'bob', role: 'member' }),
  });
  assert.equal(res.status, 201);
  const responseBody = /** @type {any} */ (await res.json());
  assert.equal(responseBody.principal_id, 'p2');
  assert.equal(lastEngramCloudRequest.method, 'POST');
  assert.equal(lastEngramCloudRequest.url, '/admin/users');
  assert.equal(lastEngramCloudRequest.headers.authorization, `Bearer ${ENGRAM_CLOUD_ADMIN_TOKEN}`);
  assert.deepEqual(JSON.parse(lastEngramCloudRequest.body), { username: 'bob', role: 'member' });
});

test('POST /admin/engram-cloud/users with a mismatched Origin returns 403, stub never hit', async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const res = await fetch(`${baseUrl}/admin/engram-cloud/users`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: 'https://attacker.example',
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrf,
    },
    body: JSON.stringify({ username: 'bob' }),
  });
  assert.equal(res.status, 403);
  assert.equal(lastEngramCloudRequest, undefined);
});

test('POST /admin/engram-cloud/users with a missing CSRF token returns 403, stub never hit', async () => {
  const { cookie } = loginAsAdmin();
  const res = await fetch(`${baseUrl}/admin/engram-cloud/users`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ username: 'bob' }),
  });
  assert.equal(res.status, 403);
  assert.equal(lastEngramCloudRequest, undefined);
});

test('POST /admin/engram-cloud/users/:id/grants relays the grant call with the URL-encoded id and project body', async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  nextEngramCloudResponse = {
    status: 201,
    body: { principal_id: 'p2', project: 'acme', granted_by_principal_id: 'p1' },
  };
  const res = await fetch(`${baseUrl}/admin/engram-cloud/users/p2/grants`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrf,
    },
    body: JSON.stringify({ project: 'acme' }),
  });
  assert.equal(res.status, 201);
  const responseBody = /** @type {any} */ (await res.json());
  assert.equal(responseBody.project, 'acme');
  assert.equal(lastEngramCloudRequest.url, '/admin/users/p2/grants');
  assert.deepEqual(JSON.parse(lastEngramCloudRequest.body), { project: 'acme' });
});

test('POST /admin/engram-cloud/users/:id/tokens relays the issued raw_token exactly once', async () => {
  const { cookie, userId } = loginAsAdmin();
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  nextEngramCloudResponse = {
    status: 201,
    body: { raw_token: 'shown-once-value', token: { id: 't1', principal_id: 'p2' } },
  };
  const res = await fetch(`${baseUrl}/admin/engram-cloud/users/p2/tokens`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrf,
    },
    body: JSON.stringify({ name: 'laptop' }),
  });
  assert.equal(res.status, 201);
  const responseBody = /** @type {any} */ (await res.json());
  assert.equal(responseBody.raw_token, 'shown-once-value');
  assert.equal(lastEngramCloudRequest.url, '/admin/users/p2/tokens');
});

test('POST /admin/engram-cloud/users/:id/tokens with no admin cookie returns 401, stub never hit', async () => {
  const res = await fetch(`${baseUrl}/admin/engram-cloud/users/p2/tokens`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  assert.equal(res.status, 401);
  assert.equal(lastEngramCloudRequest, undefined);
});

test('a regular (non-admin) session cookie never authenticates GET /admin/engram-cloud/users', async () => {
  const regularId = insertUser({ username: 'engram-cloud-regular-cookie-test', isAdmin: false });
  const regularToken = createSessionToken({ uid: regularId }, SESSION_SECRET);
  const res = await fetch(`${baseUrl}/admin/engram-cloud/users`, {
    headers: { Cookie: `session=${regularToken}`, Accept: 'application/json' },
  });
  assert.equal(res.status, 401);
});

test('when the upstream engram-cloud call fails, the proxy route surfaces a 502, never a raw stack trace', async () => {
  const { cookie } = loginAsAdmin();
  await engramCloudStub.close();
  const res = await fetch(`${baseUrl}/admin/engram-cloud/users`, { headers: { Cookie: cookie } });
  assert.equal(res.status, 502);
  const responseBody = /** @type {any} */ (await res.json());
  assert.ok(!JSON.stringify(responseBody).includes(ENGRAM_CLOUD_ADMIN_TOKEN));
  // afterEach's own engramCloudStub.close() on an already-closed server is a
  // harmless no-op (Node's http.Server.close() tolerates a double-close).
});

// Phase 5 (engram-unified-console) — GET /admin/engram-cloud/sso: per-admin
// SSO into Engram Cloud's own /dashboard. Provisions a Cloud identity on
// first use (create user → issue token → save encrypted), then always
// dashboard-logs-in with THIS admin's own stored token, never the shared
// ENGRAM_CLOUD_ADMIN_TOKEN (design.md Phase 5's explicit identity decision).

test('GET /admin/engram-cloud/sso with no admin cookie returns 401, stub never hit', async () => {
  const res = await fetch(`${baseUrl}/admin/engram-cloud/sso`, {
    headers: { Accept: 'application/json' },
  });
  assert.equal(res.status, 401);
  assert.equal(lastEngramCloudRequest, undefined);
});

test('GET /admin/engram-cloud/sso with no stored credential provisions one (create user, issue token), stores it encrypted, then dashboard-logs-in and redirects to /dashboard', async () => {
  const { cookie, userId } = loginAsAdmin('sso-first-time-admin');
  engramCloudResponsesByRoute['POST /admin/users'] = {
    status: 201,
    body: { principal_id: 'p-sso-1', username: 'sso-first-time-admin', role: 'admin' },
  };
  engramCloudResponsesByRoute['POST /admin/users/p-sso-1/tokens'] = {
    status: 201,
    body: { raw_token: 'freshly-issued-token', token: { id: 't1', principal_id: 'p-sso-1' } },
  };
  engramCloudResponsesByRoute['POST /dashboard/login'] = {
    status: 303,
    headers: {
      Location: '/dashboard/',
      'Set-Cookie': 'engram_dashboard_token=xyz; Path=/dashboard; HttpOnly; SameSite=Lax',
    },
  };

  const res = await fetch(`${baseUrl}/admin/engram-cloud/sso`, {
    headers: { Cookie: cookie },
    redirect: 'manual',
  });

  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/dashboard');
  assert.equal(
    res.headers.get('set-cookie'),
    'engram_dashboard_token=xyz; Path=/dashboard; HttpOnly; SameSite=Lax',
  );

  const createCall = engramCloudRequestLog.find((r) => r.url === '/admin/users');
  assert.equal(createCall.method, 'POST');
  assert.deepEqual(JSON.parse(createCall.body), {
    username: 'sso-first-time-admin',
    role: 'admin',
  });

  // engram-contributor-attribution (fix, 2026-09-18): Cloud's own
  // managed-token auth is deny-by-default for /sync/mutations/push — a
  // freshly linked principal must be self-granted its own identity-named
  // project, or its private default space can never sync once it
  // authenticates with its OWN token instead of the old shared one.
  const selfGrantCall = engramCloudRequestLog.find(
    (r) => r.url === '/admin/users/p-sso-1/grants',
  );
  assert.equal(selfGrantCall.method, 'POST');
  assert.deepEqual(JSON.parse(selfGrantCall.body), { project: 'sso-first-time-admin' });

  const loginCall = engramCloudRequestLog.find((r) => r.url === '/dashboard/login');
  assert.equal(loginCall.body, 'token=freshly-issued-token');

  const { decrypt } = await import('../src/crypto.js');
  const row = /** @type {any} */ (
    db.prepare('SELECT principal_id, ciphertext FROM engram_cloud_credentials WHERE user_id = ?').get(userId)
  );
  assert.equal(row.principal_id, 'p-sso-1');
  assert.equal(decrypt(row.ciphertext), 'freshly-issued-token');
});

test('GET /admin/engram-cloud/sso with an already-stored credential skips provisioning and reuses the stored token', async () => {
  const { cookie, userId } = loginAsAdmin('sso-returning-admin');
  const { encrypt } = await import('../src/crypto.js');
  db.prepare(
    "INSERT INTO engram_cloud_credentials (user_id, principal_id, ciphertext, updated_at) VALUES (?, ?, ?, datetime('now'))",
  ).run(userId, 'p-sso-2', encrypt('already-issued-token'));

  engramCloudResponsesByRoute['POST /dashboard/login'] = {
    status: 303,
    headers: {
      Location: '/dashboard/',
      'Set-Cookie': 'engram_dashboard_token=abc; Path=/dashboard; HttpOnly; SameSite=Lax',
    },
  };

  const res = await fetch(`${baseUrl}/admin/engram-cloud/sso`, {
    headers: { Cookie: cookie },
    redirect: 'manual',
  });

  assert.equal(res.status, 302);
  assert.equal(engramCloudRequestLog.some((r) => r.url === '/admin/users'), false);
  const loginCall = engramCloudRequestLog.find((r) => r.url === '/dashboard/login');
  assert.equal(loginCall.body, 'token=already-issued-token');
});

test('GET /admin/engram-cloud/sso surfaces a clean error when provisioning fails (e.g. a username collision), never a raw stack trace', async () => {
  const { cookie } = loginAsAdmin('sso-collision-admin');
  engramCloudResponsesByRoute['POST /admin/users'] = {
    status: 409,
    body: { error: 'username_taken' },
  };

  const res = await fetch(`${baseUrl}/admin/engram-cloud/sso`, { headers: { Cookie: cookie } });
  assert.equal(res.status, 502);
  const body = /** @type {any} */ (await res.json());
  assert.equal(body.error, 'engram_cloud_sso_failed');
});

test('GET /admin/engram-cloud/sso still succeeds even when the self-grant call itself fails (best-effort, never blocks SSO)', async () => {
  const { cookie } = loginAsAdmin('sso-selfgrant-fails-admin');
  engramCloudResponsesByRoute['POST /admin/users'] = {
    status: 201,
    body: { principal_id: 'p-sso-2', username: 'sso-selfgrant-fails-admin', role: 'admin' },
  };
  engramCloudResponsesByRoute['POST /admin/users/p-sso-2/tokens'] = {
    status: 201,
    body: { raw_token: 'freshly-issued-token', token: { id: 't1', principal_id: 'p-sso-2' } },
  };
  engramCloudResponsesByRoute['POST /admin/users/p-sso-2/grants'] = {
    status: 500,
    body: { error: 'boom' },
  };
  engramCloudResponsesByRoute['POST /dashboard/login'] = {
    status: 303,
    headers: { Location: '/dashboard/', 'Set-Cookie': 'engram_dashboard_token=xyz; Path=/dashboard' },
  };

  const res = await fetch(`${baseUrl}/admin/engram-cloud/sso`, {
    headers: { Cookie: cookie },
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/dashboard');
});

test('a regular (non-admin) session cookie never authenticates GET /admin/engram-cloud/sso', async () => {
  const regularId = insertUser({ username: 'engram-cloud-sso-regular-cookie-test', isAdmin: false });
  const regularToken = createSessionToken({ uid: regularId }, SESSION_SECRET);
  const res = await fetch(`${baseUrl}/admin/engram-cloud/sso`, {
    headers: { Cookie: `session=${regularToken}`, Accept: 'application/json' },
  });
  assert.equal(res.status, 401);
});

// Phase 5 (engram-unified-console) — GET /admin/console: the shared
// header+sidebar+main shell, Monitor/Cloud rendered inside via <iframe>.

test('GET /admin/console unauthenticated (Accept: text/html) redirects to /admin/login', async () => {
  const res = await fetch(`${baseUrl}/admin/console`, {
    headers: { Accept: 'text/html' },
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.ok(res.headers.get('location').startsWith('/admin/login'));
});

test('GET /admin/console?view=monitor renders the shell with an iframe pointed at /monitor', async () => {
  const { cookie } = loginAsAdmin();
  const res = await fetch(`${baseUrl}/admin/console?view=monitor`, { headers: { Cookie: cookie } });
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.ok(body.includes('<iframe src="/monitor"'));
  assert.ok(!body.includes('<script'));
});

test('GET /admin/console?view=cloud renders the shell with an iframe pointed at the SSO route', async () => {
  const { cookie } = loginAsAdmin();
  const res = await fetch(`${baseUrl}/admin/console?view=cloud`, { headers: { Cookie: cookie } });
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.ok(body.includes('<iframe src="/admin/engram-cloud/sso"'));
});

test('GET /admin/console with no/unrecognized view defaults to the monitor view', async () => {
  const { cookie } = loginAsAdmin();
  const res = await fetch(`${baseUrl}/admin/console?view=bogus`, { headers: { Cookie: cookie } });
  const body = await res.text();
  assert.ok(body.includes('<iframe src="/monitor"'));
});

test('GET /admin/console carries a frame-src CSP directive (unlike every other admin page)', async () => {
  const { cookie } = loginAsAdmin();
  const res = await fetch(`${baseUrl}/admin/console`, { headers: { Cookie: cookie } });
  assert.ok(res.headers.get('content-security-policy').includes("frame-src 'self'"));
});

// admin-identity-unification, Unit 1 — POST /admin/login also provisions a
// Cloud link if one is missing (design.md D1/D2), reusing the same
// ensureEngramCloudLink logic the SSO route already has.

async function createRealAdmin(username, role = 'admin') {
  const { hashPassword } = await import('../src/tokens.js');
  const password = 'correct-horse-battery-staple';
  const passwordHash = await hashPassword(password);
  const info = db
    .prepare('INSERT INTO users (username, password_hash, is_admin, role) VALUES (?, ?, 1, ?)')
    .run(username, passwordHash, role);
  return { userId: Number(info.lastInsertRowid), username, password };
}

test('POST /admin/login provisions a Cloud link for a first-time admin, without visiting the SSO route', async () => {
  const { userId, username, password } = await createRealAdmin('login-provision-first-time');
  engramCloudResponsesByRoute['POST /admin/users'] = {
    status: 201,
    body: { principal_id: 'p-login-1', username, role: 'admin' },
  };
  engramCloudResponsesByRoute['POST /admin/users/p-login-1/tokens'] = {
    status: 201,
    body: { raw_token: 'login-issued-token', token: { id: 't1', principal_id: 'p-login-1' } },
  };

  const res = await postAdminLogin({ username, password });
  assert.equal(res.status, 302);

  const row = /** @type {any} */ (
    db.prepare('SELECT principal_id FROM engram_cloud_credentials WHERE user_id = ?').get(userId)
  );
  assert.equal(row.principal_id, 'p-login-1');
});

test('POST /admin/login for an already-linked admin makes no new Cloud calls', async () => {
  const { userId, username, password } = await createRealAdmin('login-provision-already-linked');
  const { encrypt } = await import('../src/crypto.js');
  db.prepare(
    "INSERT INTO engram_cloud_credentials (user_id, principal_id, ciphertext, updated_at) VALUES (?, ?, ?, datetime('now'))",
  ).run(userId, 'p-existing', encrypt('existing-token'));

  const res = await postAdminLogin({ username, password });
  assert.equal(res.status, 302);
  assert.equal(engramCloudRequestLog.length, 0);
});

test('POST /admin/login succeeds normally even when Engram Cloud is unreachable, and creates no link', async () => {
  const { userId, username, password } = await createRealAdmin('login-provision-cloud-down');
  await engramCloudStub.close();

  const res = await postAdminLogin({ username, password });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/users');

  const row = db
    .prepare('SELECT 1 FROM engram_cloud_credentials WHERE user_id = ?')
    .get(userId);
  assert.equal(row, undefined);
  // afterEach's own engramCloudStub.close() on an already-closed server is a
  // harmless no-op (Node's http.Server.close() tolerates a double-close).
});

// admin-identity-unification, Unit 2 — GET/POST /admin/engram-cloud/import.

test('GET /admin/engram-cloud/import with no admin cookie returns 401, stub never hit', async () => {
  const res = await fetch(`${baseUrl}/admin/engram-cloud/import`, {
    headers: { Accept: 'application/json' },
  });
  assert.equal(res.status, 401);
  assert.equal(lastEngramCloudRequest, undefined);
});

test('GET /admin/engram-cloud/import lists a Cloud principal with no local link and excludes one that has one', async () => {
  const { cookie, userId } = loginAsAdmin();
  const { encrypt } = await import('../src/crypto.js');
  db.prepare(
    "INSERT INTO engram_cloud_credentials (user_id, principal_id, ciphertext, updated_at) VALUES (?, ?, ?, datetime('now'))",
  ).run(userId, 'p-already-linked', encrypt('linked-token'));
  engramCloudResponsesByRoute['GET /admin/users'] = {
    status: 200,
    body: [
      { principal_id: 'p-already-linked', username: 'previously-linked-user', role: 'member' },
      { principal_id: 'p-unlinked', username: 'brand-new-unlinked-user', role: 'member' },
    ],
  };

  const res = await fetch(`${baseUrl}/admin/engram-cloud/import`, { headers: { Cookie: cookie } });
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.ok(body.includes('brand-new-unlinked-user'));
  assert.ok(!body.includes('previously-linked-user'));
});

test('POST /admin/engram-cloud/import creates a working local account linked to the chosen principal', async () => {
  const { cookie, userId } = loginAsAdmin('import-operator');
  const adminSecret = ADMIN_SECRET;
  const csrf = issueAdminCsrfToken(userId, adminSecret);
  engramCloudResponsesByRoute['POST /admin/users/p-to-import/tokens'] = {
    status: 201,
    body: { raw_token: 'import-issued-token', token: { id: 't1', principal_id: 'p-to-import' } },
  };

  const res = await fetch(`${baseUrl}/admin/engram-cloud/import`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      principalId: 'p-to-import',
      username: 'imported-local-account',
      password: 'a-strong-password',
      passwordConfirm: 'a-strong-password',
      role: 'admin',
      csrf,
    }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);

  const newUser = /** @type {any} */ (
    db.prepare('SELECT id FROM users WHERE username = ?').get('imported-local-account')
  );
  assert.ok(newUser);
  const link = /** @type {any} */ (
    db.prepare('SELECT principal_id FROM engram_cloud_credentials WHERE user_id = ?').get(newUser.id)
  );
  assert.equal(link.principal_id, 'p-to-import');
});

test('POST /admin/engram-cloud/import with mismatched password confirmation redirects with error=mismatch, creates nothing', async () => {
  const { cookie, userId } = loginAsAdmin('import-mismatch-operator');
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);

  const res = await fetch(`${baseUrl}/admin/engram-cloud/import`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      principalId: 'p-mismatch',
      username: 'mismatch-account',
      password: 'a-strong-password',
      passwordConfirm: 'does-not-match',
      role: 'admin',
      csrf,
    }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/engram-cloud/import?error=mismatch');
  assert.equal(engramCloudRequestLog.length, 0);
  const row = db.prepare('SELECT 1 FROM users WHERE username = ?').get('mismatch-account');
  assert.equal(row, undefined);
});

test('POST /admin/engram-cloud/import with a mismatched Origin returns 403, stub never hit', async () => {
  const { cookie, userId } = loginAsAdmin('import-origin-operator');
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const res = await fetch(`${baseUrl}/admin/engram-cloud/import`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: 'https://evil.example.com',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      principalId: 'p-origin',
      username: 'origin-account',
      password: 'a-strong-password',
      passwordConfirm: 'a-strong-password',
      csrf,
    }),
  });
  assert.equal(res.status, 403);
  assert.equal(lastEngramCloudRequest, undefined);
});

test('POST /admin/engram-cloud/import with no admin cookie returns 401', async () => {
  const res = await fetch(`${baseUrl}/admin/engram-cloud/import`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  assert.equal(res.status, 401);
});

// admin-identity-unification, Unit 3 — member role: only the Engram Cloud
// SSO surface is reachable; everything else stays admin-only.

test('POST /admin/login succeeds for a role=member account, redirects to the console cloud view (not /admin/users, which would just 403)', async () => {
  const { username, password } = await createRealAdmin('login-member', 'member');
  const res = await postAdminLogin({ username, password });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/console?view=cloud');
});

test('POST /admin/login still redirects an admin to /admin/users, unchanged', async () => {
  const { username, password } = await createRealAdmin('login-admin-redirect-check');
  const res = await postAdminLogin({ username, password });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/users');
});

test('a member session is rejected by GET /admin/users (JSON caller)', async () => {
  const { cookie } = loginAsMember();
  const res = await fetch(`${baseUrl}/admin/users`, {
    headers: { Cookie: cookie, Accept: 'application/json' },
  });
  assert.equal(res.status, 403);
});

test('a member session on GET /admin/users with Accept: text/html is redirected to the console cloud view, not a raw JSON 403', async () => {
  const { cookie } = loginAsMember();
  const res = await fetch(`${baseUrl}/admin/users`, {
    headers: { Cookie: cookie, Accept: 'text/html' },
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/console?view=cloud');
});

test('a member session is rejected by GET /admin/engram-cloud/import', async () => {
  const { cookie } = loginAsMember();
  const res = await fetch(`${baseUrl}/admin/engram-cloud/import`, {
    headers: { Cookie: cookie, Accept: 'application/json' },
  });
  assert.equal(res.status, 403);
  assert.equal(lastEngramCloudRequest, undefined);
});

test('a member session is rejected by GET /admin/engram-cloud/users (the Phase 3 admin proxy)', async () => {
  const { cookie } = loginAsMember();
  const res = await fetch(`${baseUrl}/admin/engram-cloud/users`, {
    headers: { Cookie: cookie, Accept: 'application/json' },
  });
  assert.equal(res.status, 403);
  assert.equal(lastEngramCloudRequest, undefined);
});

test('a member session on GET /admin/console?view=monitor is redirected to the cloud view, not admitted or errored', async () => {
  const { cookie } = loginAsMember();
  const res = await fetch(`${baseUrl}/admin/console?view=monitor`, { headers: { Cookie: cookie } });
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.ok(body.includes('<iframe src="/admin/engram-cloud/sso"'));
});

test('a member session is accepted by GET /admin/engram-cloud/sso, same as admin', async () => {
  const { cookie, userId } = loginAsMember();
  engramCloudResponsesByRoute['POST /admin/users'] = {
    status: 201,
    body: { principal_id: 'p-member-1', username: 'unit-member', role: 'member' },
  };
  engramCloudResponsesByRoute['POST /admin/users/p-member-1/tokens'] = {
    status: 201,
    body: { raw_token: 'member-token', token: { id: 't1', principal_id: 'p-member-1' } },
  };
  engramCloudResponsesByRoute['POST /dashboard/login'] = {
    status: 303,
    headers: { 'Set-Cookie': 'engram_dashboard_token=xyz; Path=/dashboard; HttpOnly; SameSite=Lax' },
  };

  const res = await fetch(`${baseUrl}/admin/engram-cloud/sso`, { headers: { Cookie: cookie }, redirect: 'manual' });
  assert.equal(res.status, 302);

  const createCall = engramCloudRequestLog.find((r) => r.url === '/admin/users');
  assert.deepEqual(JSON.parse(createCall.body), { username: 'unit-member', role: 'member' });
  const link = /** @type {any} */ (
    db.prepare('SELECT principal_id FROM engram_cloud_credentials WHERE user_id = ?').get(userId)
  );
  assert.equal(link.principal_id, 'p-member-1');
});

// mcp-profile-page — GET/POST /admin/profile: reachable by BOTH roles
// (unlike every other admin-app.js route this session), self or (admin
// only) another admin-panel account's MCP config + Cloud grants.

/** @returns {{ userId: number, cookie: string }} */
function insertAdminAccountWithCloudLink(username, role, principalId) {
  const userId = insertUser({ username, role });
  db.prepare(
    "INSERT INTO engram_cloud_credentials (user_id, principal_id, ciphertext, updated_at) VALUES (?, ?, 'irrelevant-ciphertext', datetime('now'))",
  ).run(userId, principalId);
  const token = createAdminSessionToken(userId, ADMIN_SECRET);
  return { userId, cookie: `__Host-admin_session=${token}` };
}

test('GET /admin/profile with no admin cookie returns 401', async () => {
  const res = await fetch(`${baseUrl}/admin/profile`, { headers: { Accept: 'application/json' } });
  assert.equal(res.status, 401);
});

test('GET /admin/profile (self, member, first visit) auto-issues a token and shows a copyable config per grant, using each grant project VERBATIM (engram-shared-projects — no prefix stripping/filtering)', async () => {
  const { cookie, userId } = insertAdminAccountWithCloudLink('profile-member-1', 'member', 'p-profile-1');
  engramCloudResponsesByRoute['GET /admin/users/p-profile-1/grants'] = {
    status: 200,
    body: [
      { principal_id: 'p-profile-1', project: 'demo-project', granted_by_principal_id: 'p-admin', created_at: '2026-01-01T00:00:00Z' },
      { principal_id: 'p-profile-1', project: 'team-shared-project', granted_by_principal_id: 'p-admin', created_at: '2026-01-01T00:00:00Z' },
    ],
  };

  const res = await fetch(`${baseUrl}/admin/profile`, { headers: { Cookie: cookie } });
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.ok(body.includes('demo-project'));
  assert.ok(body.includes('team-shared-project'));
  assert.ok(body.includes('"url": "https://jagoqui.tech/mcp/engram"') || body.includes('/mcp/engram'));

  const tokenRow = /** @type {any} */ (
    db.prepare("SELECT * FROM tokens WHERE user_id = ? AND revoked_at IS NULL").get(userId)
  );
  assert.ok(tokenRow);
  // The raw token isn't stored anywhere — only its hash — so the strongest
  // assertion available is that a real (non-empty, non-placeholder) Bearer
  // value was rendered, not that it matches a known constant.
  assert.ok(body.includes('Authorization'));
});

test('GET /admin/profile (self) on a SECOND visit does not re-issue a token or show a raw value, and offers Regenerate instead', async () => {
  const { cookie, userId } = insertAdminAccountWithCloudLink('profile-member-2', 'member', 'p-profile-2');
  engramCloudResponsesByRoute['GET /admin/users/p-profile-2/grants'] = { status: 200, body: [] };

  await fetch(`${baseUrl}/admin/profile`, { headers: { Cookie: cookie } });
  const firstCount = /** @type {any} */ (
    db.prepare('SELECT COUNT(*) AS n FROM tokens WHERE user_id = ?').get(userId)
  ).n;

  const res = await fetch(`${baseUrl}/admin/profile`, { headers: { Cookie: cookie } });
  const body = await res.text();
  const secondCount = /** @type {any} */ (
    db.prepare('SELECT COUNT(*) AS n FROM tokens WHERE user_id = ?').get(userId)
  ).n;
  assert.equal(secondCount, firstCount);
  assert.ok(body.includes('action="/admin/profile/regenerate-token"'));
});

test('GET /admin/profile (self, first visit, ZERO Engram Cloud grants) still shows the raw Bearer token via a default private config block, not just "No grants" text', async () => {
  const { cookie } = insertAdminAccountWithCloudLink('profile-zero-grants', 'admin', 'p-profile-zero');
  engramCloudResponsesByRoute['GET /admin/users/p-profile-zero/grants'] = { status: 200, body: [] };

  const res = await fetch(`${baseUrl}/admin/profile`, { headers: { Cookie: cookie } });
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.ok(body.includes('Authorization'));
  assert.ok(body.includes('Bearer '));
  assert.ok(body.includes('Default'));
});

test('GET /admin/profile?userId=N is rejected for a member (own profile only)', async () => {
  const { cookie } = insertAdminAccountWithCloudLink('profile-member-3', 'member', 'p-profile-3');
  const res = await fetch(`${baseUrl}/admin/profile?userId=1`, {
    headers: { Cookie: cookie, Accept: 'application/json' },
  });
  assert.equal(res.status, 403);
});

test('GET /admin/profile?userId=N works for an admin viewing another admin-panel account', async () => {
  const { cookie: adminCookie } = loginAsAdmin('profile-admin-viewer');
  const { userId: targetId } = insertAdminAccountWithCloudLink('profile-member-4', 'member', 'p-profile-4');
  engramCloudResponsesByRoute['GET /admin/users/p-profile-4/grants'] = { status: 200, body: [] };

  const res = await fetch(`${baseUrl}/admin/profile?userId=${targetId}`, { headers: { Cookie: adminCookie } });
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.ok(body.includes('profile-member-4'));
});

test('POST /admin/profile/regenerate-token (self) issues a new token, revokes the old one, and shows the fresh raw value DIRECTLY (D10, no redirect that would lose it)', async () => {
  const { cookie, userId } = insertAdminAccountWithCloudLink('profile-member-5', 'member', 'p-profile-5');
  engramCloudResponsesByRoute['GET /admin/users/p-profile-5/grants'] = {
    status: 200,
    body: [{ principal_id: 'p-profile-5', project: 'demo-project', granted_by_principal_id: 'p-admin', created_at: '2026-01-01T00:00:00Z' }],
  };
  await fetch(`${baseUrl}/admin/profile`, { headers: { Cookie: cookie } });
  const oldToken = /** @type {any} */ (
    db.prepare('SELECT id FROM tokens WHERE user_id = ? AND revoked_at IS NULL').get(userId)
  );
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);

  const res = await fetch(`${baseUrl}/admin/profile/regenerate-token`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ tokenId: String(oldToken.id), csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.ok(body.includes('demo-project'));
  assert.ok(body.includes('Authorization'));
  assert.ok(body.includes('Copy this now'));

  const oldRow = /** @type {any} */ (db.prepare('SELECT revoked_at FROM tokens WHERE id = ?').get(oldToken.id));
  assert.ok(oldRow.revoked_at);
  const activeCount = /** @type {any} */ (
    db.prepare('SELECT COUNT(*) AS n FROM tokens WHERE user_id = ? AND revoked_at IS NULL').get(userId)
  ).n;
  assert.equal(activeCount, 1);
});

test('POST /admin/profile/regenerate-token with a userId for another account is rejected for a member', async () => {
  const { cookie, userId } = insertAdminAccountWithCloudLink('profile-member-6', 'member', 'p-profile-6');
  const { userId: otherId } = insertAdminAccountWithCloudLink('profile-member-7', 'member', 'p-profile-7');
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);

  const res = await fetch(`${baseUrl}/admin/profile/regenerate-token`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ tokenId: '1', userId: String(otherId), csrf }),
  });
  assert.equal(res.status, 403);
});

test('POST /admin/profile/revoke-token (self) revokes the active token and leaves none active', async () => {
  const { cookie, userId } = insertAdminAccountWithCloudLink('profile-member-8', 'member', 'p-profile-8');
  engramCloudResponsesByRoute['GET /admin/users/p-profile-8/grants'] = { status: 200, body: [] };
  await fetch(`${baseUrl}/admin/profile`, { headers: { Cookie: cookie } });
  const activeToken = /** @type {any} */ (
    db.prepare('SELECT id FROM tokens WHERE user_id = ? AND revoked_at IS NULL').get(userId)
  );
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);

  const res = await fetch(`${baseUrl}/admin/profile/revoke-token`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ tokenId: String(activeToken.id), csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);

  const activeCount = /** @type {any} */ (
    db.prepare('SELECT COUNT(*) AS n FROM tokens WHERE user_id = ? AND revoked_at IS NULL').get(userId)
  ).n;
  assert.equal(activeCount, 0);
});

test('POST /admin/profile/revoke-token with a userId for another account is rejected for a member', async () => {
  const { cookie, userId } = insertAdminAccountWithCloudLink('profile-member-9', 'member', 'p-profile-9');
  const { userId: otherId } = insertAdminAccountWithCloudLink('profile-member-10', 'member', 'p-profile-10');
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);

  const res = await fetch(`${baseUrl}/admin/profile/revoke-token`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ tokenId: '1', userId: String(otherId), csrf }),
  });
  assert.equal(res.status, 403);
});

test('POST /admin/profile/revoke-token works for an admin revoking another admin-panel account\'s token', async () => {
  const { cookie: adminCookie } = loginAsAdmin('profile-admin-revoker');
  const { userId: targetId } = insertAdminAccountWithCloudLink('profile-member-11', 'member', 'p-profile-11');
  engramCloudResponsesByRoute['GET /admin/users/p-profile-11/grants'] = { status: 200, body: [] };
  await fetch(`${baseUrl}/admin/profile?userId=${targetId}`, { headers: { Cookie: adminCookie } });
  const activeToken = /** @type {any} */ (
    db.prepare('SELECT id FROM tokens WHERE user_id = ? AND revoked_at IS NULL').get(targetId)
  );
  const adminId = /** @type {any} */ (db.prepare('SELECT id FROM users WHERE username = ?').get('profile-admin-revoker')).id;
  const csrf = issueAdminCsrfToken(adminId, ADMIN_SECRET);

  const res = await fetch(`${baseUrl}/admin/profile/revoke-token`, {
    method: 'POST',
    headers: {
      Cookie: adminCookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ tokenId: String(activeToken.id), userId: String(targetId), csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);

  const activeCount = /** @type {any} */ (
    db.prepare('SELECT COUNT(*) AS n FROM tokens WHERE user_id = ? AND revoked_at IS NULL').get(targetId)
  ).n;
  assert.equal(activeCount, 0);
});

// Both-token-systems-shown-separately (user-requested 2026-09-18, after
// verifying via deepwiki against Gentleman-Programming/engram what Cloud
// actually tracks: no usage count, no client/machine/IP, ever).

test('GET /admin/profile (self) does NOT emit a userId hidden field on the Regenerate/Revoke forms — the real bug fix', async () => {
  const { cookie } = insertAdminAccountWithCloudLink('profile-selfbug-1', 'member', 'p-profile-selfbug-1');
  engramCloudResponsesByRoute['GET /admin/users/p-profile-selfbug-1/grants'] = { status: 200, body: [] };
  engramCloudResponsesByRoute['GET /admin/users/p-profile-selfbug-1/tokens'] = { status: 200, body: [] };

  const res = await fetch(`${baseUrl}/admin/profile`, { headers: { Cookie: cookie } });
  const body = await res.text();
  assert.ok(!body.includes('name="userId"'));
});

test('GET /admin/profile?userId=N (admin viewing another account) DOES emit the userId hidden field', async () => {
  const { cookie: adminCookie } = loginAsAdmin('profile-selfbug-admin');
  const { userId: targetId } = insertAdminAccountWithCloudLink('profile-selfbug-2', 'member', 'p-profile-selfbug-2');
  engramCloudResponsesByRoute['GET /admin/users/p-profile-selfbug-2/grants'] = { status: 200, body: [] };
  engramCloudResponsesByRoute['GET /admin/users/p-profile-selfbug-2/tokens'] = { status: 200, body: [] };

  const res = await fetch(`${baseUrl}/admin/profile?userId=${targetId}`, { headers: { Cookie: adminCookie } });
  const body = await res.text();
  assert.ok(body.includes(`name="userId" value="${targetId}"`));
});

test('A member submitting EXACTLY what the self-view Regenerate form emits (no userId key) succeeds, not 403 (reproduces the real live bug)', async () => {
  const { cookie, userId } = insertAdminAccountWithCloudLink('profile-selfbug-3', 'member', 'p-profile-selfbug-3');
  engramCloudResponsesByRoute['GET /admin/users/p-profile-selfbug-3/grants'] = { status: 200, body: [] };
  engramCloudResponsesByRoute['GET /admin/users/p-profile-selfbug-3/tokens'] = { status: 200, body: [] };
  const getRes = await fetch(`${baseUrl}/admin/profile`, { headers: { Cookie: cookie } });
  const getBody = await getRes.text();
  assert.ok(!getBody.includes('name="userId"'), 'precondition: self form must not include userId');

  const activeToken = /** @type {any} */ (
    db.prepare('SELECT id FROM tokens WHERE user_id = ? AND revoked_at IS NULL').get(userId)
  );
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  const res = await fetch(`${baseUrl}/admin/profile/regenerate-token`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    // Deliberately no `userId` key — exactly what the real form (fixed
    // above) now submits for self, unlike before the fix.
    body: new URLSearchParams({ tokenId: String(activeToken.id), csrf }),
  });
  assert.equal(res.status, 200);
});

test('GET /admin/profile renders the full gateway-token HISTORY (active and revoked), not just the current one', async () => {
  const { cookie, userId } = insertAdminAccountWithCloudLink('profile-history-1', 'member', 'p-profile-history-1');
  engramCloudResponsesByRoute['GET /admin/users/p-profile-history-1/grants'] = { status: 200, body: [] };
  engramCloudResponsesByRoute['GET /admin/users/p-profile-history-1/tokens'] = { status: 200, body: [] };
  await fetch(`${baseUrl}/admin/profile`, { headers: { Cookie: cookie } });
  const firstToken = /** @type {any} */ (
    db.prepare('SELECT id FROM tokens WHERE user_id = ? AND revoked_at IS NULL').get(userId)
  );
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);
  await fetch(`${baseUrl}/admin/profile/regenerate-token`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ tokenId: String(firstToken.id), csrf }),
  });

  const res = await fetch(`${baseUrl}/admin/profile`, { headers: { Cookie: cookie } });
  const body = await res.text();
  const tokenRows = /** @type {any[]} */ (
    db.prepare('SELECT id FROM tokens WHERE user_id = ? ORDER BY id').all(userId)
  );
  assert.equal(tokenRows.length, 2);
  // The revoked (first) row renders NO tokenId value at all — by design,
  // Regenerate/Revoke only ever render for an active token (dead-end
  // actions are never offered) — so the only reliable signal that BOTH
  // rows made it into the table is the total row count, via one badge
  // <td> per token row (the Cloud tokens table is stubbed empty above,
  // so every badge <td> in this body belongs to the gateway table).
  const badgeCellCount = (body.match(/<td><span class="badge">/g) ?? []).length;
  assert.equal(badgeCellCount, 2);
  assert.ok(body.includes(`value="${tokenRows[1].id}"`), 'the active (second) token row must offer actions');
  assert.ok(body.includes('revoked'));
  assert.ok(body.includes('active'));
});

test('GET /admin/profile shows a separate "Engram Cloud token" section, with revoked tokens showing their reason', async () => {
  const { cookie } = insertAdminAccountWithCloudLink('profile-cloud-1', 'admin', 'p-profile-cloud-1');
  engramCloudResponsesByRoute['GET /admin/users/p-profile-cloud-1/grants'] = { status: 200, body: [] };
  engramCloudResponsesByRoute['GET /admin/users/p-profile-cloud-1/tokens'] = {
    status: 200,
    body: [
      {
        id: 'tok_active_1', principal_id: 'p-profile-cloud-1', token_prefix: 'eg_live',
        name: 'console-sso', created_by_principal_id: 'p-admin', created_at: '2026-01-01T00:00:00Z',
        last_used_at: '2026-01-05T00:00:00Z', revoked_at: null, revoked_by_principal_id: null, revocation_reason: null,
      },
      {
        id: 'tok_old_1', principal_id: 'p-profile-cloud-1', token_prefix: 'eg_dead',
        name: 'console-sso', created_by_principal_id: 'p-admin', created_at: '2025-12-01T00:00:00Z',
        last_used_at: null, revoked_at: '2025-12-15T00:00:00Z', revoked_by_principal_id: 'p-admin',
        revocation_reason: 'revoked via admin panel',
      },
    ],
  };

  const res = await fetch(`${baseUrl}/admin/profile`, { headers: { Cookie: cookie } });
  const body = await res.text();
  assert.ok(body.includes('Engram Cloud token'));
  assert.ok(body.includes('eg_live'));
  assert.ok(body.includes('eg_dead'));
  assert.ok(body.includes('revoked via admin panel'));
  // The honest disclaimer legitimately SAYS "usage count"/"machine" to
  // explain they're NOT tracked — the real guard is that no column or
  // value in the table itself claims to show one.
  assert.ok(!body.includes('<th>Machine</th>'));
  assert.ok(!body.includes('<th>IP</th>'));
  assert.ok(!body.includes('<th>Usage</th>'));
});

test('GET /admin/profile hides the Engram Cloud token section entirely when there is no Cloud link at all (self-heal failed)', async () => {
  const userId = insertUser({ username: 'profile-nolinkatall', isAdmin: true, role: 'admin' });
  const cookie = `__Host-admin_session=${createAdminSessionToken(userId, ADMIN_SECRET)}`;
  // No stub for POST /admin/users → falls back to nextEngramCloudResponse's
  // default {status:200, body:{}}, missing principal_id → createEngramCloudUser
  // fails → ensureEngramCloudLink throws, swallowed, no credential row saved.
  nextEngramCloudResponse = { status: 500, body: { error: 'unreachable' } };

  const res = await fetch(`${baseUrl}/admin/profile`, { headers: { Cookie: cookie } });
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.ok(!body.includes('Engram Cloud token'));
});

test('a non-array Cloud tokens response never crashes the page (defensive, not just optimistic) — same class of bug as the redirect-loses-the-token fix', async () => {
  const { cookie } = insertAdminAccountWithCloudLink('profile-malformed-1', 'admin', 'p-profile-malformed-1');
  engramCloudResponsesByRoute['GET /admin/users/p-profile-malformed-1/grants'] = { status: 200, body: [] };
  engramCloudResponsesByRoute['GET /admin/users/p-profile-malformed-1/tokens'] = { status: 200, body: {} };

  const res = await fetch(`${baseUrl}/admin/profile`, { headers: { Cookie: cookie } });
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.ok(body.includes('Engram Cloud token'));
});

test('POST /admin/profile/cloud-token/revoke (self) revokes a Cloud token and records an audit row', async () => {
  const { cookie, userId } = insertAdminAccountWithCloudLink('profile-cloudrevoke-1', 'member', 'p-profile-cloudrevoke-1');
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);

  const res = await fetch(`${baseUrl}/admin/profile/cloud-token/revoke`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ tokenId: 'tok_abc', csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(lastEngramCloudRequest?.method, 'POST');
  assert.equal(lastEngramCloudRequest?.url, '/admin/tokens/tok_abc/revoke');
  assert.deepEqual(JSON.parse(/** @type {string} */ (lastEngramCloudRequest?.body)), {
    reason: 'revoked via admin panel',
  });

  const auditRows = /** @type {any[]} */ (
    db.prepare("SELECT * FROM admin_audit_log WHERE action = 'cloud_token.revoke'").all()
  );
  assert.equal(auditRows.length, 1);
  assert.equal(auditRows[0].outcome, 'success');
  assert.equal(auditRows[0].target_user_id, userId);
  assert.equal(auditRows[0].target_token_id, null);
  assert.deepEqual(JSON.parse(auditRows[0].detail), { cloudTokenId: 'tok_abc' });
});

test('POST /admin/profile/cloud-token/revoke with a userId for another account is rejected for a member', async () => {
  const { cookie, userId } = insertAdminAccountWithCloudLink('profile-cloudrevoke-2', 'member', 'p-profile-cloudrevoke-2');
  const { userId: otherId } = insertAdminAccountWithCloudLink('profile-cloudrevoke-3', 'member', 'p-profile-cloudrevoke-3');
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);

  const res = await fetch(`${baseUrl}/admin/profile/cloud-token/revoke`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ tokenId: 'tok_abc', userId: String(otherId), csrf }),
  });
  assert.equal(res.status, 403);
});

test('POST /admin/profile/cloud-token/revoke works for an admin revoking a target account\'s Cloud token', async () => {
  const { cookie: adminCookie } = loginAsAdmin('profile-cloudrevoke-admin');
  const { userId: targetId } = insertAdminAccountWithCloudLink('profile-cloudrevoke-4', 'member', 'p-profile-cloudrevoke-4');
  const adminId = /** @type {any} */ (
    db.prepare('SELECT id FROM users WHERE username = ?').get('profile-cloudrevoke-admin')
  ).id;
  const csrf = issueAdminCsrfToken(adminId, ADMIN_SECRET);

  const res = await fetch(`${baseUrl}/admin/profile/cloud-token/revoke`, {
    method: 'POST',
    headers: {
      Cookie: adminCookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ tokenId: 'tok_xyz', userId: String(targetId), csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(lastEngramCloudRequest?.url, '/admin/tokens/tok_xyz/revoke');
});

test('POST /admin/profile/cloud-token/revoke redirects with error=not_found (form client) when the account has no Cloud link', async () => {
  const userId = insertUser({ username: 'profile-cloudrevoke-nolink', isAdmin: true, role: 'admin' });
  const cookie = `__Host-admin_session=${createAdminSessionToken(userId, ADMIN_SECRET)}`;
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);

  const res = await fetch(`${baseUrl}/admin/profile/cloud-token/revoke`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ tokenId: 'tok_abc', csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.ok(res.headers.get('location')?.includes('error=not_found'));
});

// Projects section (user-requested 2026-09-18): show which Cloud
// projects a profile has access to, plus an admin-only way to grant a
// new one, quoting Cloud's own deny-by-default model.

test('GET /admin/profile shows a Projects section with full grant metadata', async () => {
  const { cookie } = insertAdminAccountWithCloudLink('profile-projects-1', 'admin', 'p-profile-projects-1');
  engramCloudResponsesByRoute['GET /admin/users/p-profile-projects-1/grants'] = {
    status: 200,
    body: [
      { principal_id: 'p-profile-projects-1', project: 'demo-project', granted_by_principal_id: 'p-admin', created_at: '2026-01-01T00:00:00Z' },
    ],
  };
  engramCloudResponsesByRoute['GET /admin/users/p-profile-projects-1/tokens'] = { status: 200, body: [] };

  const res = await fetch(`${baseUrl}/admin/profile`, { headers: { Cookie: cookie } });
  const body = await res.text();
  assert.ok(body.includes('Projects'));
  assert.ok(body.includes('demo-project'));
  assert.ok(body.includes('p-admin'));
  assert.ok(body.includes('2026-01-01T00:00:00Z'));
});

test('GET /admin/profile shows the Grant form for an admin, but NEVER for a member (deny-by-default)', async () => {
  const { cookie: memberCookie } = insertAdminAccountWithCloudLink('profile-projects-2', 'member', 'p-profile-projects-2');
  engramCloudResponsesByRoute['GET /admin/users/p-profile-projects-2/grants'] = { status: 200, body: [] };
  engramCloudResponsesByRoute['GET /admin/users/p-profile-projects-2/tokens'] = { status: 200, body: [] };
  const memberRes = await fetch(`${baseUrl}/admin/profile`, { headers: { Cookie: memberCookie } });
  const memberBody = await memberRes.text();
  assert.ok(!memberBody.includes('action="/admin/profile/grant-project"'));

  const { cookie: adminCookie } = loginAsAdmin('profile-projects-admin');
  const adminRes = await fetch(`${baseUrl}/admin/profile`, { headers: { Cookie: adminCookie } });
  const adminBody = await adminRes.text();
  assert.ok(adminBody.includes('action="/admin/profile/grant-project"'));
});

test('POST /admin/profile/grant-project (admin, self) grants the project and records an audit row', async () => {
  const { cookie: adminCookie } = loginAsAdmin('profile-grant-1');
  const adminId = /** @type {any} */ (db.prepare('SELECT id FROM users WHERE username = ?').get('profile-grant-1')).id;
  engramCloudResponsesByRoute['POST /admin/users'] = {
    status: 200,
    body: { principal_id: 'p-grant-1' },
  };
  engramCloudResponsesByRoute['POST /admin/users/p-grant-1/tokens'] = {
    status: 200,
    body: { raw_token: 'irrelevant', token: { id: 't1' } },
  };
  // Trigger ensureEngramCloudLink's provisioning (self-heal) by visiting first.
  await fetch(`${baseUrl}/admin/profile`, { headers: { Cookie: adminCookie } });
  const csrf = issueAdminCsrfToken(adminId, ADMIN_SECRET);

  const res = await fetch(`${baseUrl}/admin/profile/grant-project`, {
    method: 'POST',
    headers: {
      Cookie: adminCookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ project: 'demo-project', csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(lastEngramCloudRequest?.method, 'POST');
  assert.equal(lastEngramCloudRequest?.url, '/admin/users/p-grant-1/grants');
  assert.deepEqual(JSON.parse(/** @type {string} */ (lastEngramCloudRequest?.body)), { project: 'demo-project' });

  const auditRows = /** @type {any[]} */ (
    db.prepare("SELECT * FROM admin_audit_log WHERE action = 'project.grant'").all()
  );
  assert.equal(auditRows.length, 1);
  assert.equal(auditRows[0].outcome, 'success');
  assert.equal(auditRows[0].target_user_id, adminId);
  assert.deepEqual(JSON.parse(auditRows[0].detail), { project: 'demo-project' });
});

test('POST /admin/profile/grant-project works for an admin granting a target account a project', async () => {
  const { cookie: adminCookie } = loginAsAdmin('profile-grant-admin');
  const adminId = /** @type {any} */ (db.prepare('SELECT id FROM users WHERE username = ?').get('profile-grant-admin')).id;
  const { userId: targetId } = insertAdminAccountWithCloudLink('profile-grant-2', 'member', 'p-grant-2');
  const csrf = issueAdminCsrfToken(adminId, ADMIN_SECRET);

  const res = await fetch(`${baseUrl}/admin/profile/grant-project`, {
    method: 'POST',
    headers: {
      Cookie: adminCookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ project: 'shared-project', userId: String(targetId), csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), `/admin/profile?userId=${targetId}`);
  assert.equal(lastEngramCloudRequest?.url, '/admin/users/p-grant-2/grants');
});

test('POST /admin/profile/grant-project is rejected for a member, even targeting themselves with no userId', async () => {
  const { cookie, userId } = insertAdminAccountWithCloudLink('profile-grant-3', 'member', 'p-grant-3');
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);

  const res = await fetch(`${baseUrl}/admin/profile/grant-project`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ project: 'demo-project', csrf }),
  });
  assert.equal(res.status, 403);
  assert.equal(lastEngramCloudRequest, undefined);
});

test('POST /admin/profile/grant-project with an empty project name redirects with error=invalid_project', async () => {
  const { cookie: adminCookie } = loginAsAdmin('profile-grant-4');
  const adminId = /** @type {any} */ (db.prepare('SELECT id FROM users WHERE username = ?').get('profile-grant-4')).id;
  const csrf = issueAdminCsrfToken(adminId, ADMIN_SECRET);

  const res = await fetch(`${baseUrl}/admin/profile/grant-project`, {
    method: 'POST',
    headers: {
      Cookie: adminCookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ project: '   ', csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.ok(res.headers.get('location')?.includes('error=invalid_project'));
});

test('POST /admin/profile/grant-project redirects with error=not_found when the target has no Cloud link', async () => {
  const userId = insertUser({ username: 'profile-grant-nolink', isAdmin: true, role: 'admin' });
  const cookie = `__Host-admin_session=${createAdminSessionToken(userId, ADMIN_SECRET)}`;
  nextEngramCloudResponse = { status: 500, body: { error: 'unreachable' } };
  const csrf = issueAdminCsrfToken(userId, ADMIN_SECRET);

  const res = await fetch(`${baseUrl}/admin/profile/grant-project`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ project: 'demo-project', csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.ok(res.headers.get('location')?.includes('error=not_found'));
});

test('POST /admin/profile/grant-project redirects with error=unreachable (and audits a failure) when Cloud rejects the grant', async () => {
  const { cookie: adminCookie } = loginAsAdmin('profile-grant-5');
  const adminId = /** @type {any} */ (db.prepare('SELECT id FROM users WHERE username = ?').get('profile-grant-5')).id;
  const { userId: targetId } = insertAdminAccountWithCloudLink('profile-grant-6', 'member', 'p-grant-6');
  engramCloudResponsesByRoute['POST /admin/users/p-grant-6/grants'] = { status: 500, body: { error: 'boom' } };
  const csrf = issueAdminCsrfToken(adminId, ADMIN_SECRET);

  const res = await fetch(`${baseUrl}/admin/profile/grant-project`, {
    method: 'POST',
    headers: {
      Cookie: adminCookie,
      Origin: `https://monitor.${DOMAIN}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ project: 'demo-project', userId: String(targetId), csrf }),
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  assert.ok(res.headers.get('location')?.includes('error=unreachable'));

  const auditRows = /** @type {any[]} */ (
    db.prepare("SELECT * FROM admin_audit_log WHERE action = 'project.grant'").all()
  );
  assert.equal(auditRows.length, 1);
  assert.equal(auditRows[0].outcome, 'failure');
});

// engram-shared-projects — GET /internal/engram-grant: service-to-service
// only (shared secret, no admin session), checked once by engram-router's
// cold spawn path before allowing a client into a shared (non-private)
// project.

test('GET /internal/engram-grant with no/wrong secret returns 401, stub never hit', async () => {
  const res1 = await fetch(`${baseUrl}/internal/engram-grant?identity=x&project=y`);
  assert.equal(res1.status, 401);
  const res2 = await fetch(`${baseUrl}/internal/engram-grant?identity=x&project=y`, {
    headers: { 'X-Internal-Secret': 'wrong-secret' },
  });
  assert.equal(res2.status, 401);
  assert.equal(lastEngramCloudRequest, undefined);
});

test('GET /internal/engram-grant returns granted:true when the identity has an exact grant for that bare project', async () => {
  insertAdminAccountWithCloudLink('grant-check-identity-1', 'admin', 'p-grant-1');
  engramCloudResponsesByRoute['GET /admin/users/p-grant-1/grants'] = {
    status: 200,
    body: [{ principal_id: 'p-grant-1', project: 'shared-project-alpha', granted_by_principal_id: 'p-admin', created_at: '2026-01-01T00:00:00Z' }],
  };

  const res = await fetch(
    `${baseUrl}/internal/engram-grant?identity=grant-check-identity-1&project=shared-project-alpha`,
    { headers: { 'X-Internal-Secret': INTERNAL_SECRET } },
  );
  assert.equal(res.status, 200);
  const body = /** @type {any} */ (await res.json());
  assert.equal(body.granted, true);
});

test('GET /internal/engram-grant returns granted:false when no such grant exists', async () => {
  insertAdminAccountWithCloudLink('grant-check-identity-2', 'admin', 'p-grant-2');
  engramCloudResponsesByRoute['GET /admin/users/p-grant-2/grants'] = { status: 200, body: [] };

  const res = await fetch(
    `${baseUrl}/internal/engram-grant?identity=grant-check-identity-2&project=nope`,
    { headers: { 'X-Internal-Secret': INTERNAL_SECRET } },
  );
  assert.equal(res.status, 200);
  const body = /** @type {any} */ (await res.json());
  assert.equal(body.granted, false);
});

test('GET /internal/engram-grant returns granted:false (fail closed) for an unknown identity, or one with no Cloud link, or an unreachable Cloud', async () => {
  const unknown = await fetch(
    `${baseUrl}/internal/engram-grant?identity=no-such-user&project=x`,
    { headers: { 'X-Internal-Secret': INTERNAL_SECRET } },
  );
  assert.equal((/** @type {any} */ (await unknown.json())).granted, false);

  insertUser({ username: 'grant-check-no-link', role: 'admin' });
  const noLink = await fetch(
    `${baseUrl}/internal/engram-grant?identity=grant-check-no-link&project=x`,
    { headers: { 'X-Internal-Secret': INTERNAL_SECRET } },
  );
  assert.equal((/** @type {any} */ (await noLink.json())).granted, false);

  insertAdminAccountWithCloudLink('grant-check-cloud-down', 'admin', 'p-grant-3');
  await engramCloudStub.close();
  const cloudDown = await fetch(
    `${baseUrl}/internal/engram-grant?identity=grant-check-cloud-down&project=x`,
    { headers: { 'X-Internal-Secret': INTERNAL_SECRET } },
  );
  assert.equal((/** @type {any} */ (await cloudDown.json())).granted, false);
});

// engram-contributor-attribution — GET /internal/engram-cloud-token: same
// service-to-service shape as /internal/engram-grant, but resolves an
// identity's own DECRYPTED Cloud token (pure local DB, never calls out to
// Cloud) — engram-router's cold spawn path uses it so each spawned child
// authenticates with ITS identity's own token instead of the shared
// legacy one, fixing Cloud's Contributors tab attribution.

test('GET /internal/engram-cloud-token with no/wrong secret returns 401', async () => {
  const res1 = await fetch(`${baseUrl}/internal/engram-cloud-token?identity=x`);
  assert.equal(res1.status, 401);
  const res2 = await fetch(`${baseUrl}/internal/engram-cloud-token?identity=x`, {
    headers: { 'X-Internal-Secret': 'wrong-secret' },
  });
  assert.equal(res2.status, 401);
});

test('GET /internal/engram-cloud-token with no identity param returns 400', async () => {
  const res = await fetch(`${baseUrl}/internal/engram-cloud-token`, {
    headers: { 'X-Internal-Secret': INTERNAL_SECRET },
  });
  assert.equal(res.status, 400);
});

test('GET /internal/engram-cloud-token returns the decrypted token for a real linked identity', async () => {
  const userId = insertUser({ username: 'cloud-token-identity-1', role: 'admin' });
  db.prepare(
    "INSERT INTO engram_cloud_credentials (user_id, principal_id, ciphertext, updated_at) VALUES (?, ?, ?, datetime('now'))",
  ).run(userId, 'p-cloud-token-1', encrypt('real-raw-cloud-token-value'));

  const res = await fetch(
    `${baseUrl}/internal/engram-cloud-token?identity=cloud-token-identity-1`,
    { headers: { 'X-Internal-Secret': INTERNAL_SECRET } },
  );
  assert.equal(res.status, 200);
  const body = /** @type {any} */ (await res.json());
  assert.equal(body.token, 'real-raw-cloud-token-value');
});

test('GET /internal/engram-cloud-token returns token:null for an unknown identity', async () => {
  const res = await fetch(
    `${baseUrl}/internal/engram-cloud-token?identity=no-such-user`,
    { headers: { 'X-Internal-Secret': INTERNAL_SECRET } },
  );
  assert.equal(res.status, 200);
  const body = /** @type {any} */ (await res.json());
  assert.equal(body.token, null);
});

test('GET /internal/engram-cloud-token returns token:null for a known identity with no Cloud link', async () => {
  insertUser({ username: 'cloud-token-no-link', role: 'admin' });

  const res = await fetch(
    `${baseUrl}/internal/engram-cloud-token?identity=cloud-token-no-link`,
    { headers: { 'X-Internal-Secret': INTERNAL_SECRET } },
  );
  assert.equal(res.status, 200);
  const body = /** @type {any} */ (await res.json());
  assert.equal(body.token, null);
});
