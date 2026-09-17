import { test, before, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { openDb } from '../src/db.js';
import { createServer } from '../src/app.js';
import { createAdminSessionToken } from '../src/admin-session.js';
import { createSessionToken } from '../src/session.js';
import { issueAdminCsrfToken } from '../src/csrf.js';
import { ADMIN_LOGIN_MAX_ATTEMPTS } from '../src/admin-throttle.js';
import http from 'node:http';

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

test('GET /admin/users lists only is_admin=0 users, with disabled state and token counts, never admin rows', async () => {
  const { cookie } = loginAsAdmin();
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
  assert.ok(!body.includes('unit8-admin'));
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

test('POST /admin/login succeeds for a role=member account, same as admin', async () => {
  const { username, password } = await createRealAdmin('login-member', 'member');
  const res = await postAdminLogin({ username, password });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/admin/users');
});

test('a member session is rejected by GET /admin/users', async () => {
  const { cookie } = loginAsMember();
  const res = await fetch(`${baseUrl}/admin/users`, {
    headers: { Cookie: cookie, Accept: 'application/json' },
  });
  assert.equal(res.status, 403);
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
