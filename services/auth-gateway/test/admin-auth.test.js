import { test } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../src/db.js';
import { createAdminSessionToken } from '../src/admin-session.js';
import { authenticateAdmin } from '../src/admin-auth.js';

const ADMIN_SECRET = 'admin-auth-test-secret';

/**
 * @param {import('better-sqlite3').Database} db
 * @param {{ username?: string, isAdmin?: boolean, disabled?: boolean }} [opts]
 */
function insertUser(db, opts = {}) {
  const { username = 'root-admin', isAdmin = true, disabled = false } = opts;
  const info = db
    .prepare(
      'INSERT INTO users (username, password_hash, is_admin, disabled_at) VALUES (?, ?, ?, ?)',
    )
    .run(
      username,
      'bcrypt-placeholder',
      isAdmin ? 1 : 0,
      disabled ? '2024-01-01T00:00:00Z' : null,
    );
  return Number(info.lastInsertRowid);
}

/**
 * @param {string} token
 * @returns {{ cookie: string }}
 */
function cookieHeaders(token) {
  return { cookie: `__Host-admin_session=${token}` };
}

// 5.1 — valid admin cookie -> the user row.
test('authenticateAdmin returns the user row for a valid admin cookie, is_admin=1, not disabled', () => {
  const db = openDb(':memory:');
  const userId = insertUser(db, { username: 'root-admin' });
  const token = createAdminSessionToken(userId, ADMIN_SECRET);
  const user = authenticateAdmin(db, cookieHeaders(token), ADMIN_SECRET);
  assert.ok(user);
  assert.equal(user.id, userId);
  assert.equal(user.username, 'root-admin');
  db.close();
});

// 5.1 — is_admin=0 -> null, even with an otherwise valid, signed token.
test('authenticateAdmin returns null when the token references a non-admin user (is_admin=0)', () => {
  const db = openDb(':memory:');
  const userId = insertUser(db, { username: 'regular-jane', isAdmin: false });
  const token = createAdminSessionToken(userId, ADMIN_SECRET);
  const user = authenticateAdmin(db, cookieHeaders(token), ADMIN_SECRET);
  assert.equal(user, null);
  db.close();
});

// 5.1 — disabled_at set -> null, live re-check against the DB (never cached).
test('authenticateAdmin returns null when the admin user has been disabled', () => {
  const db = openDb(':memory:');
  const userId = insertUser(db, { username: 'disabled-admin', isAdmin: true, disabled: true });
  const token = createAdminSessionToken(userId, ADMIN_SECRET);
  const user = authenticateAdmin(db, cookieHeaders(token), ADMIN_SECRET);
  assert.equal(user, null);
  db.close();
});

// 5.1 — is_admin/disabled_at are re-checked LIVE, not cached in the token:
// disabling the user AFTER the token was issued still rejects it.
test('authenticateAdmin rejects a token issued before the admin user was disabled (live re-check, never cached)', () => {
  const db = openDb(':memory:');
  const userId = insertUser(db, { username: 'later-disabled', isAdmin: true });
  const token = createAdminSessionToken(userId, ADMIN_SECRET);
  db.prepare('UPDATE users SET disabled_at = ? WHERE id = ?').run('2024-06-01T00:00:00Z', userId);
  const user = authenticateAdmin(db, cookieHeaders(token), ADMIN_SECRET);
  assert.equal(user, null);
  db.close();
});

// 5.1 — expired token -> null.
test('authenticateAdmin returns null for an expired admin session token', () => {
  const db = openDb(':memory:');
  const userId = insertUser(db, { username: 'expired-admin' });
  const issuedAt = Date.now();
  const token = createAdminSessionToken(userId, ADMIN_SECRET, issuedAt);
  const farFuture = issuedAt + 28801 * 1000;
  const user = authenticateAdmin(db, cookieHeaders(token), ADMIN_SECRET, farFuture);
  assert.equal(user, null);
  db.close();
});

// 5.1 — tampered token -> null.
test('authenticateAdmin returns null for a tampered admin session token', () => {
  const db = openDb(':memory:');
  const userId = insertUser(db, { username: 'tampered-admin' });
  const token = createAdminSessionToken(userId, ADMIN_SECRET);
  const tampered = `${token}deadbeef`;
  const user = authenticateAdmin(db, cookieHeaders(tampered), ADMIN_SECRET);
  assert.equal(user, null);
  db.close();
});

// 5.1 — no cookie at all -> null.
test('authenticateAdmin returns null when no cookie header is present', () => {
  const db = openDb(':memory:');
  insertUser(db, { username: 'root-admin' });
  const user = authenticateAdmin(db, {}, ADMIN_SECRET);
  assert.equal(user, null);
  db.close();
});

// 5.1/A8 — an Authorization: Bearer header alone (no cookie) never
// authenticates, regardless of the token's validity — the function must
// never read headers.authorization at all.
test('threat: authenticateAdmin never reads headers.authorization (A8) — a Bearer header carrying a valid admin token still returns null with no cookie', () => {
  const db = openDb(':memory:');
  const userId = insertUser(db, { username: 'bearer-admin' });
  const token = createAdminSessionToken(userId, ADMIN_SECRET);
  const user = authenticateAdmin(db, { authorization: `Bearer ${token}` }, ADMIN_SECRET);
  assert.equal(user, null);
  db.close();
});
