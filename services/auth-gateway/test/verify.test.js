import { test, before, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { openDb } from '../src/db.js';
import { hashToken } from '../src/tokens.js';
import { encrypt } from '../src/crypto.js';
import { createSessionToken } from '../src/session.js';
import { createServer } from '../src/app.js';
import { authenticateWithMethod } from '../src/verify.js';

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
 * @param {{ username?: string, password?: string, disabled?: boolean, admin?: boolean }} [opts]
 */
function insertUser(opts = {}) {
  const { username = 'alice', password = 'irrelevant-for-token-tests', disabled = false } = opts;
  const info = db
    .prepare('INSERT INTO users (username, password_hash, disabled_at) VALUES (?, ?, ?)')
    .run(username, `bcrypt-placeholder-${password}`, disabled ? '2024-01-01T00:00:00Z' : null);
  return Number(info.lastInsertRowid);
}

/**
 * @param {number} userId
 * @param {string} rawToken
 * @param {{ revoked?: boolean }} [opts]
 */
function insertToken(userId, rawToken, opts = {}) {
  const { revoked = false } = opts;
  db.prepare('INSERT INTO tokens (user_id, token_hash, revoked_at) VALUES (?, ?, ?)').run(
    userId,
    hashToken(rawToken),
    revoked ? '2024-01-01T00:00:00Z' : null,
  );
}

/**
 * @param {number} userId
 * @param {{ scheme?: string, plaintext?: string }} [opts]
 */
function insertAtlassianCredential(userId, opts = {}) {
  const { scheme = 'Token', plaintext = 'atlassian-pat-value' } = opts;
  db.prepare(
    "INSERT INTO atlassian_credentials (user_id, scheme, ciphertext, updated_at) VALUES (?, ?, ?, datetime('now'))",
  ).run(userId, scheme, encrypt(plaintext));
  return plaintext;
}

// --- 3.1: 204 valid Bearer / valid cookie; 401 absent/invalid/revoked/disabled ---

test('GET /verify returns 204 for a valid Bearer token', async () => {
  const userId = insertUser({ username: 'alice' });
  insertToken(userId, 'raw-token-alice');
  const res = await fetch(`${baseUrl}/verify`, {
    headers: { Authorization: 'Bearer raw-token-alice' },
  });
  assert.equal(res.status, 204);
  assert.equal(res.headers.get('x-gateway-user'), 'alice');
  assert.equal(res.headers.get('x-gateway-user-id'), String(userId));
});

test('GET /verify returns 204 for a valid session cookie', async () => {
  const userId = insertUser({ username: 'bob' });
  const token = createSessionToken({ uid: userId }, SESSION_SECRET);
  const res = await fetch(`${baseUrl}/verify`, {
    headers: { Cookie: `session=${token}` },
  });
  assert.equal(res.status, 204);
  assert.equal(res.headers.get('x-gateway-user'), 'bob');
  assert.equal(res.headers.get('x-gateway-user-id'), String(userId));
});

test('GET /verify returns 401 when no credential is present', async () => {
  const res = await fetch(`${baseUrl}/verify`);
  assert.equal(res.status, 401);
  assert.match(res.headers.get('www-authenticate') ?? '', /Bearer/);
});

test('GET /verify returns 401 for an invalid Bearer token', async () => {
  const userId = insertUser({ username: 'carol' });
  insertToken(userId, 'the-real-token');
  const res = await fetch(`${baseUrl}/verify`, {
    headers: { Authorization: 'Bearer a-wrong-token' },
  });
  assert.equal(res.status, 401);
});

test('GET /verify returns 401 for a revoked token', async () => {
  const userId = insertUser({ username: 'dave' });
  insertToken(userId, 'revoked-token', { revoked: true });
  const res = await fetch(`${baseUrl}/verify`, {
    headers: { Authorization: 'Bearer revoked-token' },
  });
  assert.equal(res.status, 401);
});

test('GET /verify returns 401 for a valid token belonging to a disabled user', async () => {
  const userId = insertUser({ username: 'erin', disabled: true });
  insertToken(userId, 'erins-token');
  const res = await fetch(`${baseUrl}/verify`, {
    headers: { Authorization: 'Bearer erins-token' },
  });
  assert.equal(res.status, 401);
});

test('GET /verify returns 401 for a session cookie referencing a disabled user', async () => {
  const userId = insertUser({ username: 'frank', disabled: true });
  const token = createSessionToken({ uid: userId }, SESSION_SECRET);
  const res = await fetch(`${baseUrl}/verify`, {
    headers: { Cookie: `session=${token}` },
  });
  assert.equal(res.status, 401);
});

test('GET /verify returns 401 for a tampered/invalid session cookie', async () => {
  const res = await fetch(`${baseUrl}/verify`, {
    headers: { Cookie: 'session=not-a-real-token.deadbeef' },
  });
  assert.equal(res.status, 401);
});

// --- 3.2: 302 to auth.{$DOMAIN}/login?next= when Accept: text/html ---

test('GET /verify redirects to the login page for browser (Accept: text/html) requests without credentials', async () => {
  const res = await fetch(`${baseUrl}/verify`, {
    headers: {
      Accept: 'text/html,application/xhtml+xml',
      'X-Forwarded-Uri': '/mcp/context7/some/page',
    },
    redirect: 'manual',
  });
  assert.equal(res.status, 302);
  const location = res.headers.get('location');
  assert.ok(location, 'expected a Location header');
  assert.match(location ?? '', new RegExp(`^https://auth\\.${DOMAIN}/login\\?next=`));
  assert.match(location ?? '', /mcp%2Fcontext7%2Fsome%2Fpage|mcp\/context7\/some\/page/);
});

test('GET /verify still returns plain 401 (not a redirect) when Accept does not indicate a browser', async () => {
  const res = await fetch(`${baseUrl}/verify`, {
    headers: { Accept: 'application/json' },
    redirect: 'manual',
  });
  assert.equal(res.status, 401);
});

// --- 3.3: 403 Atlassian route, no enrolled credential ---

test('GET /verify returns 403 for an authenticated user hitting an Atlassian route with no enrolled credential', async () => {
  const userId = insertUser({ username: 'grace' });
  insertToken(userId, 'graces-token');
  const res = await fetch(`${baseUrl}/verify`, {
    headers: {
      Authorization: 'Bearer graces-token',
      'X-Forwarded-Uri': '/mcp/atlassian/jira/search',
    },
  });
  assert.equal(res.status, 403);
  const body = await res.json();
  assert.match(JSON.stringify(body), /atlassian/i);
});

// --- 5.5: enrollUrl points at the credential panel, not the old POST-only route ---

test('GET /verify enrollUrl points at the /credentials panel, not the old POST-only /me/atlassian route', async () => {
  const userId = insertUser({ username: 'olivia' });
  insertToken(userId, 'olivias-token');
  const res = await fetch(`${baseUrl}/verify`, {
    headers: {
      Authorization: 'Bearer olivias-token',
      'X-Forwarded-Uri': '/mcp/atlassian/jira/search',
    },
  });
  assert.equal(res.status, 403);
  const body = await res.json();
  assert.equal(body.enrollUrl, `https://auth.${DOMAIN}/credentials`);
});

test('GET /verify returns 204 with X-Atlassian-Authorization for an authenticated user with an enrolled credential on an Atlassian route', async () => {
  const userId = insertUser({ username: 'heidi' });
  insertToken(userId, 'heidis-token');
  const plaintext = insertAtlassianCredential(userId, { scheme: 'Token' });
  const res = await fetch(`${baseUrl}/verify`, {
    headers: {
      Authorization: 'Bearer heidis-token',
      'X-Forwarded-Uri': '/mcp/atlassian/jira/search',
    },
  });
  assert.equal(res.status, 204);
  assert.equal(res.headers.get('x-atlassian-authorization'), `Token ${plaintext}`);
});

// --- 3.4: threat — header spoofing: /verify ignores client-supplied X-Gateway-User ---

test('threat: an unauthenticated request with a spoofed X-Gateway-User header is still rejected with 401', async () => {
  const res = await fetch(`${baseUrl}/verify`, {
    headers: { 'X-Gateway-User': 'attacker-controlled-identity' },
  });
  assert.equal(res.status, 401);
});

test('threat: an authenticated request with a spoofed X-Gateway-User header gets the real server-derived identity back, not the spoofed one', async () => {
  const userId = insertUser({ username: 'ivan' });
  insertToken(userId, 'ivans-token');
  const res = await fetch(`${baseUrl}/verify`, {
    headers: {
      Authorization: 'Bearer ivans-token',
      'X-Gateway-User': 'attacker-controlled-identity',
      'X-Gateway-User-Id': '999999',
    },
  });
  assert.equal(res.status, 204);
  assert.equal(res.headers.get('x-gateway-user'), 'ivan');
  assert.equal(res.headers.get('x-gateway-user-id'), String(userId));
});

// --- 3.5: threat — secret over-forward: X-Atlassian-Authorization omitted off-route ---

test('threat: X-Atlassian-Authorization is omitted on a non-Atlassian route even with an enrolled credential', async () => {
  const userId = insertUser({ username: 'judy' });
  insertToken(userId, 'judys-token');
  insertAtlassianCredential(userId);
  const res = await fetch(`${baseUrl}/verify`, {
    headers: {
      Authorization: 'Bearer judys-token',
      'X-Forwarded-Uri': '/mcp/context7/some/tool',
    },
  });
  assert.equal(res.status, 204);
  assert.equal(res.headers.get('x-atlassian-authorization'), null);
});

test('threat: a path-traversal X-Forwarded-Uri (/mcp/atlassian/../context7) does not leak X-Atlassian-Authorization', async () => {
  const userId = insertUser({ username: 'karl' });
  insertToken(userId, 'karls-token');
  insertAtlassianCredential(userId);
  const res = await fetch(`${baseUrl}/verify`, {
    headers: {
      Authorization: 'Bearer karls-token',
      'X-Forwarded-Uri': '/mcp/atlassian/../context7',
    },
  });
  assert.equal(res.status, 204);
  assert.equal(res.headers.get('x-atlassian-authorization'), null);
});

// --- correction: a missing AUTH_GATEWAY_SESSION_SECRET must not crash the process ---

test('GET /verify returns a graceful 500 (not a process crash) when AUTH_GATEWAY_SESSION_SECRET is unset', async () => {
  // Mirrors production's real main(), which calls createServer(db, {}) with
  // no sessionSecret in appConfig — resolveConfig() then falls through to
  // getSessionSecret(), which throws when the env var is unset.
  const original = process.env.AUTH_GATEWAY_SESSION_SECRET;
  delete process.env.AUTH_GATEWAY_SESSION_SECRET;
  const unconfiguredDb = openDb(':memory:');
  const unconfiguredServer = createServer(unconfiguredDb, { domain: DOMAIN });
  try {
    await new Promise((resolve) => unconfiguredServer.listen(0, () => resolve(undefined)));
    const address = /** @type {import('node:net').AddressInfo} */ (unconfiguredServer.address());
    const res = await fetch(`http://127.0.0.1:${address.port}/verify`);
    assert.equal(res.status, 500);
    const body = /** @type {any} */ (await res.json());
    assert.equal(body.error, 'internal_error');
  } finally {
    await new Promise((resolve) => unconfiguredServer.close(() => resolve(undefined)));
    unconfiguredDb.close();
    process.env.AUTH_GATEWAY_SESSION_SECRET = original;
  }
});

// --- 3.1: authenticateWithMethod reports HOW a request authenticated (D2) ---

test('authenticateWithMethod returns { user, method: "bearer" } for a valid Bearer token', () => {
  const userId = insertUser({ username: 'liam' });
  insertToken(userId, 'liams-token');
  const result = authenticateWithMethod(
    db,
    { authorization: 'Bearer liams-token' },
    SESSION_SECRET,
  );
  assert.ok(result);
  assert.equal(result.method, 'bearer');
  assert.equal(result.user.id, userId);
});

test('a valid Bearer token bumps that exact token\'s last_used_at (found live 2026-09-18: the profile page always showed "never", even for actively-used tokens — nothing ever wrote to this column)', () => {
  const userId = insertUser({ username: 'noah' });
  insertToken(userId, 'noahs-token');
  const before = /** @type {any} */ (
    db.prepare('SELECT last_used_at FROM tokens WHERE user_id = ?').get(userId)
  );
  assert.equal(before.last_used_at, null);

  authenticateWithMethod(db, { authorization: 'Bearer noahs-token' }, SESSION_SECRET);

  const after = /** @type {any} */ (
    db.prepare('SELECT last_used_at FROM tokens WHERE user_id = ?').get(userId)
  );
  assert.ok(after.last_used_at, 'last_used_at must be set after a successful Bearer auth');
});

test('a Bearer token with X-Engram-Subproject records that raw project value in last_used_project (cloud-first-identity-and-passwords)', () => {
  const userId = insertUser({ username: 'paul' });
  insertToken(userId, 'pauls-token');

  authenticateWithMethod(
    db,
    { authorization: 'Bearer pauls-token', 'x-engram-subproject': 'team-shared-project' },
    SESSION_SECRET,
  );

  const row = /** @type {any} */ (
    db.prepare('SELECT last_used_project FROM tokens WHERE user_id = ?').get(userId)
  );
  assert.equal(row.last_used_project, 'team-shared-project');
});

test('a Bearer token with no X-Engram-Subproject leaves last_used_project null (private default)', () => {
  const userId = insertUser({ username: 'quinn' });
  insertToken(userId, 'quinns-token');

  authenticateWithMethod(db, { authorization: 'Bearer quinns-token' }, SESSION_SECRET);

  const row = /** @type {any} */ (
    db.prepare('SELECT last_used_project FROM tokens WHERE user_id = ?').get(userId)
  );
  assert.equal(row.last_used_project, null);
});

test('an invalid/revoked Bearer token never touches last_used_at', () => {
  const userId = insertUser({ username: 'olivia' });
  insertToken(userId, 'olivias-token', { revoked: true });

  authenticateWithMethod(db, { authorization: 'Bearer olivias-token' }, SESSION_SECRET);

  const row = /** @type {any} */ (
    db.prepare('SELECT last_used_at FROM tokens WHERE user_id = ?').get(userId)
  );
  assert.equal(row.last_used_at, null);
});

test('authenticateWithMethod returns { user, method: "cookie" } for a valid session cookie', () => {
  const userId = insertUser({ username: 'maya' });
  const token = createSessionToken({ uid: userId }, SESSION_SECRET);
  const result = authenticateWithMethod(db, { cookie: `session=${token}` }, SESSION_SECRET);
  assert.ok(result);
  assert.equal(result.method, 'cookie');
  assert.equal(result.user.id, userId);
});

test('authenticateWithMethod returns null when no credential matches', () => {
  const result = authenticateWithMethod(db, {}, SESSION_SECRET);
  assert.equal(result, null);
});

test('authenticateWithMethod returns null when Bearer and cookie are both invalid', () => {
  const result = authenticateWithMethod(
    db,
    { authorization: 'Bearer not-a-real-token', cookie: 'session=not-a-real-token.deadbeef' },
    SESSION_SECRET,
  );
  assert.equal(result, null);
});

// --- D2/R4: a garbage Bearer header alongside a valid cookie must report
// method 'cookie', never 'bearer' — sniffing on header presence alone would
// let an attacker skip CSRF enforcement by attaching any non-matching
// Authorization header to a cookie-authenticated request. ---

test('threat: garbage Bearer header + valid cookie authenticates via cookie, not bearer (D2/R4)', () => {
  const userId = insertUser({ username: 'nina' });
  const token = createSessionToken({ uid: userId }, SESSION_SECRET);
  const result = authenticateWithMethod(
    db,
    { authorization: 'Bearer garbage-does-not-exist', cookie: `session=${token}` },
    SESSION_SECRET,
  );
  assert.ok(result);
  assert.equal(result.method, 'cookie');
  assert.equal(result.user.id, userId);
});
