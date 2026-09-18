import { authenticateAdmin } from './admin-auth.js';
import {
  createAdminSessionToken,
  getAdminSessionSecret,
  serializeAdminSessionCookie,
  clearAdminSessionCookie,
} from './admin-session.js';
import { wantsHtml } from './verify.js';
import { verifyPassword } from './tokens.js';
import { PAGE_HEADERS, ADMIN_PAGE_HEADERS, CONSOLE_PAGE_HEADERS } from './html.js';
import { sanitizeNext } from './login-page.js';
import { renderAdminLoginPage } from './admin-login-page.js';
import {
  renderUsersPage,
  renderTokensPage,
  renderTokenIssuedPage,
  renderConsolePage,
  renderImportPage,
  renderImportedPage,
  renderProfilePage,
} from './admin-panel.js';
import { isAcceptableOrigin, verifyAdminCsrfToken, issueAdminCsrfToken } from './csrf.js';
import { createLoginThrottle } from './admin-throttle.js';
import { recordAudit } from './admin-audit.js';
import {
  listManagedUsers,
  listAdminAccounts,
  getAdminAccount,
  createManagedUser,
  setManagedUserDisabled,
  getManagedUser,
  listTokensForUser,
  issueToken as issueMcpToken,
  issueManagedToken,
  revokeManagedToken,
  regenerateToken,
  revokeProfileToken,
  importEngramCloudPrincipal,
  generateDefaultPassword,
  resetUserPassword,
  changeUserPassword,
} from './user-admin.js';
import {
  listUsers as listEngramCloudUsers,
  createUser as createEngramCloudUser,
  grantProject as grantEngramCloudProject,
  listGrants as listEngramCloudGrants,
  listTokens as listEngramCloudTokens,
  revokeCloudToken,
  issueToken as issueEngramCloudToken,
  loginDashboard as loginEngramCloudDashboard,
} from './engram-cloud-client.js';
import { encrypt, decrypt } from './crypto.js';

// Every subdomain the Caddyfile carves /admin/login* out of forward_auth
// for — keep in sync with the Caddyfile's admin-gated vhosts.
const ADMIN_LOGIN_HOSTS = ['monitor', 'engram-cloud'];

// One process-lifetime throttle (D12/A9): a container restart is the
// documented escape hatch for the single-admin lockout DoS this key choice
// accepts, so the map deliberately does NOT survive a restart.
const adminLoginThrottle = createLoginThrottle();

// bcrypt.hash('admin-login-constant-work-dummy', 12) — a fixed, non-secret
// hash compared against on every unknown-username attempt (D13) so
// verifyPassword always does the same bcrypt work whether or not the
// submitted username exists. Without this, an unknown username skips
// bcrypt entirely and returns measurably faster than a known one with a
// wrong password, letting an attacker enumerate valid usernames by timing.
const DUMMY_PASSWORD_HASH = '$2b$12$VW/Xq0GkGvmTqgW/Of4vGemqIfLdaPlVHjl3gN2AJLBwsjGDNb.OK';

// A local copy of app.js's readBody — deliberately not imported from there:
// app.js imports handleAdminRequest FROM this module, so importing anything
// back from app.js would make the two dispatchers circularly depend on each
// other, undermining the "never interleave" isolation this file's own
// original design comment calls out. Matches this file's existing local
// sendJson, which is copied for the same reason, not shared either.
const MAX_ADMIN_REQUEST_BODY_BYTES = 64 * 1024;

/**
 * @param {import('node:http').IncomingMessage} req
 * @returns {Promise<{ isForm: boolean, data: Record<string, any> }>}
 */
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    /** @type {Buffer[]} */
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_ADMIN_REQUEST_BODY_BYTES) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      const contentType = /** @type {string} */ (req.headers['content-type'] || '');
      const isForm = contentType.startsWith('application/x-www-form-urlencoded');
      if (isForm) {
        resolve({ isForm: true, data: Object.fromEntries(new URLSearchParams(raw)) });
        return;
      }
      if (!raw) {
        resolve({ isForm: false, data: {} });
        return;
      }
      try {
        resolve({ isForm: false, data: JSON.parse(raw) });
      } catch {
        reject(new Error('invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

/**
 * @param {import('node:http').ServerResponse} res
 * @param {number} status
 * @param {unknown} body
 */
function sendJson(res, status, body) {
  const json = JSON.stringify(body);
  res.setHeader('Content-Type', 'application/json');
  res.writeHead(status);
  res.end(json);
}

/**
 * Rejects a non-admin (member) session from an admin-only route
 * (admin-identity-unification Unit 3): a member's ONLY reachable surface
 * is `GET /admin/engram-cloud/sso` and the console's `view=cloud` tab —
 * Engram Cloud's own dashboard already enforces whatever that role
 * can/can't do internally, so no fine-grained permission system is built
 * here. `admin.is_admin === 1` is already guaranteed by `authenticateAdmin`
 * for anyone reaching this check (it means "can reach the admin-panel
 * login gate at all") — `role` is the finer admin/member distinction
 * WITHIN that.
 *
 * Dual-mode, same `wantsHtml` idiom as every other auth check in this
 * dispatcher (found live, 2026-09-17: a member landing here via a direct
 * navigation — a bookmark, a stale `next`, typing the URL — got a raw
 * JSON body instead of ending up back on the one surface they can use).
 * A JSON/API caller (the Phase 3 Cloud proxy's real consumer, Monitor's
 * own SPA) still gets a clean 403, never a redirect it can't follow
 * usefully.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {{ role: string }} admin
 * @returns {boolean} true if rejected — caller MUST return immediately
 */
function rejectNonAdminRole(req, res, admin) {
  if (admin.role !== 'admin') {
    if (wantsHtml(req.headers.accept)) {
      res.writeHead(302, { Location: '/admin/console?view=cloud' });
      res.end();
      return true;
    }
    sendJson(res, 403, { error: 'admin_role_required' });
    return true;
  }
  return false;
}

/**
 * GET /admin/verify — the Caddy forward_auth target for the admin.{$DOMAIN}
 * vhost (design.md Caddyfile section). authenticateAdmin is cookie-only
 * (A8), so a Bearer token never grants admin. Dual-mode failure response
 * mirrors GET /verify's wantsHtml() idiom, redirecting a browser to the
 * admin login page instead of returning a bare 401.
 *
 * The admin secret is read lazily here, never in app.js's resolveConfig()
 * (D9) — an unprovisioned AUTH_GATEWAY_ADMIN_SESSION_SECRET only 500s
 * /admin/*, it never takes the rest of the gateway down.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 */
function handleAdminVerify(req, res, db) {
  const adminSecret = getAdminSessionSecret();
  const user = authenticateAdmin(db, { cookie: req.headers.cookie }, adminSecret);
  if (!user) {
    if (wantsHtml(req.headers.accept)) {
      // Relative, not a separate admin.{$DOMAIN} host: the admin session
      // cookie is deliberately host-only (no Domain= — see
      // admin-session.js), so login must happen on the SAME host that
      // forward_auth is protecting (monitor.{$DOMAIN} today), never a
      // different subdomain the browser would never send that cookie to.
      res.writeHead(302, { Location: '/admin/login' });
      res.end();
      return;
    }
    sendJson(res, 401, { error: 'unauthenticated' });
    return;
  }
  res.writeHead(204);
  res.end();
}

/**
 * GET /admin/login — the zero-JS login form, unauthenticated. `next` comes
 * straight from the query string; renderAdminLoginPage sanitizes it.
 *
 * Deliberately PAGE_HEADERS, not ADMIN_PAGE_HEADERS — spec's Strict
 * Security Headers requirement lists exactly 3 headers for this page (CSP,
 * Cache-Control: no-store, X-Content-Type-Options: nosniff), never
 * Referrer-Policy. Confirmed live (2026-09-16): Referrer-Policy:
 * no-referrer on this page made Chrome send Origin: null on the login
 * form's top-level POST navigation — a known Chromium behavior tying a
 * navigation's Origin header to the page's referrer policy (fetch/XHR are
 * unaffected) — which isAcceptableOrigin then correctly rejects as an
 * opaque origin (A6/R5), 403ing every real browser login. No secret is
 * ever rendered on this page, so Referrer-Policy bought nothing here in
 * the first place; ADMIN_PAGE_HEADERS stays on the authenticated pages
 * below, where it protects real data in the URL/history.
 * @param {import('node:http').ServerResponse} res
 * @param {URL} url
 */
function handleGetAdminLogin(res, url) {
  const next = url.searchParams.get('next');
  res.writeHead(200, PAGE_HEADERS);
  res.end(renderAdminLoginPage({ next }));
}

/**
 * Re-renders the admin login page as a failure response — mirrors
 * app.js's sendLoginFailure exactly, against the admin page instead.
 * PAGE_HEADERS, not ADMIN_PAGE_HEADERS — same reasoning as
 * handleGetAdminLogin above.
 * @param {import('node:http').ServerResponse} res
 * @param {number} status
 * @param {{ next?: unknown, username?: unknown, error: string }} options
 */
function sendAdminLoginFailure(res, status, { next, username, error }) {
  res.writeHead(status, PAGE_HEADERS);
  res.end(renderAdminLoginPage({ next, error, username }));
}

/**
 * POST /admin/login — verifies username/password against `users` and
 * REQUIRES is_admin=1; a correct password for a non-admin user gets the
 * exact same generic failure as a wrong password (never distinguishing
 * "wrong password" from "not an admin" to an attacker). On success, issues
 * the already-implemented admin session cookie.
 *
 * Guard order (design.md Route Inventory): strict-per-host Origin -> body ->
 * throttle (needs the parsed username) -> constant-work verify (D13). Every
 * outcome — throttled, bad credentials, not-admin, or success — writes one
 * `admin_audit_log` row (design.md "Logged actions"); failures carry no
 * actor (the attempt was never authenticated) and record the *submitted*
 * username as `actorLabel` so the row stays readable.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string }} config
 */
async function handlePostAdminLogin(req, res, db, config) {
  // /admin/login is carved out of forward_auth on every admin-gated host
  // (Caddyfile) — currently monitor.{$DOMAIN} and engram-cloud.{$DOMAIN} —
  // so the real Origin can legitimately be any one of them, never the
  // apex. Accepted if it matches ANY of them (same reasoning as app.js's
  // handleLogin, generalized to more than one serving host).
  //
  // strict: true (D7) — deliberately diverges from credential-admin-panel's
  // reject-on-mismatch/allow-on-absent asymmetry (app.js's handleLogin uses
  // strict: false to keep curl/CLI login working). There is no CLI
  // admin-login use case — provisioning and rotation are bin/admin.js —
  // so the weaker rule buys nothing here and closes the
  // enctype="text/plain" login-CSRF vector (R5) outright rather than
  // partially. Every current browser sends Origin on a same-origin POST,
  // so this costs nothing for the real zero-JS login form.
  const originOk = ADMIN_LOGIN_HOSTS.some((subdomain) =>
    isAcceptableOrigin(
      { origin: req.headers.origin, referer: req.headers.referer },
      { domain: `${subdomain}.${config.domain}`, strict: true },
    ),
  );
  if (!originOk) {
    sendJson(res, 403, { error: 'csrf_origin_rejected' });
    return;
  }

  /** @type {{ isForm: boolean, data: Record<string, any> }} */
  let body;
  try {
    body = await readBody(req);
  } catch {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }

  const { isForm, data } = body;
  const { username, password, next } = data ?? {};

  if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
    if (isForm) {
      sendAdminLoginFailure(res, 400, { next, username, error: 'Invalid username or password.' });
      return;
    }
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }

  // `users.username` is UNIQUE COLLATE NOCASE (db.js), so the SELECT below
  // already treats 'Admin'/'admin'/'ADMIN' as the same row — the throttle
  // key must fold case the same way, or an attacker bypasses the lockout by
  // simply varying case on every 6th attempt.
  const throttleKey = username.toLowerCase();
  if (adminLoginThrottle.isLocked(throttleKey)) {
    recordAudit(db, {
      actorUserId: null,
      actorLabel: username,
      action: 'login',
      outcome: 'failure',
      detail: { reason: 'throttled' },
    });
    if (isForm) {
      sendAdminLoginFailure(res, 429, {
        next,
        username,
        error: 'Too many attempts. Try again later.',
      });
      return;
    }
    sendJson(res, 429, { error: 'too_many_attempts' });
    return;
  }

  const user = /** @type {any} */ (
    db.prepare('SELECT * FROM users WHERE username = ?').get(username)
  );
  // Constant-work (D13): verifyPassword always runs bcrypt, against the
  // real hash when the user exists or a fixed dummy hash when it doesn't —
  // an unknown username must take exactly as long to reject as a wrong
  // password for a real one, or the timing itself enumerates usernames.
  const validPassword = await verifyPassword(
    password,
    user ? user.password_hash : DUMMY_PASSWORD_HASH,
  );

  if (!user || !validPassword) {
    adminLoginThrottle.recordFailure(throttleKey);
    recordAudit(db, {
      actorUserId: null,
      actorLabel: username,
      action: 'login',
      outcome: 'failure',
      detail: { reason: 'bad_credentials' },
    });
    if (isForm) {
      sendAdminLoginFailure(res, 401, { next, username, error: 'Invalid username or password.' });
      return;
    }
    sendJson(res, 401, { error: 'invalid_credentials' });
    return;
  }

  if (user.disabled_at || user.is_admin !== 1) {
    adminLoginThrottle.recordFailure(throttleKey);
    recordAudit(db, {
      actorUserId: null,
      actorLabel: username,
      action: 'login',
      outcome: 'failure',
      detail: { reason: 'not_admin' },
    });
    if (isForm) {
      sendAdminLoginFailure(res, 401, { next, username, error: 'Invalid username or password.' });
      return;
    }
    sendJson(res, 401, { error: 'invalid_credentials' });
    return;
  }

  adminLoginThrottle.reset(throttleKey);
  recordAudit(db, {
    actorUserId: user.id,
    actorLabel: user.username,
    action: 'login',
    outcome: 'success',
  });

  const adminSecret = getAdminSessionSecret();
  const token = createAdminSessionToken(user.id, adminSecret);
  res.setHeader('Set-Cookie', serializeAdminSessionCookie(token));

  // admin-identity-unification D2: awaited, but never lets an Engram Cloud
  // failure (unreachable, create-user collision, ...) affect whether THIS
  // login succeeds — the session cookie above is already set regardless.
  // A no-op for every login after the admin's first (ensureEngramCloudLink
  // reads the existing row instead of provisioning again).
  try {
    await ensureEngramCloudLink(db, user);
  } catch {
    // Deliberately swallowed — see D2. GET /admin/engram-cloud/sso remains
    // the self-healing retry path if this attempt failed.
  }

  if (isForm) {
    // Role-aware fallback (Unit 3), not sanitizeNext's default
    // '/credentials': a member landing on /admin/users would just get
    // rejectNonAdminRole's 403 — the console's cloud view is the only
    // surface a member can actually use, so that is the fallback for
    // them instead. An admin's fallback is unchanged from before.
    const fallback = user.role === 'admin' ? '/admin/users' : '/admin/console?view=cloud';
    res.writeHead(302, { Location: sanitizeNext(next, fallback) });
    res.end();
    return;
  }

  sendJson(res, 200, { ok: true });
}

/**
 * POST /admin/logout — the full 5-step admin write guard (design.md Route
 * Inventory: "admin cookie | full 5-step"), then clears the admin session
 * cookie and audits the action. Unlike the other admin writes, there is no
 * DB mutation to combine with the audit insert in one transaction (D8) —
 * clearing a cookie is not a database row — so `recordAudit` runs standalone.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string }} config
 */
async function handlePostAdminLogout(req, res, db, config) {
  // 1. Authenticate — cookie only (authenticateAdmin never reads Bearer).
  const adminSecret = getAdminSessionSecret();
  const user = authenticateAdmin(db, { cookie: req.headers.cookie }, adminSecret);
  if (!user) {
    sendJson(res, 401, { error: 'unauthenticated' });
    return;
  }

  // 2. Origin check — strict (D7): an authenticated mutation has no CLI use
  // case, unlike the login form's caller-may-omit-Origin exception.
  const originOk = ADMIN_LOGIN_HOSTS.some((subdomain) =>
    isAcceptableOrigin(
      { origin: req.headers.origin, referer: req.headers.referer },
      { domain: `${subdomain}.${config.domain}`, strict: true },
    ),
  );
  if (!originOk) {
    sendJson(res, 403, { error: 'csrf_origin_rejected' });
    return;
  }

  // 3. Parse body (form 'csrf' field, or header-only for non-form callers).
  /** @type {{ isForm: boolean, data: Record<string, any> }} */
  let body;
  try {
    body = await readBody(req);
  } catch {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }
  const { isForm, data } = body;

  // 4. CSRF token — header first (DELETE-style callers), else the form field.
  const csrfToken = /** @type {string | undefined} */ (req.headers['x-csrf-token']) ?? data?.csrf;
  const csrfOk = verifyAdminCsrfToken(csrfToken, { uid: user.id, adminSecret });
  if (!csrfOk) {
    if (isForm) {
      res.writeHead(302, { Location: '/admin/login' });
      res.end();
      return;
    }
    sendJson(res, 403, { error: 'csrf_token_invalid' });
    return;
  }

  // 5. Mutate: clear the cookie, audit the logout.
  res.setHeader('Set-Cookie', clearAdminSessionCookie());
  recordAudit(db, {
    actorUserId: user.id,
    actorLabel: user.username,
    action: 'logout',
    outcome: 'success',
  });

  if (isForm) {
    res.writeHead(302, { Location: '/admin/login' });
    res.end();
    return;
  }
  sendJson(res, 200, { ok: true });
}

/**
 * GET /admin/users — lists every regular (is_admin=0) user with a
 * token-count summary, plus the create-user form. Unauthenticated dual-mode
 * response mirrors app.js's handleCredentialsPanel wantsHtml() idiom, one
 * level up: redirects back to THIS page via `next` once logged in.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {URL} url
 */
async function handleGetAdminUsers(req, res, db, url) {
  const adminSecret = getAdminSessionSecret();
  const admin = authenticateAdmin(db, { cookie: req.headers.cookie }, adminSecret);
  if (!admin) {
    if (wantsHtml(req.headers.accept)) {
      res.writeHead(302, { Location: '/admin/login?next=%2Fadmin%2Fusers' });
      res.end();
      return;
    }
    sendJson(res, 401, { error: 'unauthenticated' });
    return;
  }
  if (rejectNonAdminRole(req, res, admin)) {
    return;
  }

  const users = listManagedUsers(db);
  const adminAccounts = listAdminAccounts(db);
  const cloudLinksByUserId = new Map(
    /** @type {any[]} */ (db.prepare('SELECT user_id, principal_id FROM engram_cloud_credentials').all()).map(
      (row) => [row.user_id, row.principal_id],
    ),
  );
  // cloud-first-identity-and-passwords: best-effort (D2, swallowed) — a
  // Cloud outage must never break the Users page itself, just hide the
  // banner for this one view.
  let unlinkedCloudPrincipalCount = 0;
  try {
    unlinkedCloudPrincipalCount = (await listUnlinkedEngramCloudPrincipals(db)).length;
  } catch {
    // swallowed
  }
  const csrfToken = issueAdminCsrfToken(admin.id, adminSecret);
  const errorCode = url.searchParams.get('error');
  res.writeHead(200, ADMIN_PAGE_HEADERS);
  res.end(
    renderUsersPage({
      users,
      adminAccounts,
      cloudLinksByUserId,
      unlinkedCloudPrincipalCount,
      csrfToken,
      errorCode,
      viewer: { username: admin.username, role: admin.role },
    }),
  );
}

/**
 * POST /admin/users — the full 5-step admin write guard (design.md Route
 * Inventory), then creates a regular user via createManagedUser. `isAdmin`
 * is never read from the submitted body at all (design.md's Create a
 * Regular User requirement: "the flag MUST NOT be settable from this
 * form") — createManagedUser hardcodes is_admin=0 unconditionally, so there
 * is nothing here for a spoofed body field to override even if one existed.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string }} config
 */
async function handlePostAdminUsers(req, res, db, config) {
  // 1. Authenticate — cookie only.
  const adminSecret = getAdminSessionSecret();
  const admin = authenticateAdmin(db, { cookie: req.headers.cookie }, adminSecret);
  if (!admin) {
    sendJson(res, 401, { error: 'unauthenticated' });
    return;
  }
  if (rejectNonAdminRole(req, res, admin)) {
    return;
  }

  // 2. Origin check — strict (D7), same reasoning as POST /admin/logout:
  // an authenticated mutation has no CLI use case.
  const originOk = ADMIN_LOGIN_HOSTS.some((subdomain) =>
    isAcceptableOrigin(
      { origin: req.headers.origin, referer: req.headers.referer },
      { domain: `${subdomain}.${config.domain}`, strict: true },
    ),
  );
  if (!originOk) {
    sendJson(res, 403, { error: 'csrf_origin_rejected' });
    return;
  }

  // 3. Parse body.
  /** @type {{ isForm: boolean, data: Record<string, any> }} */
  let body;
  try {
    body = await readBody(req);
  } catch {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }
  const { isForm, data } = body;

  // 4. CSRF token — header first, else the form field.
  const csrfToken = /** @type {string | undefined} */ (req.headers['x-csrf-token']) ?? data?.csrf;
  const csrfOk = verifyAdminCsrfToken(csrfToken, { uid: admin.id, adminSecret });
  if (!csrfOk) {
    if (isForm) {
      res.writeHead(302, { Location: '/admin/users?error=csrf' });
      res.end();
      return;
    }
    sendJson(res, 403, { error: 'csrf_token_invalid' });
    return;
  }

  // 5. Validate, then create + audit atomically (createManagedUser, D8).
  const { username, password, passwordConfirm } = data ?? {};
  if (typeof username !== 'string' || !username || typeof password !== 'string' || !password) {
    if (isForm) {
      res.writeHead(302, { Location: '/admin/users?error=invalid' });
      res.end();
      return;
    }
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }

  // The zero-JS form always submits passwordConfirm (renderUsersPage);
  // a non-form/JSON caller has no such field to fill in and isn't asked
  // for one — only the form path enforces the match.
  if (isForm && password !== passwordConfirm) {
    res.writeHead(302, { Location: '/admin/users?error=mismatch' });
    res.end();
    return;
  }

  /** @type {{ id: number, username: string }} */
  let newUser;
  try {
    newUser = await createManagedUser(db, {
      username,
      password,
      actorUserId: admin.id,
      actorLabel: admin.username,
    });
  } catch {
    // The only realistic failure of this single INSERT is users.username's
    // UNIQUE COLLATE NOCASE constraint (D8: createManagedUser's transaction
    // means no audit row was written for it either).
    if (isForm) {
      res.writeHead(302, { Location: '/admin/users?error=duplicate' });
      res.end();
      return;
    }
    sendJson(res, 409, { error: 'duplicate_username' });
    return;
  }

  if (isForm) {
    res.writeHead(302, { Location: '/admin/users' });
    res.end();
    return;
  }
  sendJson(res, 200, { ok: true, id: newUser.id, username: newUser.username });
}

/**
 * POST /admin/users/disable and POST /admin/users/enable — the full 5-step
 * admin write guard, then setManagedUserDisabled with `disabled` fixed by
 * which route matched (design.md's Route Inventory: two separate routes,
 * not one route with a body flag — the disable/enable choice is never
 * itself an attacker-controlled input). The target user id ALWAYS comes
 * from the POST body's `userId` field, never a path parameter (spec.md's
 * Disable/Enable requirement).
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string }} config
 * @param {boolean} disabled
 */
async function handlePostAdminUserDisabled(req, res, db, config, disabled) {
  // 1. Authenticate — cookie only.
  const adminSecret = getAdminSessionSecret();
  const admin = authenticateAdmin(db, { cookie: req.headers.cookie }, adminSecret);
  if (!admin) {
    sendJson(res, 401, { error: 'unauthenticated' });
    return;
  }
  if (rejectNonAdminRole(req, res, admin)) {
    return;
  }

  // 2. Origin check — strict (D7), same reasoning as every other admin write.
  const originOk = ADMIN_LOGIN_HOSTS.some((subdomain) =>
    isAcceptableOrigin(
      { origin: req.headers.origin, referer: req.headers.referer },
      { domain: `${subdomain}.${config.domain}`, strict: true },
    ),
  );
  if (!originOk) {
    sendJson(res, 403, { error: 'csrf_origin_rejected' });
    return;
  }

  // 3. Parse body.
  /** @type {{ isForm: boolean, data: Record<string, any> }} */
  let body;
  try {
    body = await readBody(req);
  } catch {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }
  const { isForm, data } = body;

  // 4. CSRF token — header first, else the form field.
  const csrfToken = /** @type {string | undefined} */ (req.headers['x-csrf-token']) ?? data?.csrf;
  const csrfOk = verifyAdminCsrfToken(csrfToken, { uid: admin.id, adminSecret });
  if (!csrfOk) {
    if (isForm) {
      res.writeHead(302, { Location: '/admin/users?error=csrf' });
      res.end();
      return;
    }
    sendJson(res, 403, { error: 'csrf_token_invalid' });
    return;
  }

  // 5. Validate the target shape, then mutate + audit atomically
  // (setManagedUserDisabled, D8). userId is a form field, so it always
  // arrives as a string — Number() on a non-numeric or missing value
  // yields NaN, handled as invalid_request_body rather than reaching the
  // DB layer with a garbage bind parameter.
  const userId = Number(data?.userId);
  if (!Number.isInteger(userId) || userId <= 0) {
    if (isForm) {
      res.writeHead(302, { Location: '/admin/users?error=invalid' });
      res.end();
      return;
    }
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }

  const changed = setManagedUserDisabled(db, {
    userId,
    disabled,
    actorUserId: admin.id,
    actorLabel: admin.username,
  });
  if (!changed) {
    // Unknown id, or the admin's own row (A14 — setManagedUserDisabled's
    // `AND is_admin = 0` predicate makes that a no-op by construction, not
    // a special case this handler needs to detect itself).
    if (isForm) {
      res.writeHead(302, { Location: '/admin/users?error=not_found' });
      res.end();
      return;
    }
    sendJson(res, 404, { error: 'user_not_found' });
    return;
  }

  if (isForm) {
    res.writeHead(302, { Location: '/admin/users' });
    res.end();
    return;
  }
  sendJson(res, 200, { ok: true });
}

/**
 * GET /admin/users/tokens?userId=N — one target user's token list, plus
 * the issue-new-token form. `userId` MUST come from the query string, never
 * a path parameter (spec's View a User's Tokens requirement). Both the
 * shape check and the eligibility check (getManagedUser, is_admin=0) run
 * before any rendering, so an invalid or admin-owned id never reaches
 * listTokensForUser at all.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {URL} url
 */
function handleGetAdminTokens(req, res, db, url) {
  const adminSecret = getAdminSessionSecret();
  const admin = authenticateAdmin(db, { cookie: req.headers.cookie }, adminSecret);
  if (!admin) {
    if (wantsHtml(req.headers.accept)) {
      res.writeHead(302, {
        Location: `/admin/login?next=${encodeURIComponent(`${url.pathname}${url.search}`)}`,
      });
      res.end();
      return;
    }
    sendJson(res, 401, { error: 'unauthenticated' });
    return;
  }
  if (rejectNonAdminRole(req, res, admin)) {
    return;
  }

  const userId = Number(url.searchParams.get('userId'));
  if (!Number.isInteger(userId) || userId <= 0) {
    if (wantsHtml(req.headers.accept)) {
      res.writeHead(302, { Location: '/admin/users?error=invalid' });
      res.end();
      return;
    }
    sendJson(res, 400, { error: 'invalid_request' });
    return;
  }

  const targetUser = getManagedUser(db, userId);
  if (!targetUser) {
    if (wantsHtml(req.headers.accept)) {
      res.writeHead(302, { Location: '/admin/users?error=not_found' });
      res.end();
      return;
    }
    sendJson(res, 404, { error: 'user_not_found' });
    return;
  }

  const tokens = listTokensForUser(db, userId);
  const csrfToken = issueAdminCsrfToken(admin.id, adminSecret);
  const errorCode = url.searchParams.get('error');
  res.writeHead(200, ADMIN_PAGE_HEADERS);
  res.end(
    renderTokensPage({
      username: targetUser.username,
      userId,
      tokens,
      csrfToken,
      errorCode,
      viewer: { username: admin.username, role: admin.role },
    }),
  );
}

/**
 * POST /admin/tokens/issue — the full 5-step admin write guard, then
 * issueManagedToken. Unlike every other admin write so far, a successful
 * form submission renders the show-once page DIRECTLY (200), never a 302
 * (D10: "breaking POST/Redirect/GET" on purpose) — a redirect's Location
 * would have to carry the raw token in its query string to reach the next
 * GET, which leaks it into Caddy access logs, browser history, and Referer.
 * Every failure path still redirects to /admin/users, matching every other
 * write's error convention — only the success path is special-cased.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string }} config
 */
async function handlePostAdminTokensIssue(req, res, db, config) {
  // 1. Authenticate — cookie only.
  const adminSecret = getAdminSessionSecret();
  const admin = authenticateAdmin(db, { cookie: req.headers.cookie }, adminSecret);
  if (!admin) {
    sendJson(res, 401, { error: 'unauthenticated' });
    return;
  }
  if (rejectNonAdminRole(req, res, admin)) {
    return;
  }

  // 2. Origin check — strict (D7), same reasoning as every other admin write.
  const originOk = ADMIN_LOGIN_HOSTS.some((subdomain) =>
    isAcceptableOrigin(
      { origin: req.headers.origin, referer: req.headers.referer },
      { domain: `${subdomain}.${config.domain}`, strict: true },
    ),
  );
  if (!originOk) {
    sendJson(res, 403, { error: 'csrf_origin_rejected' });
    return;
  }

  // 3. Parse body.
  /** @type {{ isForm: boolean, data: Record<string, any> }} */
  let body;
  try {
    body = await readBody(req);
  } catch {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }
  const { isForm, data } = body;

  // 4. CSRF token — header first, else the form field.
  const csrfToken = /** @type {string | undefined} */ (req.headers['x-csrf-token']) ?? data?.csrf;
  const csrfOk = verifyAdminCsrfToken(csrfToken, { uid: admin.id, adminSecret });
  if (!csrfOk) {
    if (isForm) {
      res.writeHead(302, { Location: '/admin/users?error=csrf' });
      res.end();
      return;
    }
    sendJson(res, 403, { error: 'csrf_token_invalid' });
    return;
  }

  // 5. Validate, then issue + audit atomically (issueManagedToken, D8) —
  // eligibility (is_admin=0) is re-checked there too, not trusted from a
  // separate earlier lookup.
  const userId = Number(data?.userId);
  if (!Number.isInteger(userId) || userId <= 0) {
    if (isForm) {
      res.writeHead(302, { Location: '/admin/users?error=invalid' });
      res.end();
      return;
    }
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }
  const label = typeof data?.label === 'string' && data.label ? data.label : null;

  const result = issueManagedToken(db, {
    userId,
    label,
    actorUserId: admin.id,
    actorLabel: admin.username,
  });
  if (!result) {
    if (isForm) {
      res.writeHead(302, { Location: '/admin/users?error=not_found' });
      res.end();
      return;
    }
    sendJson(res, 404, { error: 'user_not_found' });
    return;
  }

  if (isForm) {
    res.writeHead(200, ADMIN_PAGE_HEADERS);
    res.end(
      renderTokenIssuedPage({ username: result.username, userId, rawToken: result.rawToken }),
    );
    return;
  }
  sendJson(res, 200, { ok: true, rawToken: result.rawToken, tokenId: result.tokenId });
}

/**
 * Steps 1-4 shared by POST /admin/tokens/revoke and POST
 * /admin/tokens/regenerate: authenticate, strict Origin (D7), parse body,
 * verify CSRF, then validate `userId` (redirects to /admin/users on
 * failure — no known subpage yet at this point) and resolve it to a real
 * eligible target via getManagedUser (redirects to /admin/users on failure
 * too — the target page needs a valid userId to build a URL for). Returns
 * `null` when the caller must stop (already responded); otherwise
 * `{ isForm, data, userId, targetUser }` for the caller to validate its own
 * remaining fields (tokenId) and mutate.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string }} config
 * @returns {Promise<{ admin: any, isForm: boolean, data: Record<string, any>, userId: number, targetUser: any } | null>}
 */
async function beginTokenWrite(req, res, db, config) {
  const adminSecret = getAdminSessionSecret();
  const admin = authenticateAdmin(db, { cookie: req.headers.cookie }, adminSecret);
  if (!admin) {
    sendJson(res, 401, { error: 'unauthenticated' });
    return null;
  }
  if (rejectNonAdminRole(req, res, admin)) {
    return null;
  }

  const originOk = ADMIN_LOGIN_HOSTS.some((subdomain) =>
    isAcceptableOrigin(
      { origin: req.headers.origin, referer: req.headers.referer },
      { domain: `${subdomain}.${config.domain}`, strict: true },
    ),
  );
  if (!originOk) {
    sendJson(res, 403, { error: 'csrf_origin_rejected' });
    return null;
  }

  /** @type {{ isForm: boolean, data: Record<string, any> }} */
  let body;
  try {
    body = await readBody(req);
  } catch {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return null;
  }
  const { isForm, data } = body;

  const csrfToken = /** @type {string | undefined} */ (req.headers['x-csrf-token']) ?? data?.csrf;
  const csrfOk = verifyAdminCsrfToken(csrfToken, { uid: admin.id, adminSecret });
  if (!csrfOk) {
    if (isForm) {
      res.writeHead(302, { Location: '/admin/users?error=csrf' });
      res.end();
      return null;
    }
    sendJson(res, 403, { error: 'csrf_token_invalid' });
    return null;
  }

  const userId = Number(data?.userId);
  if (!Number.isInteger(userId) || userId <= 0) {
    if (isForm) {
      res.writeHead(302, { Location: '/admin/users?error=invalid' });
      res.end();
      return null;
    }
    sendJson(res, 400, { error: 'invalid_request_body' });
    return null;
  }

  const targetUser = getManagedUser(db, userId);
  if (!targetUser) {
    if (isForm) {
      res.writeHead(302, { Location: '/admin/users?error=not_found' });
      res.end();
      return null;
    }
    sendJson(res, 404, { error: 'user_not_found' });
    return null;
  }

  return { admin, isForm, data, userId, targetUser };
}

/**
 * POST /admin/tokens/revoke — no secret to show (unlike issue/regenerate),
 * so every outcome redirects back to the target user's own token list
 * (`/admin/users/tokens?userId=N`) rather than the generic `/admin/users`
 * — once `userId` is known-valid (beginTokenWrite already confirmed it),
 * staying on that page is strictly more useful than bouncing to the list.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string }} config
 */
async function handlePostAdminTokensRevoke(req, res, db, config) {
  const begun = await beginTokenWrite(req, res, db, config);
  if (!begun) {
    return;
  }
  const { admin, isForm, data, userId } = begun;

  const tokenId = Number(data?.tokenId);
  if (!Number.isInteger(tokenId) || tokenId <= 0) {
    if (isForm) {
      res.writeHead(302, { Location: `/admin/users/tokens?userId=${userId}&error=invalid` });
      res.end();
      return;
    }
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }

  const revoked = revokeManagedToken(db, {
    tokenId,
    userId,
    actorUserId: admin.id,
    actorLabel: admin.username,
  });
  if (!revoked) {
    if (isForm) {
      res.writeHead(302, { Location: `/admin/users/tokens?userId=${userId}&error=not_found` });
      res.end();
      return;
    }
    sendJson(res, 404, { error: 'token_not_found' });
    return;
  }

  if (isForm) {
    res.writeHead(302, { Location: `/admin/users/tokens?userId=${userId}` });
    res.end();
    return;
  }
  sendJson(res, 200, { ok: true });
}

/**
 * POST /admin/tokens/regenerate — calls the EXISTING regenerateToken
 * (Unit 2), not a new wrapper: it already runs its own audited transaction
 * (D8), just predating this file's `*Managed*` naming convention. It
 * throws (rather than returning null/false) when the token isn't found,
 * isn't owned by userId, or is already revoked — caught here exactly like
 * handlePostAdminUsers already catches createManagedUser's duplicate-
 * username throw.
 *
 * Like POST /admin/tokens/issue, the SUCCESS path renders the show-once
 * page DIRECTLY (200), never a redirect (D10) — regenerate mints a new raw
 * token exactly like issue does, so it needs the identical treatment;
 * every failure path still redirects, matching revoke's convention above.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string }} config
 */
async function handlePostAdminTokensRegenerate(req, res, db, config) {
  const begun = await beginTokenWrite(req, res, db, config);
  if (!begun) {
    return;
  }
  const { admin, isForm, data, userId, targetUser } = begun;

  const tokenId = Number(data?.tokenId);
  if (!Number.isInteger(tokenId) || tokenId <= 0) {
    if (isForm) {
      res.writeHead(302, { Location: `/admin/users/tokens?userId=${userId}&error=invalid` });
      res.end();
      return;
    }
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }

  /** @type {{ rawToken: string, newTokenId: number }} */
  let result;
  try {
    result = regenerateToken(db, {
      tokenId,
      userId,
      actorUserId: admin.id,
      actorLabel: admin.username,
    });
  } catch {
    // Token not found, not owned by userId, or already revoked.
    if (isForm) {
      res.writeHead(302, { Location: `/admin/users/tokens?userId=${userId}&error=not_found` });
      res.end();
      return;
    }
    sendJson(res, 404, { error: 'token_not_found' });
    return;
  }

  if (isForm) {
    res.writeHead(200, ADMIN_PAGE_HEADERS);
    res.end(
      renderTokenIssuedPage({ username: targetUser.username, userId, rawToken: result.rawToken }),
    );
    return;
  }
  sendJson(res, 200, { ok: true, rawToken: result.rawToken, tokenId: result.newTokenId });
}

/**
 * Shared steps 1-4 for every /admin/engram-cloud/* write: authenticate,
 * strict Origin (D7), parse body, verify CSRF. These routes are a pure
 * JSON relay for Monitor's own SPA (Phase 4, external repo — see
 * design.md's Migration/Rollout) — never a zero-JS form — so the CSRF
 * token always arrives via the X-CSRF-Token header. GET
 * /admin/engram-cloud/users hands one out fresh on every response for the
 * SPA to reuse on subsequent writes, the JSON-response equivalent of every
 * other admin page's hidden csrf field.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string }} config
 * @returns {Promise<{ admin: any, data: Record<string, any> } | null>}
 */
async function beginEngramCloudWrite(req, res, db, config) {
  const adminSecret = getAdminSessionSecret();
  const admin = authenticateAdmin(db, { cookie: req.headers.cookie }, adminSecret);
  if (!admin) {
    sendJson(res, 401, { error: 'unauthenticated' });
    return null;
  }
  if (rejectNonAdminRole(req, res, admin)) {
    return null;
  }

  const originOk = ADMIN_LOGIN_HOSTS.some((subdomain) =>
    isAcceptableOrigin(
      { origin: req.headers.origin, referer: req.headers.referer },
      { domain: `${subdomain}.${config.domain}`, strict: true },
    ),
  );
  if (!originOk) {
    sendJson(res, 403, { error: 'csrf_origin_rejected' });
    return null;
  }

  /** @type {{ isForm: boolean, data: Record<string, any> }} */
  let body;
  try {
    body = await readBody(req);
  } catch {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return null;
  }

  const csrfToken =
    /** @type {string | undefined} */ (req.headers['x-csrf-token']) ?? body.data?.csrf;
  const csrfOk = verifyAdminCsrfToken(csrfToken, { uid: admin.id, adminSecret });
  if (!csrfOk) {
    sendJson(res, 403, { error: 'csrf_token_invalid' });
    return null;
  }

  return { admin, data: body.data };
}

/**
 * Calls into engram-cloud-client.js and relays its result — a 502 on any
 * failure. engram-cloud-client.js's own thrown errors never include the
 * admin token (verified by its own test suite), but this catch is also
 * the backstop against a raw stack trace or unexpected shape ever
 * reaching the response body (design.md's "Engram Cloud admin token
 * exposure" threat row).
 * @param {import('node:http').ServerResponse} res
 * @param {() => Promise<any>} fn
 * @param {number} [successStatus]
 */
async function relayEngramCloudCall(res, fn, successStatus = 200) {
  /** @type {any} */
  let result;
  try {
    result = await fn();
  } catch {
    sendJson(res, 502, { error: 'engram_cloud_unreachable' });
    return;
  }
  sendJson(res, successStatus, result);
}

/**
 * GET /admin/engram-cloud/users — relays engram-cloud's own managed-user
 * list.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 */
async function handleGetEngramCloudUsers(req, res, db) {
  const adminSecret = getAdminSessionSecret();
  const admin = authenticateAdmin(db, { cookie: req.headers.cookie }, adminSecret);
  if (!admin) {
    sendJson(res, 401, { error: 'unauthenticated' });
    return;
  }
  if (rejectNonAdminRole(req, res, admin)) {
    return;
  }

  /** @type {any} */
  let users;
  try {
    users = await listEngramCloudUsers();
  } catch {
    sendJson(res, 502, { error: 'engram_cloud_unreachable' });
    return;
  }

  const csrfToken = issueAdminCsrfToken(admin.id, adminSecret);
  sendJson(res, 200, { csrfToken, users });
}

/**
 * POST /admin/engram-cloud/users — relays a managed-user creation.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string }} config
 */
async function handlePostEngramCloudUsers(req, res, db, config) {
  const begun = await beginEngramCloudWrite(req, res, db, config);
  if (!begun) {
    return;
  }
  const { username, email, displayName, role } = begun.data ?? {};
  if (typeof username !== 'string' || !username) {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }
  await relayEngramCloudCall(
    res,
    () => createEngramCloudUser({ username, email, displayName, role }),
    201,
  );
}

/**
 * POST /admin/engram-cloud/users/:id/grants — relays a project grant.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string }} config
 * @param {string} principalId
 */
async function handlePostEngramCloudGrant(req, res, db, config, principalId) {
  const begun = await beginEngramCloudWrite(req, res, db, config);
  if (!begun) {
    return;
  }
  const { project } = begun.data ?? {};
  if (typeof project !== 'string' || !project) {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }
  await relayEngramCloudCall(res, () => grantEngramCloudProject({ principalId, project }), 201);
}

/**
 * POST /admin/engram-cloud/users/:id/tokens — relays a show-once token
 * issuance. No D10 direct-render treatment needed here (unlike this
 * service's own /admin/tokens/issue) — the caller is a JSON API client
 * (Monitor's SPA), never a browser form navigation, so there is no
 * redirect/Location leak vector to defend against.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string }} config
 * @param {string} principalId
 */
async function handlePostEngramCloudToken(req, res, db, config, principalId) {
  const begun = await beginEngramCloudWrite(req, res, db, config);
  if (!begun) {
    return;
  }
  const { name } = begun.data ?? {};
  await relayEngramCloudCall(
    res,
    () => issueEngramCloudToken({ principalId, name: typeof name === 'string' ? name : undefined }),
    201,
  );
}

/**
 * GET /admin/console?view=monitor|cloud (Phase 5) — the shared
 * header+sidebar+main shell. Auth pattern matches every other rendered
 * admin GET page (handleGetAdminUsers): redirect an unauthenticated
 * browser to the login page, 401 JSON for anything else.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {URL} url
 */
function handleGetAdminConsole(req, res, db, url) {
  const adminSecret = getAdminSessionSecret();
  const admin = authenticateAdmin(db, { cookie: req.headers.cookie }, adminSecret);
  if (!admin) {
    if (wantsHtml(req.headers.accept)) {
      res.writeHead(302, { Location: '/admin/login?next=%2Fadmin%2Fconsole' });
      res.end();
      return;
    }
    sendJson(res, 401, { error: 'unauthenticated' });
    return;
  }

  // A member has nowhere else useful to land (Unit 3) — force the cloud
  // view regardless of the query param, rather than 403ing a plain
  // navigational GET the nav itself would never even link to for them.
  const requestedView = url.searchParams.get('view');
  const view = admin.role === 'admin' ? requestedView : 'cloud';

  const csrfToken = issueAdminCsrfToken(admin.id, adminSecret);
  res.writeHead(200, CONSOLE_PAGE_HEADERS);
  res.end(renderConsolePage({ view, csrfToken, role: admin.role, username: admin.username }));
}

/**
 * Reads this admin's own stored Engram Cloud token (Phase 5 SSO), if any.
 * @param {import('better-sqlite3').Database} db
 * @param {number} userId
 * @returns {string | null}
 */
function getEngramCloudCredential(db, userId) {
  const row = /** @type {any} */ (
    db.prepare('SELECT ciphertext FROM engram_cloud_credentials WHERE user_id = ?').get(userId)
  );
  return row ? decrypt(row.ciphertext) : null;
}

/**
 * Stores this admin's own Engram Cloud token at rest, encrypted the same
 * way atlassian_credentials already is (crypto.js, reused as-is — see
 * design.md Phase 5).
 * @param {import('better-sqlite3').Database} db
 * @param {{ userId: number, principalId: string, token: string }} opts
 */
function saveEngramCloudCredential(db, { userId, principalId, token }) {
  db.prepare(
    `INSERT INTO engram_cloud_credentials (user_id, principal_id, ciphertext, updated_at)
     VALUES (?, ?, ?, datetime('now'))
     ON CONFLICT(user_id) DO UPDATE SET
       principal_id = excluded.principal_id,
       ciphertext = excluded.ciphertext,
       updated_at = excluded.updated_at`,
  ).run(userId, principalId, encrypt(token));
}

/**
 * Returns this admin's own Engram Cloud token, provisioning one (create
 * user + issue token + encrypted store) if this is their first time —
 * extracted from Phase 5's `GET /admin/engram-cloud/sso` (D1/D11: no
 * second implementation) so `handlePostAdminLogin` can reuse it exactly.
 * Never the shared `ENGRAM_CLOUD_ADMIN_TOKEN` (Phase 5's explicit identity
 * decision: every admin must appear as their own distinct Cloud principal).
 * Throws on any failure (network, create-user collision, ...) — callers
 * decide what "failure to link" means for their own route.
 * @param {import('better-sqlite3').Database} db
 * @param {{ id: number, username: string }} admin
 * @returns {Promise<string>}
 */
async function ensureEngramCloudLink(db, admin) {
  const existing = getEngramCloudCredential(db, admin.id);
  if (existing) {
    return existing;
  }
  const created = await createEngramCloudUser({ username: admin.username, role: admin.role });
  const issued = await issueEngramCloudToken({
    principalId: created.principal_id,
    name: 'console-sso',
  });
  saveEngramCloudCredential(db, {
    userId: admin.id,
    principalId: created.principal_id,
    token: issued.raw_token,
  });

  // engram-contributor-attribution (fix, 2026-09-18): Cloud's OWN
  // managed-token auth for POST /sync/mutations/push is deny-by-default —
  // a principal can only sync a project it's been explicitly granted,
  // even its own identity-named private default. Before this session's
  // per-identity-token change, every child spawned with the ONE shared
  // legacy ENGRAM_CLOUD_TOKEN, authorized via Cloud's separate
  // ENGRAM_CLOUD_ALLOWED_PROJECTS allowlist instead — nobody ever needed
  // a grant for their own space. Now that each identity authenticates
  // with its OWN managed token, it needs its own self-grant or its
  // private default silently stops syncing (found live: confirmed via a
  // direct Postgres check that cloud_mutations/cloud_chunks received
  // zero new rows for ANYONE since the per-identity-token deploy).
  // Best-effort (swallowed): a transient grant failure must never break
  // SSO login or the profile page, same reasoning as every other Cloud
  // call in this function's callers.
  try {
    await grantEngramCloudProject({ principalId: created.principal_id, project: admin.username });
  } catch {
    // swallowed
  }

  return issued.raw_token;
}

/**
 * GET /admin/engram-cloud/sso — per-admin auto-login into Engram Cloud's
 * own built-in dashboard (Phase 5). A plain navigational GET (no state
 * mutation of our own tables beyond lazily provisioning a Cloud identity
 * the first time), so no CSRF/Origin check — matches every other read-only
 * admin GET route.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 */
async function handleGetEngramCloudSso(req, res, db) {
  const adminSecret = getAdminSessionSecret();
  const admin = authenticateAdmin(db, { cookie: req.headers.cookie }, adminSecret);
  if (!admin) {
    sendJson(res, 401, { error: 'unauthenticated' });
    return;
  }

  try {
    const token = await ensureEngramCloudLink(db, admin);
    const { setCookie } = await loginEngramCloudDashboard(token);
    if (setCookie) {
      res.setHeader('Set-Cookie', setCookie);
    }
    res.writeHead(302, { Location: '/dashboard' });
    res.end();
  } catch {
    // Never the caught error's own message/stack (same discipline as
    // relayEngramCloudCall) — a create-user collision, an unreachable
    // upstream, and a dashboard-login rejection all surface identically.
    sendJson(res, 502, { error: 'engram_cloud_sso_failed' });
  }
}

/**
 * Every Engram Cloud principal absent from `engram_cloud_credentials`
 * (design.md D5: computed fresh via set difference, no cached flag) —
 * shared by `handleGetEngramCloudImport` (full list) and
 * `handleGetAdminUsers` (cloud-first-identity-and-passwords: just the
 * count, for its banner) so the two never diverge (D11).
 * @param {import('better-sqlite3').Database} db
 * @returns {Promise<any[]>}
 */
async function listUnlinkedEngramCloudPrincipals(db) {
  const cloudUsers = await listEngramCloudUsers();
  const linkedPrincipalIds = new Set(
    /** @type {any[]} */ (db.prepare('SELECT principal_id FROM engram_cloud_credentials').all()).map(
      (row) => row.principal_id,
    ),
  );
  return cloudUsers.filter((user) => !linkedPrincipalIds.has(user.principal_id));
}

/**
 * GET /admin/engram-cloud/import (admin-identity-unification) — lists
 * every Engram Cloud principal absent from `engram_cloud_credentials`
 * (design.md D5: computed fresh via set difference, no cached flag).
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {URL} url
 */
async function handleGetEngramCloudImport(req, res, db, url) {
  const adminSecret = getAdminSessionSecret();
  const admin = authenticateAdmin(db, { cookie: req.headers.cookie }, adminSecret);
  if (!admin) {
    if (wantsHtml(req.headers.accept)) {
      res.writeHead(302, { Location: '/admin/login?next=%2Fadmin%2Fengram-cloud%2Fimport' });
      res.end();
      return;
    }
    sendJson(res, 401, { error: 'unauthenticated' });
    return;
  }
  if (rejectNonAdminRole(req, res, admin)) {
    return;
  }

  /** @type {any[]} */
  let unlinked;
  try {
    unlinked = await listUnlinkedEngramCloudPrincipals(db);
  } catch {
    sendJson(res, 502, { error: 'engram_cloud_unreachable' });
    return;
  }

  const csrfToken = issueAdminCsrfToken(admin.id, adminSecret);
  res.writeHead(200, ADMIN_PAGE_HEADERS);
  res.end(
    renderImportPage({
      principals: unlinked,
      csrfToken,
      errorCode: url.searchParams.get('error'),
      viewer: { username: admin.username, role: admin.role },
    }),
  );
}

/**
 * POST /admin/engram-cloud/import (admin-identity-unification) — the full
 * 5-step admin write guard, then issues the chosen principal a fresh
 * Engram Cloud token and creates its local account
 * (`importEngramCloudPrincipal`, D4/D8) in one go.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string }} config
 */
async function handlePostEngramCloudImport(req, res, db, config) {
  // 1. Authenticate.
  const adminSecret = getAdminSessionSecret();
  const admin = authenticateAdmin(db, { cookie: req.headers.cookie }, adminSecret);
  if (!admin) {
    sendJson(res, 401, { error: 'unauthenticated' });
    return;
  }
  if (rejectNonAdminRole(req, res, admin)) {
    return;
  }

  // 2. Origin check — strict (D7), same reasoning as every other admin write.
  const originOk = ADMIN_LOGIN_HOSTS.some((subdomain) =>
    isAcceptableOrigin(
      { origin: req.headers.origin, referer: req.headers.referer },
      { domain: `${subdomain}.${config.domain}`, strict: true },
    ),
  );
  if (!originOk) {
    sendJson(res, 403, { error: 'csrf_origin_rejected' });
    return;
  }

  // 3. Parse body.
  /** @type {{ isForm: boolean, data: Record<string, any> }} */
  let body;
  try {
    body = await readBody(req);
  } catch {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }
  const { isForm, data } = body;

  // 4. CSRF token.
  const csrfToken = /** @type {string | undefined} */ (req.headers['x-csrf-token']) ?? data?.csrf;
  if (!verifyAdminCsrfToken(csrfToken, { uid: admin.id, adminSecret })) {
    if (isForm) {
      res.writeHead(302, { Location: '/admin/engram-cloud/import?error=csrf' });
      res.end();
      return;
    }
    sendJson(res, 403, { error: 'csrf_token_invalid' });
    return;
  }

  // 5. Validate, issue a token for the chosen principal, then create the
  // local account + link atomically (importEngramCloudPrincipal, D4/D8).
  // `role` is a hidden field rendered server-side from the already-fetched
  // unlinked-principal list (Unit 3) — same trust level as `principalId`
  // itself: the submitter is already an authenticated admin, not a new
  // trust boundary. Still allow-listed (A13), never passed through raw.
  //
  // cloud-first-identity-and-passwords: the password is now SERVER-
  // GENERATED (generateDefaultPassword, D11 — same generator as
  // reset-password), never admin-typed — the admin hands the shown-once
  // value to whoever needs it, same D10 pattern as everywhere else on
  // this page.
  const { principalId, username, role } = data ?? {};
  if (
    typeof principalId !== 'string' ||
    !principalId ||
    typeof username !== 'string' ||
    !username ||
    (role !== 'admin' && role !== 'member')
  ) {
    if (isForm) {
      res.writeHead(302, { Location: '/admin/engram-cloud/import?error=invalid' });
      res.end();
      return;
    }
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }
  const password = generateDefaultPassword();

  /** @type {any} */
  let issued;
  try {
    issued = await issueEngramCloudToken({ principalId, name: 'console-import' });
  } catch {
    if (isForm) {
      res.writeHead(302, { Location: '/admin/engram-cloud/import?error=unreachable' });
      res.end();
      return;
    }
    sendJson(res, 502, { error: 'engram_cloud_unreachable' });
    return;
  }

  try {
    await importEngramCloudPrincipal(db, {
      username,
      password,
      principalId,
      token: issued.raw_token,
      role,
      actorUserId: admin.id,
      actorLabel: admin.username,
    });
  } catch {
    // The only realistic failure here is users.username's UNIQUE
    // constraint — the issued token above is not revoked (design.md D4's
    // accepted trade-off: one harmless orphaned token on the Cloud side).
    if (isForm) {
      res.writeHead(302, { Location: '/admin/engram-cloud/import?error=duplicate' });
      res.end();
      return;
    }
    sendJson(res, 409, { error: 'duplicate_username' });
    return;
  }

  if (isForm) {
    res.writeHead(200, ADMIN_PAGE_HEADERS);
    res.end(renderImportedPage({ username, rawPassword: password }));
    return;
  }
  sendJson(res, 200, { ok: true, rawPassword: password });
}

/**
 * Resolves a `?userId=`/body `userId` into the profile target
 * (mcp-profile-page): absent → self, for anyone. Present → only an
 * admin may target a DIFFERENT admin-panel account; a member is
 * rejected outright, even if the id happens to be their own (keeps this
 * one rule simple — self is reached by omitting the param, never by
 * supplying it).
 * @param {import('node:http').ServerResponse} res
 * @param {{ id: number, role: string }} admin
 * @param {string | null} requestedUserId
 * @param {import('better-sqlite3').Database} db
 * @returns {{ id: number, username: string, role: string, disabled_at: string | null } | null} the target, or null if a response was already sent
 */
function resolveProfileTarget(res, admin, requestedUserId, db) {
  if (requestedUserId === null) {
    return admin;
  }
  if (admin.role !== 'admin') {
    sendJson(res, 403, { error: 'admin_role_required' });
    return null;
  }
  const found = getAdminAccount(db, Number(requestedUserId));
  if (!found) {
    sendJson(res, 404, { error: 'not_found' });
    return null;
  }
  return found;
}

/**
 * GET /admin/profile[?userId=N] (mcp-profile-page) — reachable by BOTH
 * admin and member (the only admin-app.js route besides the SSO route
 * itself with that property), unlike every other route this session.
 * Auto-issues an MCP Bearer token (`tokens` table, same one `/mcp/*`
 * routes already check via `authenticateWithMethod` — no new table) the
 * first time a target has none, same lazy pattern as
 * `ensureEngramCloudLink`. The raw value is only ever shown on the
 * request that just issued it (D10: `tokens.token_hash` never lets it be
 * retrieved again) — a later visit renders metadata + a Regenerate form
 * instead.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {URL} url
 * @param {{ domain: string }} config
 */
async function handleGetAdminProfile(req, res, db, url, config) {
  const adminSecret = getAdminSessionSecret();
  const admin = authenticateAdmin(db, { cookie: req.headers.cookie }, adminSecret);
  if (!admin) {
    if (wantsHtml(req.headers.accept)) {
      res.writeHead(302, { Location: '/admin/login?next=%2Fadmin%2Fprofile' });
      res.end();
      return;
    }
    sendJson(res, 401, { error: 'unauthenticated' });
    return;
  }

  const target = resolveProfileTarget(res, admin, url.searchParams.get('userId'), db);
  if (!target) {
    return;
  }

  await sendProfilePage(res, db, admin, target, config, null, url.searchParams.get('error'));
}

/**
 * Shared rendering for both GET /admin/profile and the success path of
 * POST /admin/profile/regenerate-token — D11, not a second implementation.
 * `forcedRawToken`, when given (the regenerate handler's freshly minted
 * value), is trusted as-is and shown directly; otherwise this auto-issues
 * a token the first time a target has none, same lazy pattern as
 * `ensureEngramCloudLink`. Either way it's a single 200 render, never a
 * redirect — a redirect would land on a later GET where the raw value no
 * longer exists anywhere (tokens are hashed at rest, D10), showing the
 * viewer nothing to copy. This is exactly the live bug reported
 * 2026-09-18: regenerate used to redirect and silently lose the new value.
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ id: number, username: string, role: string }} admin
 * @param {{ id: number, username: string, role: string }} target
 * @param {{ domain: string }} config
 * @param {string | null} [forcedRawToken]
 * @param {string | null} [errorCode]
 */
async function sendProfilePage(
  res,
  db,
  admin,
  target,
  config,
  forcedRawToken = null,
  errorCode = null,
  rawPassword = null,
) {
  // Self-heal the Cloud link exactly like the SSO route does (D2:
  // swallowed — a Cloud outage must never break this page, just show an
  // empty grants list).
  try {
    await ensureEngramCloudLink(db, target);
  } catch {
    // swallowed
  }

  const linkRow = /** @type {any} */ (
    db.prepare('SELECT principal_id FROM engram_cloud_credentials WHERE user_id = ?').get(target.id)
  );
  /** @type {string[]} */
  let subprojects = [];
  /** @type {any[]} */
  let grants = [];
  /** @type {any[] | null} */
  let cloudTokens = null;
  if (linkRow) {
    try {
      const result = await listEngramCloudGrants({ principalId: linkRow.principal_id });
      grants = Array.isArray(result) ? result : [];
      // engram-shared-projects: a grant's `project` field is an arbitrary
      // string, used VERBATIM as X-Engram-Subproject — no identity prefix
      // is stripped or assumed here (an earlier version of this code did,
      // based on the now-obsolete always-prefixed design; found live,
      // 2026-09-18, via a profile showing zero projects for a real grant).
      subprojects = grants.map((/** @type {any} */ g) => g.project);
    } catch {
      // swallowed — same reasoning as the Cloud-link self-heal above
    }
    try {
      const result = await listEngramCloudTokens({ principalId: linkRow.principal_id });
      // Defensive, not just optimistic: `res.writeHead(200, ...)` has
      // already run by the time this value reaches `renderProfilePage`
      // below, so a malformed (non-array) response here must NEVER throw
      // downstream — a throw after headers are sent leaves `res.end()`
      // uncalled, hanging the response forever instead of erroring
      // cleanly (found while adding this section: a test's default stub
      // response `{}`, not an array, reproduced exactly this hang).
      cloudTokens = Array.isArray(result) ? result : [];
    } catch {
      // swallowed — a Cloud outage must never break this page; an empty
      // list (not null) so the section still renders, just with nothing
      // to show, distinct from "no Cloud link at all" (null, hides it).
      cloudTokens = [];
    }
  }

  // cloud-first-identity-and-passwords: best-effort aggregation of every
  // project ANY linked principal is granted, for the Grant form's
  // <datalist> autocomplete — Cloud has no "list all projects" endpoint
  // (confirmed via deepwiki), so this is the closest available
  // approximation, not a claim of completeness. Swallowed per-principal
  // (D2) — one unreachable Cloud lookup must never break the whole list.
  const knownProjectsSet = new Set(subprojects);
  const otherLinkedPrincipals = /** @type {any[]} */ (
    db.prepare('SELECT principal_id FROM engram_cloud_credentials WHERE principal_id != ?').all(
      linkRow?.principal_id ?? '',
    )
  );
  for (const { principal_id: otherPrincipalId } of otherLinkedPrincipals) {
    try {
      const result = await listEngramCloudGrants({ principalId: otherPrincipalId });
      if (Array.isArray(result)) {
        for (const grant of result) {
          knownProjectsSet.add(grant.project);
        }
      }
    } catch {
      // swallowed
    }
  }
  const knownProjects = [...knownProjectsSet];

  let rawToken = forcedRawToken;
  let gatewayTokens = listTokensForUser(db, target.id);
  if (!rawToken && !gatewayTokens.some((/** @type {any} */ t) => !t.revoked_at)) {
    const issued = issueMcpToken(db, { userId: target.id, label: 'mcp-profile' });
    rawToken = issued.rawToken;
    gatewayTokens = listTokensForUser(db, target.id);
  }

  const csrfToken = issueAdminCsrfToken(admin.id, getAdminSessionSecret());
  res.writeHead(200, ADMIN_PAGE_HEADERS);
  res.end(
    renderProfilePage({
      target,
      viewer: { username: admin.username, role: admin.role, id: admin.id },
      subprojects,
      grants,
      knownProjects,
      rawToken,
      gatewayTokens,
      cloudTokens,
      rawPassword,
      mcpUrl: `https://${config.domain}/mcp/engram`,
      csrfToken,
      errorCode,
    }),
  );
}

/**
 * POST /admin/profile/regenerate-token (mcp-profile-page) — full 5-step
 * admin write guard, then `regenerateToken` (already existed, D8) scoped
 * to self for anyone, or a chosen `userId` for an admin only. Reachable
 * by both roles, same as the GET route above.
 *
 * The success path renders the profile page DIRECTLY via `sendProfilePage`
 * (200, form clients) or returns `rawToken` inline (JSON clients) — never a
 * redirect (D10, same convention as `handlePostAdminTokensRegenerate`).
 * Fixed 2026-09-18: this used to redirect to GET /admin/profile, which by
 * then already sees an active token and never shows a raw value again —
 * the regenerated token was minted but never actually shown to the user.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string }} config
 */
async function handlePostAdminProfileRegenerateToken(req, res, db, config) {
  const adminSecret = getAdminSessionSecret();
  const admin = authenticateAdmin(db, { cookie: req.headers.cookie }, adminSecret);
  if (!admin) {
    sendJson(res, 401, { error: 'unauthenticated' });
    return;
  }

  const originOk = ADMIN_LOGIN_HOSTS.some((subdomain) =>
    isAcceptableOrigin(
      { origin: req.headers.origin, referer: req.headers.referer },
      { domain: `${subdomain}.${config.domain}`, strict: true },
    ),
  );
  if (!originOk) {
    sendJson(res, 403, { error: 'csrf_origin_rejected' });
    return;
  }

  /** @type {{ isForm: boolean, data: Record<string, any> }} */
  let body;
  try {
    body = await readBody(req);
  } catch {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }
  const { isForm, data } = body;

  const csrfToken = /** @type {string | undefined} */ (req.headers['x-csrf-token']) ?? data?.csrf;
  if (!verifyAdminCsrfToken(csrfToken, { uid: admin.id, adminSecret })) {
    sendJson(res, 403, { error: 'csrf_token_invalid' });
    return;
  }

  const { tokenId, userId } = data ?? {};
  const target = resolveProfileTarget(res, admin, userId !== undefined ? String(userId) : null, db);
  if (!target) {
    return;
  }

  const redirectTarget =
    target.id === admin.id ? '/admin/profile' : `/admin/profile?userId=${target.id}`;

  /** @type {{ rawToken: string, newTokenId: number }} */
  let result;
  try {
    result = regenerateToken(db, {
      tokenId: Number(tokenId),
      userId: target.id,
      actorUserId: admin.id,
      actorLabel: admin.username,
    });
  } catch {
    if (isForm) {
      res.writeHead(302, { Location: `${redirectTarget}${target.id === admin.id ? '?' : '&'}error=not_found` });
      res.end();
      return;
    }
    sendJson(res, 404, { error: 'not_found' });
    return;
  }

  if (isForm) {
    await sendProfilePage(res, db, admin, target, config, result.rawToken);
    return;
  }
  sendJson(res, 200, { ok: true, rawToken: result.rawToken });
}

/**
 * POST /admin/profile/revoke-token (mcp-profile-page) — member self-service:
 * "quitar" the current token without issuing a replacement, leaving the
 * profile with no active token until the next visit auto-issues a fresh
 * one (same lazy pattern as the first-visit issue in GET /admin/profile).
 * Same write guard + `resolveProfileTarget` eligibility as regenerate above.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string }} config
 */
async function handlePostAdminProfileRevokeToken(req, res, db, config) {
  const adminSecret = getAdminSessionSecret();
  const admin = authenticateAdmin(db, { cookie: req.headers.cookie }, adminSecret);
  if (!admin) {
    sendJson(res, 401, { error: 'unauthenticated' });
    return;
  }

  const originOk = ADMIN_LOGIN_HOSTS.some((subdomain) =>
    isAcceptableOrigin(
      { origin: req.headers.origin, referer: req.headers.referer },
      { domain: `${subdomain}.${config.domain}`, strict: true },
    ),
  );
  if (!originOk) {
    sendJson(res, 403, { error: 'csrf_origin_rejected' });
    return;
  }

  /** @type {{ isForm: boolean, data: Record<string, any> }} */
  let body;
  try {
    body = await readBody(req);
  } catch {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }
  const { isForm, data } = body;

  const csrfToken = /** @type {string | undefined} */ (req.headers['x-csrf-token']) ?? data?.csrf;
  if (!verifyAdminCsrfToken(csrfToken, { uid: admin.id, adminSecret })) {
    sendJson(res, 403, { error: 'csrf_token_invalid' });
    return;
  }

  const { tokenId, userId } = data ?? {};
  const target = resolveProfileTarget(res, admin, userId !== undefined ? String(userId) : null, db);
  if (!target) {
    return;
  }

  const redirectTarget =
    target.id === admin.id ? '/admin/profile' : `/admin/profile?userId=${target.id}`;

  const revoked = revokeProfileToken(db, {
    tokenId: Number(tokenId),
    userId: target.id,
    actorUserId: admin.id,
    actorLabel: admin.username,
  });
  if (!revoked) {
    if (isForm) {
      res.writeHead(302, { Location: `${redirectTarget}${target.id === admin.id ? '?' : '&'}error=not_found` });
      res.end();
      return;
    }
    sendJson(res, 404, { error: 'not_found' });
    return;
  }

  if (isForm) {
    res.writeHead(302, { Location: redirectTarget });
    res.end();
    return;
  }
  sendJson(res, 200, { ok: true });
}

/**
 * POST /admin/profile/cloud-token/revoke (mcp-profile-page) — revokes one
 * of Engram Cloud's OWN tokens (its admin API, not auth-gateway's SQLite
 * `tokens` table — see `renderProfileCloudTokensSection`'s doc comment for
 * why these are shown as two separate sections). Same write guard and
 * `resolveProfileTarget` eligibility as the gateway-token routes above.
 *
 * There is no local row to update, so nothing here needs a `db.transaction`
 * (D8's "mutation + audit in one transaction" is about ONE atomic write —
 * this action's only atomic step, the audit row itself, is still wrapped
 * in a trivial transaction for consistency with every other write on this
 * page). The Cloud token id (an opaque string) goes into `detail.
 * cloudTokenId`, never `targetTokenId` (that column is this codebase's own
 * INTEGER token ids, a different id space entirely).
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string }} config
 */
async function handlePostAdminProfileCloudTokenRevoke(req, res, db, config) {
  const adminSecret = getAdminSessionSecret();
  const admin = authenticateAdmin(db, { cookie: req.headers.cookie }, adminSecret);
  if (!admin) {
    sendJson(res, 401, { error: 'unauthenticated' });
    return;
  }

  const originOk = ADMIN_LOGIN_HOSTS.some((subdomain) =>
    isAcceptableOrigin(
      { origin: req.headers.origin, referer: req.headers.referer },
      { domain: `${subdomain}.${config.domain}`, strict: true },
    ),
  );
  if (!originOk) {
    sendJson(res, 403, { error: 'csrf_origin_rejected' });
    return;
  }

  /** @type {{ isForm: boolean, data: Record<string, any> }} */
  let body;
  try {
    body = await readBody(req);
  } catch {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }
  const { isForm, data } = body;

  const csrfToken = /** @type {string | undefined} */ (req.headers['x-csrf-token']) ?? data?.csrf;
  if (!verifyAdminCsrfToken(csrfToken, { uid: admin.id, adminSecret })) {
    sendJson(res, 403, { error: 'csrf_token_invalid' });
    return;
  }

  const { tokenId, userId } = data ?? {};
  const target = resolveProfileTarget(res, admin, userId !== undefined ? String(userId) : null, db);
  if (!target) {
    return;
  }

  const redirectTarget =
    target.id === admin.id ? '/admin/profile' : `/admin/profile?userId=${target.id}`;

  const linkRow = /** @type {any} */ (
    db.prepare('SELECT principal_id FROM engram_cloud_credentials WHERE user_id = ?').get(target.id)
  );
  if (!linkRow || !tokenId) {
    if (isForm) {
      res.writeHead(302, { Location: `${redirectTarget}${target.id === admin.id ? '?' : '&'}error=not_found` });
      res.end();
      return;
    }
    sendJson(res, 404, { error: 'not_found' });
    return;
  }

  try {
    await revokeCloudToken({ tokenId: String(tokenId), reason: 'revoked via admin panel' });
  } catch {
    const runFailureAudit = db.transaction(() => {
      recordAudit(db, {
        actorUserId: admin.id,
        actorLabel: admin.username,
        action: 'cloud_token.revoke',
        outcome: 'failure',
        targetUserId: target.id,
        detail: { cloudTokenId: String(tokenId) },
      });
    });
    runFailureAudit();
    if (isForm) {
      res.writeHead(302, { Location: `${redirectTarget}${target.id === admin.id ? '?' : '&'}error=not_found` });
      res.end();
      return;
    }
    sendJson(res, 404, { error: 'not_found' });
    return;
  }

  const runSuccessAudit = db.transaction(() => {
    recordAudit(db, {
      actorUserId: admin.id,
      actorLabel: admin.username,
      action: 'cloud_token.revoke',
      outcome: 'success',
      targetUserId: target.id,
      detail: { cloudTokenId: String(tokenId) },
    });
  });
  runSuccessAudit();

  if (isForm) {
    res.writeHead(302, { Location: redirectTarget });
    res.end();
    return;
  }
  sendJson(res, 200, { ok: true });
}

/**
 * POST /admin/profile/grant-project (mcp-profile-page) — ADMIN-ONLY,
 * regardless of target: Cloud's own model is deny-by-default (user-quoted,
 * 2026-09-18: "New managed users are deny-by-default: they cannot sync any
 * project until an admin grants one explicitly"), so this is never
 * reachable by a member for any target, including their own profile —
 * unlike every other `/admin/profile/*` write above, which use
 * `resolveProfileTarget`'s self-for-anyone rule. `rejectNonAdminRole` is
 * checked FIRST, before `resolveProfileTarget` is ever called, since that
 * helper's own role gate only fires when a `userId` is actually present —
 * a member calling this with no `userId` (targeting themselves) would
 * otherwise slip through.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string }} config
 */
async function handlePostAdminProfileGrantProject(req, res, db, config) {
  const adminSecret = getAdminSessionSecret();
  const admin = authenticateAdmin(db, { cookie: req.headers.cookie }, adminSecret);
  if (!admin) {
    sendJson(res, 401, { error: 'unauthenticated' });
    return;
  }
  if (rejectNonAdminRole(req, res, admin)) {
    return;
  }

  const originOk = ADMIN_LOGIN_HOSTS.some((subdomain) =>
    isAcceptableOrigin(
      { origin: req.headers.origin, referer: req.headers.referer },
      { domain: `${subdomain}.${config.domain}`, strict: true },
    ),
  );
  if (!originOk) {
    sendJson(res, 403, { error: 'csrf_origin_rejected' });
    return;
  }

  /** @type {{ isForm: boolean, data: Record<string, any> }} */
  let body;
  try {
    body = await readBody(req);
  } catch {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }
  const { isForm, data } = body;

  const csrfToken = /** @type {string | undefined} */ (req.headers['x-csrf-token']) ?? data?.csrf;
  if (!verifyAdminCsrfToken(csrfToken, { uid: admin.id, adminSecret })) {
    sendJson(res, 403, { error: 'csrf_token_invalid' });
    return;
  }

  const { project, userId } = data ?? {};
  const target = resolveProfileTarget(res, admin, userId !== undefined ? String(userId) : null, db);
  if (!target) {
    return;
  }

  const redirectTarget =
    target.id === admin.id ? '/admin/profile' : `/admin/profile?userId=${target.id}`;

  if (typeof project !== 'string' || !project.trim()) {
    if (isForm) {
      res.writeHead(302, { Location: `${redirectTarget}${target.id === admin.id ? '?' : '&'}error=invalid_project` });
      res.end();
      return;
    }
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }

  // Self-heal exactly like every other profile-page write above — a
  // target with no Cloud link yet still gets one provisioned on demand.
  try {
    await ensureEngramCloudLink(db, target);
  } catch {
    // swallowed — the linkRow check right below is the real gate
  }
  const linkRow = /** @type {any} */ (
    db.prepare('SELECT principal_id FROM engram_cloud_credentials WHERE user_id = ?').get(target.id)
  );
  if (!linkRow) {
    if (isForm) {
      res.writeHead(302, { Location: `${redirectTarget}${target.id === admin.id ? '?' : '&'}error=not_found` });
      res.end();
      return;
    }
    sendJson(res, 404, { error: 'not_found' });
    return;
  }

  try {
    await grantEngramCloudProject({ principalId: linkRow.principal_id, project });
  } catch {
    const runFailureAudit = db.transaction(() => {
      recordAudit(db, {
        actorUserId: admin.id,
        actorLabel: admin.username,
        action: 'project.grant',
        outcome: 'failure',
        targetUserId: target.id,
        detail: { project },
      });
    });
    runFailureAudit();
    if (isForm) {
      res.writeHead(302, { Location: `${redirectTarget}${target.id === admin.id ? '?' : '&'}error=unreachable` });
      res.end();
      return;
    }
    sendJson(res, 502, { error: 'engram_cloud_unreachable' });
    return;
  }

  const runSuccessAudit = db.transaction(() => {
    recordAudit(db, {
      actorUserId: admin.id,
      actorLabel: admin.username,
      action: 'project.grant',
      outcome: 'success',
      targetUserId: target.id,
      detail: { project },
    });
  });
  runSuccessAudit();

  if (isForm) {
    res.writeHead(302, { Location: redirectTarget });
    res.end();
    return;
  }
  sendJson(res, 200, { ok: true });
}

/**
 * POST /admin/profile/reset-password (cloud-first-identity-and-passwords)
 * — admin-only (any target, including their own account) — resetting
 * someone ELSE's login must never be self-service, unlike change-password
 * below. Same `rejectNonAdminRole`-before-`resolveProfileTarget` shape as
 * `handlePostAdminProfileGrantProject` above, for the same reason: a
 * member must never reach this route at all, even targeting themselves
 * with no `userId`.
 *
 * Success renders the profile page DIRECTLY (200, D10 show-once) via
 * `sendProfilePage`'s `rawPassword` param — a redirect here would lose the
 * generated value exactly like the regenerate-token bug fixed earlier this
 * session; JSON clients get it inline instead.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string }} config
 */
async function handlePostAdminProfileResetPassword(req, res, db, config) {
  const adminSecret = getAdminSessionSecret();
  const admin = authenticateAdmin(db, { cookie: req.headers.cookie }, adminSecret);
  if (!admin) {
    sendJson(res, 401, { error: 'unauthenticated' });
    return;
  }
  if (rejectNonAdminRole(req, res, admin)) {
    return;
  }

  const originOk = ADMIN_LOGIN_HOSTS.some((subdomain) =>
    isAcceptableOrigin(
      { origin: req.headers.origin, referer: req.headers.referer },
      { domain: `${subdomain}.${config.domain}`, strict: true },
    ),
  );
  if (!originOk) {
    sendJson(res, 403, { error: 'csrf_origin_rejected' });
    return;
  }

  /** @type {{ isForm: boolean, data: Record<string, any> }} */
  let body;
  try {
    body = await readBody(req);
  } catch {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }
  const { isForm, data } = body;

  const csrfToken = /** @type {string | undefined} */ (req.headers['x-csrf-token']) ?? data?.csrf;
  if (!verifyAdminCsrfToken(csrfToken, { uid: admin.id, adminSecret })) {
    sendJson(res, 403, { error: 'csrf_token_invalid' });
    return;
  }

  const { userId } = data ?? {};
  const target = resolveProfileTarget(res, admin, userId !== undefined ? String(userId) : null, db);
  if (!target) {
    return;
  }

  const result = await resetUserPassword(db, {
    userId: target.id,
    actorUserId: admin.id,
    actorLabel: admin.username,
  });
  if (!result) {
    const redirectTarget =
      target.id === admin.id ? '/admin/profile' : `/admin/profile?userId=${target.id}`;
    if (isForm) {
      res.writeHead(302, { Location: `${redirectTarget}${target.id === admin.id ? '?' : '&'}error=not_found` });
      res.end();
      return;
    }
    sendJson(res, 404, { error: 'not_found' });
    return;
  }

  if (isForm) {
    await sendProfilePage(res, db, admin, target, config, null, null, result.rawPassword);
    return;
  }
  sendJson(res, 200, { ok: true, rawPassword: result.rawPassword });
}

/**
 * POST /admin/profile/change-password (cloud-first-identity-and-passwords)
 * — self-service, reachable by admin OR member, ALWAYS the caller's own
 * account. Deliberately does NOT use `resolveProfileTarget` — there is no
 * legitimate "change someone else's password" case here (that's
 * reset-password, admin-only, above), so a `userId` in the body is simply
 * rejected outright rather than silently ignored.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string }} config
 */
async function handlePostAdminProfileChangePassword(req, res, db, config) {
  const adminSecret = getAdminSessionSecret();
  const admin = authenticateAdmin(db, { cookie: req.headers.cookie }, adminSecret);
  if (!admin) {
    sendJson(res, 401, { error: 'unauthenticated' });
    return;
  }

  const originOk = ADMIN_LOGIN_HOSTS.some((subdomain) =>
    isAcceptableOrigin(
      { origin: req.headers.origin, referer: req.headers.referer },
      { domain: `${subdomain}.${config.domain}`, strict: true },
    ),
  );
  if (!originOk) {
    sendJson(res, 403, { error: 'csrf_origin_rejected' });
    return;
  }

  /** @type {{ isForm: boolean, data: Record<string, any> }} */
  let body;
  try {
    body = await readBody(req);
  } catch {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }
  const { isForm, data } = body;

  const csrfToken = /** @type {string | undefined} */ (req.headers['x-csrf-token']) ?? data?.csrf;
  if (!verifyAdminCsrfToken(csrfToken, { uid: admin.id, adminSecret })) {
    sendJson(res, 403, { error: 'csrf_token_invalid' });
    return;
  }

  if (data?.userId !== undefined) {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }

  const { password, passwordConfirm } = data ?? {};
  if (typeof password !== 'string' || !password) {
    if (isForm) {
      res.writeHead(302, { Location: '/admin/profile?error=invalid' });
      res.end();
      return;
    }
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }
  if (password !== passwordConfirm) {
    if (isForm) {
      res.writeHead(302, { Location: '/admin/profile?error=mismatch' });
      res.end();
      return;
    }
    sendJson(res, 400, { error: 'password_mismatch' });
    return;
  }

  await changeUserPassword(db, {
    userId: admin.id,
    password,
    actorUserId: admin.id,
    actorLabel: admin.username,
  });

  if (isForm) {
    res.writeHead(302, { Location: '/admin/profile' });
    res.end();
    return;
  }
  sendJson(res, 200, { ok: true });
}

/**
 * Dispatches every /admin/* request (D1) — a fully independent
 * authorization model from app.js's regular routes, deliberately kept in
 * its own module so the two auth models never interleave in one file.
 * Every route through Unit 11 is implemented; only Unit 12's Caddyfile
 * wiring remains dormant. Every other /admin/* path 404s.
 * The authorization boundary is always this path prefix, never
 * req.headers.host (D2) — nothing in this dispatcher or authenticateAdmin
 * ever reads Host/X-Forwarded-Host.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('better-sqlite3').Database} db
 * @param {{ domain: string }} config
 * @returns {Promise<boolean>} true when a route matched and was handled
 */
export async function handleAdminRequest(req, res, db, config) {
  const url = new URL(req.url ?? '/', 'http://internal');
  const { pathname } = url;

  if (req.method === 'GET' && pathname === '/admin/verify') {
    handleAdminVerify(req, res, db);
    return true;
  }

  if (req.method === 'GET' && pathname === '/admin/login') {
    handleGetAdminLogin(res, url);
    return true;
  }

  if (req.method === 'POST' && pathname === '/admin/login') {
    await handlePostAdminLogin(req, res, db, config);
    return true;
  }

  if (req.method === 'POST' && pathname === '/admin/logout') {
    await handlePostAdminLogout(req, res, db, config);
    return true;
  }

  if (req.method === 'GET' && pathname === '/admin/users') {
    await handleGetAdminUsers(req, res, db, url);
    return true;
  }

  if (req.method === 'POST' && pathname === '/admin/users') {
    await handlePostAdminUsers(req, res, db, config);
    return true;
  }

  if (req.method === 'POST' && pathname === '/admin/users/disable') {
    await handlePostAdminUserDisabled(req, res, db, config, true);
    return true;
  }

  if (req.method === 'POST' && pathname === '/admin/users/enable') {
    await handlePostAdminUserDisabled(req, res, db, config, false);
    return true;
  }

  if (req.method === 'GET' && pathname === '/admin/users/tokens') {
    handleGetAdminTokens(req, res, db, url);
    return true;
  }

  if (req.method === 'POST' && pathname === '/admin/tokens/issue') {
    await handlePostAdminTokensIssue(req, res, db, config);
    return true;
  }

  if (req.method === 'POST' && pathname === '/admin/tokens/revoke') {
    await handlePostAdminTokensRevoke(req, res, db, config);
    return true;
  }

  if (req.method === 'POST' && pathname === '/admin/tokens/regenerate') {
    await handlePostAdminTokensRegenerate(req, res, db, config);
    return true;
  }

  if (req.method === 'GET' && pathname === '/admin/console') {
    handleGetAdminConsole(req, res, db, url);
    return true;
  }

  if (req.method === 'GET' && pathname === '/admin/engram-cloud/import') {
    await handleGetEngramCloudImport(req, res, db, url);
    return true;
  }

  if (req.method === 'POST' && pathname === '/admin/engram-cloud/import') {
    await handlePostEngramCloudImport(req, res, db, config);
    return true;
  }

  if (req.method === 'GET' && pathname === '/admin/profile') {
    await handleGetAdminProfile(req, res, db, url, config);
    return true;
  }

  if (req.method === 'POST' && pathname === '/admin/profile/revoke-token') {
    await handlePostAdminProfileRevokeToken(req, res, db, config);
    return;
  }

  if (req.method === 'POST' && pathname === '/admin/profile/cloud-token/revoke') {
    await handlePostAdminProfileCloudTokenRevoke(req, res, db, config);
    return;
  }

  if (req.method === 'POST' && pathname === '/admin/profile/grant-project') {
    await handlePostAdminProfileGrantProject(req, res, db, config);
    return;
  }

  if (req.method === 'POST' && pathname === '/admin/profile/reset-password') {
    await handlePostAdminProfileResetPassword(req, res, db, config);
    return;
  }

  if (req.method === 'POST' && pathname === '/admin/profile/change-password') {
    await handlePostAdminProfileChangePassword(req, res, db, config);
    return;
  }

  if (req.method === 'POST' && pathname === '/admin/profile/regenerate-token') {
    await handlePostAdminProfileRegenerateToken(req, res, db, config);
    return true;
  }

  if (req.method === 'GET' && pathname === '/admin/engram-cloud/sso') {
    await handleGetEngramCloudSso(req, res, db);
    return true;
  }

  if (req.method === 'GET' && pathname === '/admin/engram-cloud/users') {
    await handleGetEngramCloudUsers(req, res, db);
    return true;
  }

  if (req.method === 'POST' && pathname === '/admin/engram-cloud/users') {
    await handlePostEngramCloudUsers(req, res, db, config);
    return true;
  }

  const engramCloudGrantMatch = pathname.match(/^\/admin\/engram-cloud\/users\/([^/]+)\/grants$/);
  if (req.method === 'POST' && engramCloudGrantMatch) {
    await handlePostEngramCloudGrant(
      req,
      res,
      db,
      config,
      decodeURIComponent(engramCloudGrantMatch[1]),
    );
    return true;
  }

  const engramCloudTokenMatch = pathname.match(/^\/admin\/engram-cloud\/users\/([^/]+)\/tokens$/);
  if (req.method === 'POST' && engramCloudTokenMatch) {
    await handlePostEngramCloudToken(
      req,
      res,
      db,
      config,
      decodeURIComponent(engramCloudTokenMatch[1]),
    );
    return true;
  }

  res.writeHead(404);
  res.end();
  return false;
}
