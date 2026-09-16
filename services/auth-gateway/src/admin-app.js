import { authenticateAdmin } from './admin-auth.js';
import {
  createAdminSessionToken,
  getAdminSessionSecret,
  serializeAdminSessionCookie,
  clearAdminSessionCookie,
} from './admin-session.js';
import { wantsHtml } from './verify.js';
import { verifyPassword } from './tokens.js';
import { PAGE_HEADERS, ADMIN_PAGE_HEADERS } from './html.js';
import { sanitizeNext } from './login-page.js';
import { renderAdminLoginPage } from './admin-login-page.js';
import { renderUsersPage, renderTokensPage, renderTokenIssuedPage } from './admin-panel.js';
import { isAcceptableOrigin, verifyAdminCsrfToken, issueAdminCsrfToken } from './csrf.js';
import { createLoginThrottle } from './admin-throttle.js';
import { recordAudit } from './admin-audit.js';
import {
  listManagedUsers,
  createManagedUser,
  setManagedUserDisabled,
  getManagedUser,
  listTokensForUser,
  issueManagedToken,
  revokeManagedToken,
  regenerateToken,
} from './user-admin.js';

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

  if (isForm) {
    // '/admin/users' fallback, not sanitizeNext's default '/credentials' —
    // must match the hidden `next` field renderAdminLoginPage rendered on
    // the form the admin just submitted, or a plain admin/login with no
    // explicit next lands them on the wrong panel after a successful login.
    res.writeHead(302, { Location: sanitizeNext(next, '/admin/users') });
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
function handleGetAdminUsers(req, res, db, url) {
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

  const users = listManagedUsers(db);
  const csrfToken = issueAdminCsrfToken(admin.id, adminSecret);
  const errorCode = url.searchParams.get('error');
  res.writeHead(200, ADMIN_PAGE_HEADERS);
  res.end(renderUsersPage({ users, csrfToken, errorCode }));
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
    renderTokensPage({ username: targetUser.username, userId, tokens, csrfToken, errorCode }),
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
    handleGetAdminUsers(req, res, db, url);
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

  res.writeHead(404);
  res.end();
  return false;
}
