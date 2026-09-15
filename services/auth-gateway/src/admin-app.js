import { authenticateAdmin } from './admin-auth.js';
import {
  createAdminSessionToken,
  getAdminSessionSecret,
  serializeAdminSessionCookie,
} from './admin-session.js';
import { wantsHtml } from './verify.js';
import { verifyPassword } from './tokens.js';
import { PAGE_HEADERS } from './html.js';
import { sanitizeNext } from './login-page.js';
import { renderAdminLoginPage } from './admin-login-page.js';
import { isAcceptableOrigin } from './csrf.js';

// Every subdomain the Caddyfile carves /admin/login* out of forward_auth
// for — keep in sync with the Caddyfile's admin-gated vhosts.
const ADMIN_LOGIN_HOSTS = ['monitor', 'engram-cloud'];

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
 * @param {{ domain: string }} config
 */
function handleAdminVerify(req, res, db, config) {
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
  const originOk = ADMIN_LOGIN_HOSTS.some((subdomain) =>
    isAcceptableOrigin(
      { origin: req.headers.origin, referer: req.headers.referer },
      { domain: `${subdomain}.${config.domain}`, strict: false },
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

  const user = /** @type {any} */ (
    db.prepare('SELECT * FROM users WHERE username = ?').get(username)
  );
  const validPassword = user ? await verifyPassword(password, user.password_hash) : false;

  if (!user || user.disabled_at || user.is_admin !== 1 || !validPassword) {
    if (isForm) {
      sendAdminLoginFailure(res, 401, { next, username, error: 'Invalid username or password.' });
      return;
    }
    sendJson(res, 401, { error: 'invalid_credentials' });
    return;
  }

  const adminSecret = getAdminSessionSecret();
  const token = createAdminSessionToken(user.id, adminSecret);
  res.setHeader('Set-Cookie', serializeAdminSessionCookie(token));

  if (isForm) {
    res.writeHead(302, { Location: sanitizeNext(next) });
    res.end();
    return;
  }

  sendJson(res, 200, { ok: true });
}

/**
 * Dispatches every /admin/* request (D1) — a fully independent
 * authorization model from app.js's regular routes, deliberately kept in
 * its own module so the two auth models never interleave in one file. Only
 * GET /admin/verify is implemented in this unit; every other /admin/* path
 * 404s until its own unit lands (Phases 6-11). The authorization boundary
 * is always this path prefix, never req.headers.host (D2) — nothing in
 * this dispatcher or authenticateAdmin ever reads Host/X-Forwarded-Host.
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
    handleAdminVerify(req, res, db, config);
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

  res.writeHead(404);
  res.end();
  return false;
}
