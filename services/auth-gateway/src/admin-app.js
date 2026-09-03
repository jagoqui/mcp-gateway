import { authenticateAdmin } from './admin-auth.js';
import { getAdminSessionSecret } from './admin-session.js';
import { wantsHtml } from './verify.js';

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
      res.writeHead(302, { Location: `https://admin.${config.domain}/login` });
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

  res.writeHead(404);
  res.end();
  return false;
}
