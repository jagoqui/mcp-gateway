// Engram hub login surface. Fully isolated from verify.js's Bearer/cookie
// user-session model AND from admin-app.js/admin-auth.js's admin-cookie
// model (D1-style precedent from admin-app.js: the repo's auth models must
// never interleave in one module) — this one authenticates against a single
// shared team-wide secret (ENGRAM_CLOUD_TOKEN), not a per-user row in the
// `users` table, so it cannot reuse authenticate()/authenticateAdmin().
//
// sign()/timingSafeCompare() below are deliberately a local, self-contained
// copy of the same HMAC-SHA256-over-base64url / length-checked-constant-time
// algorithm session.js's own primitives use — not an import from there. This
// module ships on top of the base gateway-foundation auth-gateway alone
// (session.js's exported sign/timingSafeCompare only exist starting further
// down this repo's chain), so importing them would make this PR depend on
// unrelated, not-yet-merged chains. Reuses AUTH_GATEWAY_SESSION_SECRET
// rather than provisioning a new secret env var — no new secret is required
// for this surface.

import crypto from 'node:crypto';
import { URLSearchParams } from 'node:url';
import { parseCookies } from './session.js';
import { wantsHtml } from './verify.js';

/**
 * @param {string} payload base64url-encoded string
 * @param {string} secret
 * @returns {string} base64url HMAC-SHA256 signature
 */
function sign(payload, secret) {
  return crypto.createHmac('sha256', secret).update(payload).digest('base64url');
}

/**
 * Constant-time string comparison, length-checked first (a length mismatch
 * is not itself compared in constant time, matching crypto.timingSafeEqual's
 * own requirement that both buffers have the same length — but no timing
 * signal about *content* ever leaks for equal-length inputs).
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function timingSafeCompare(a, b) {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

export const ENGRAM_HUB_COOKIE_NAME = 'engram_hub_session';

/** Matches admin-session.js's ADMIN_SESSION_MAX_AGE_SECONDS (8h). */
const ENGRAM_HUB_SESSION_MAX_AGE_SECONDS = 28800;

/** Allowed future-dated clock skew, in seconds — mirrors admin-session.js. */
const ENGRAM_HUB_CLOCK_SKEW_SECONDS = 60;

/** Same request-body cap as app.js's readBody (D4). */
const MAX_REQUEST_BODY_BYTES = 64 * 1024;

/**
 * Reads AUTH_GATEWAY_SESSION_SECRET per call (never cached), matching
 * getSessionSecret()/getAdminSessionSecret()'s rotation property.
 * @returns {string}
 */
function getEngramHubSessionSecret() {
  const secret = process.env.AUTH_GATEWAY_SESSION_SECRET;
  if (!secret) {
    throw new Error('AUTH_GATEWAY_SESSION_SECRET is not set');
  }
  return secret;
}

/**
 * Reads ENGRAM_CLOUD_TOKEN per call (never cached), matching this module's
 * other secret getters.
 * @returns {string}
 */
function getEngramCloudToken() {
  const token = process.env.ENGRAM_CLOUD_TOKEN;
  if (!token) {
    throw new Error('ENGRAM_CLOUD_TOKEN is not set');
  }
  return token;
}

/**
 * Signed token carrying only { iat } — there is no per-user identity here,
 * unlike createSessionToken/createAdminSessionToken which carry { uid }.
 * @param {string} secret
 * @param {number} [now]
 * @returns {string}
 */
function createEngramHubSessionToken(secret, now = Date.now()) {
  const payloadObj = { iat: Math.floor(now / 1000) };
  const payload = Buffer.from(JSON.stringify(payloadObj), 'utf8').toString('base64url');
  return `${payload}.${sign(payload, secret)}`;
}

/**
 * Verifies a token from createEngramHubSessionToken(); false on any failure
 * (malformed, bad signature, invalid JSON, or age outside the window) —
 * mirrors verifyAdminSessionToken's shape, minus the uid payload.
 * @param {string | undefined | null} token
 * @param {string} secret
 * @param {number} [now]
 * @returns {boolean}
 */
function verifyEngramHubSessionToken(token, secret, now = Date.now()) {
  if (!token || typeof token !== 'string') {
    return false;
  }
  const separatorIndex = token.indexOf('.');
  if (separatorIndex === -1) {
    return false;
  }
  const payload = token.slice(0, separatorIndex);
  const signature = token.slice(separatorIndex + 1);
  const expected = sign(payload, secret);
  if (!timingSafeCompare(signature, expected)) {
    return false;
  }
  /** @type {any} */
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    return false;
  }
  if (typeof parsed !== 'object' || parsed === null || !Number.isFinite(parsed.iat)) {
    return false;
  }
  const age = Math.floor(now / 1000) - parsed.iat;
  if (age > ENGRAM_HUB_SESSION_MAX_AGE_SECONDS || age < -ENGRAM_HUB_CLOCK_SKEW_SECONDS) {
    return false;
  }
  return true;
}

/**
 * Set-Cookie value for engram_hub_session. Unlike session.js/admin-session.js
 * (both host-only, no Domain=), this one carries a leading-dot Domain= on
 * purpose: it must be readable by BOTH engram-hub.{domain} (where it's set)
 * and engram-monitor.{domain} (where Caddy's forward_auth reads it back) —
 * two different subdomains sharing one cookie is exactly what a leading-dot
 * Domain= is for.
 * @param {string} token
 * @param {string} domain
 * @param {{ secure?: boolean }} [options]
 * @returns {string}
 */
export function serializeEngramHubSessionCookie(token, domain, options = {}) {
  const { secure = true } = options;
  const attributes = [
    `${ENGRAM_HUB_COOKIE_NAME}=${token}`,
    'HttpOnly',
    'Path=/',
    'SameSite=Lax',
    `Max-Age=${ENGRAM_HUB_SESSION_MAX_AGE_SECONDS}`,
    `Domain=.${domain}`,
  ];
  if (secure) {
    attributes.push('Secure');
  }
  return attributes.join('; ');
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
 * Structured, single-line audit log for engram-hub login attempts. Doesn't
 * go through recordAudit()/admin_audit_log: that table's actor/target
 * columns key off the `users` table (D8-style precedent, see
 * admin-audit.js), and this surface has no per-user identity to attach —
 * it's a single shared team-wide token, not an admin acting on a user row.
 * Its AUDIT_ACTIONS allow-list is scoped to admin-panel actions, so forcing
 * a fit here would misuse that allow-list rather than extend it.
 * @param {'success' | 'failure'} outcome
 */
function logEngramHubLoginAttempt(outcome) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), event: 'engram_hub.login', outcome }));
}

/**
 * Reads and parses a request body as either JSON or
 * application/x-www-form-urlencoded, capped at MAX_REQUEST_BODY_BYTES —
 * mirrors app.js's readBody (kept local rather than imported/exported: it's
 * not shared, and this module stays fully self-contained by design).
 * @param {import('node:http').IncomingMessage} req
 * @returns {Promise<Record<string, any>>}
 */
function readEngramVerifyBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    /** @type {Buffer[]} */
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_REQUEST_BODY_BYTES) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      const contentType = /** @type {string} */ (req.headers['content-type'] || '');
      if (contentType.startsWith('application/x-www-form-urlencoded')) {
        resolve(Object.fromEntries(new URLSearchParams(raw)));
        return;
      }
      if (!raw) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error('invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

/**
 * Authenticates a request via the engram_hub_session cookie OR a Bearer
 * token equal to ENGRAM_CLOUD_TOKEN — either is sufficient (mirrors verify.js's
 * authenticate() dual-check shape), but neither the regular `session` cookie
 * nor the admin `__Host-admin_session` cookie is ever read here.
 * @param {{ authorization?: string, cookie?: string }} headers
 * @returns {boolean}
 */
function authenticateEngramHub(headers) {
  if (headers.authorization && headers.authorization.startsWith('Bearer ')) {
    const bearerToken = headers.authorization.slice('Bearer '.length).trim();
    if (bearerToken && timingSafeCompare(bearerToken, getEngramCloudToken())) {
      return true;
    }
  }
  const cookies = parseCookies(headers.cookie);
  return verifyEngramHubSessionToken(cookies[ENGRAM_HUB_COOKIE_NAME], getEngramHubSessionSecret());
}

/**
 * GET /engram-verify — the Caddy forward_auth target for the
 * engram-monitor.{$DOMAIN} vhost. Valid engram_hub_session cookie or Bearer
 * ENGRAM_CLOUD_TOKEN -> 204. Otherwise: an HTML-accepting browser is
 * redirected to the engram-hub login page; every other caller gets a plain
 * 401 (same {"error":"unauthenticated"} shape as /verify and /admin/verify).
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {{ domain: string }} config
 */
function handleEngramVerifyGet(req, res, config) {
  const authenticated = authenticateEngramHub({
    authorization: req.headers.authorization,
    cookie: req.headers.cookie,
  });
  if (authenticated) {
    res.writeHead(204);
    res.end();
    return;
  }
  if (wantsHtml(req.headers.accept)) {
    res.writeHead(302, { Location: `https://engram-hub.${config.domain}/` });
    res.end();
    return;
  }
  sendJson(res, 401, { error: 'unauthenticated' });
}

/**
 * POST /engram-verify — engram-hub's login endpoint. Accepts { token } as
 * JSON or application/x-www-form-urlencoded, compares it against
 * ENGRAM_CLOUD_TOKEN with a constant-time comparison (timingSafeCompare,
 * the same session.js primitive verify.js/admin-session.js already use for
 * every signature check), and on a match issues the engram_hub_session
 * cookie. On mismatch, nothing is set and no session is issued.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {{ domain: string }} config
 */
async function handleEngramVerifyPost(req, res, config) {
  /** @type {Record<string, any>} */
  let data;
  try {
    data = await readEngramVerifyBody(req);
  } catch {
    sendJson(res, 400, { error: 'invalid_request_body' });
    return;
  }

  const { token } = data ?? {};
  if (typeof token !== 'string' || !token || !timingSafeCompare(token, getEngramCloudToken())) {
    logEngramHubLoginAttempt('failure');
    sendJson(res, 401, { error: 'invalid token' });
    return;
  }

  logEngramHubLoginAttempt('success');
  const sessionToken = createEngramHubSessionToken(getEngramHubSessionSecret());
  res.setHeader('Set-Cookie', serializeEngramHubSessionCookie(sessionToken, config.domain));
  res.writeHead(204);
  res.end();
}

/**
 * Dispatches every /engram-verify request — a fully independent surface
 * from app.js's regular routes and from /admin/*, deliberately isolated in
 * its own module for the same "never interleave" reason as admin-app.js.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {{ domain: string }} config
 * @returns {Promise<boolean>} true when a route matched and was handled
 */
export async function handleEngramVerifyRequest(req, res, config) {
  if (req.method === 'GET') {
    handleEngramVerifyGet(req, res, config);
    return true;
  }

  if (req.method === 'POST') {
    await handleEngramVerifyPost(req, res, config);
    return true;
  }

  res.writeHead(404);
  res.end();
  return false;
}
