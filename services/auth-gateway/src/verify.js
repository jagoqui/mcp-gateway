import { hashToken, tokensMatch } from './tokens.js';
import { decrypt } from './crypto.js';
import { parseCookies, verifySessionToken } from './session.js';

const ATLASSIAN_PREFIX = '/mcp/atlassian';

/**
 * Normalizes a request path the same way a browser/reverse proxy resolves
 * '.' and '..' segments, so a traversal-style path (e.g.
 * '/mcp/atlassian/../context7') cannot be misread as an Atlassian route by a
 * naive string-prefix check. This is defense-in-depth: per design.md, Caddy
 * itself normalizes paths before forward_auth ever sees them, so this is not
 * the only layer protecting the Atlassian credential.
 * @param {string} rawPath
 * @returns {string}
 */
export function normalizePath(rawPath) {
  const [pathname] = String(rawPath || '/').split('?');
  const segments = pathname.split('/');
  /** @type {string[]} */
  const resolved = [];
  for (const segment of segments) {
    if (segment === '' || segment === '.') {
      continue;
    }
    if (segment === '..') {
      resolved.pop();
      continue;
    }
    resolved.push(segment);
  }
  return `/${resolved.join('/')}`;
}

/**
 * @param {string} rawPath
 * @returns {boolean}
 */
export function isAtlassianRoute(rawPath) {
  const normalized = normalizePath(rawPath);
  return normalized === ATLASSIAN_PREFIX || normalized.startsWith(`${ATLASSIAN_PREFIX}/`);
}

/**
 * @param {import('better-sqlite3').Database} db
 * @param {number} userId
 * @returns {any}
 */
function loadUser(db, userId) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
}

/**
 * Authenticates a Bearer token against the tokens table. Never trusts
 * anything but the raw token string presented on this request.
 * @param {import('better-sqlite3').Database} db
 * @param {string | undefined} authorizationHeader
 * @returns {any} the authenticated user row, or null
 */
function authenticateBearer(db, authorizationHeader) {
  if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
    return null;
  }
  const token = authorizationHeader.slice('Bearer '.length).trim();
  if (!token) {
    return null;
  }
  const row = /** @type {any} */ (
    db.prepare('SELECT * FROM tokens WHERE token_hash = ?').get(hashToken(token))
  );
  if (!row || !tokensMatch(token, row.token_hash) || row.revoked_at) {
    return null;
  }
  const user = loadUser(db, row.user_id);
  if (!user || user.disabled_at) {
    return null;
  }
  return user;
}

/**
 * Authenticates a signed HttpOnly session cookie.
 * @param {import('better-sqlite3').Database} db
 * @param {string | undefined} cookieHeader
 * @param {string} sessionSecret
 * @returns {any} the authenticated user row, or null
 */
function authenticateCookie(db, cookieHeader, sessionSecret) {
  const cookies = parseCookies(cookieHeader);
  const payload = verifySessionToken(cookies.session, sessionSecret);
  if (!payload || typeof payload.uid !== 'number') {
    return null;
  }
  const user = loadUser(db, payload.uid);
  if (!user || user.disabled_at) {
    return null;
  }
  return user;
}

/**
 * Authenticates a request via Authorization: Bearer <token> OR a signed
 * session cookie — either form is equally sufficient per spec. Identity is
 * ALWAYS derived server-side from this lookup; client-supplied
 * X-Gateway-User / X-Gateway-User-Id / X-Atlassian-Authorization headers are
 * never read for this decision (threat: header spoofing).
 * @param {import('better-sqlite3').Database} db
 * @param {{ authorization?: string, cookie?: string }} headers
 * @param {string} sessionSecret
 * @returns {any} the authenticated user row, or null
 */
export function authenticate(db, headers, sessionSecret) {
  return (
    authenticateBearer(db, headers.authorization) ??
    authenticateCookie(db, headers.cookie, sessionSecret)
  );
}

/**
 * @param {string | undefined} acceptHeader
 * @returns {boolean}
 */
export function wantsHtml(acceptHeader) {
  return typeof acceptHeader === 'string' && acceptHeader.includes('text/html');
}

/**
 * Looks up a user's enrolled Atlassian credential and decrypts it into the
 * exact header value Caddy will inject as 'Authorization' upstream (per
 * design.md's atlassianAuthHeader() contract). The scheme/shape is verified
 * against mcp-atlassian's own docs in a later PR (task 4.7); this
 * '<scheme> <token>' composition is the documented placeholder until then.
 * @param {import('better-sqlite3').Database} db
 * @param {number} userId
 * @returns {string | null}
 */
export function atlassianAuthHeader(db, userId) {
  const row = /** @type {any} */ (
    db.prepare('SELECT scheme, ciphertext FROM atlassian_credentials WHERE user_id = ?').get(userId)
  );
  if (!row) {
    return null;
  }
  return `${row.scheme} ${decrypt(row.ciphertext)}`;
}

/**
 * Builds the full /verify response decision: status, headers, and an
 * optional JSON body. Kept as a pure function (no direct req/res coupling)
 * so it is unit-testable independent of the HTTP layer.
 * @param {import('better-sqlite3').Database} db
 * @param {{
 *   authorization?: string,
 *   cookie?: string,
 *   accept?: string,
 *   forwardedUri?: string,
 * }} headers
 * @param {{ domain: string, sessionSecret: string }} config
 * @returns {{ status: number, headers: Record<string, string>, body?: unknown }}
 */
export function decideVerify(db, headers, config) {
  const { domain, sessionSecret } = config;
  const originalPath = headers.forwardedUri || '/';
  const user = authenticate(db, headers, sessionSecret);

  if (!user) {
    if (wantsHtml(headers.accept)) {
      const next = encodeURIComponent(originalPath);
      return {
        status: 302,
        headers: { Location: `https://auth.${domain}/login?next=${next}` },
      };
    }
    return {
      status: 401,
      headers: { 'WWW-Authenticate': 'Bearer realm="mcp-gateway"' },
    };
  }

  /** @type {Record<string, string>} */
  const responseHeaders = {
    'X-Gateway-User': String(user.username),
    'X-Gateway-User-Id': String(user.id),
  };

  if (isAtlassianRoute(originalPath)) {
    const header = atlassianAuthHeader(db, user.id);
    if (!header) {
      return {
        status: 403,
        headers: {},
        body: {
          error: 'no_atlassian_credential',
          enrollUrl: `https://auth.${domain}/me/atlassian`,
        },
      };
    }
    responseHeaders['X-Atlassian-Authorization'] = header;
  }

  return { status: 204, headers: responseHeaders };
}
