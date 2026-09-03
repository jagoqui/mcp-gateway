import { parseCookies } from './session.js';
import { ADMIN_SESSION_COOKIE_NAME, verifyAdminSessionToken } from './admin-session.js';

/**
 * Authenticates a request via the __Host-admin_session cookie ONLY (D2/A8).
 * The Authorization header is never read here — a Bearer token, valid or
 * not, can never grant admin access, because the admin panel is a fully
 * independent identity from the regular session/Bearer surface.
 *
 * is_admin and disabled_at are re-checked LIVE against the database on every
 * call, never trusted from the token payload — the token carries nothing
 * but { uid, iat } (D4), so an admin demoted or disabled after their token
 * was issued loses access on their very next request.
 * @param {import('better-sqlite3').Database} db
 * @param {{ cookie?: string }} headers
 * @param {string} adminSecret
 * @param {number} [now]
 * @returns {any} the authenticated admin user row, or null
 */
export function authenticateAdmin(db, headers, adminSecret, now = Date.now()) {
  const cookies = parseCookies(headers?.cookie);
  const payload = verifyAdminSessionToken(cookies[ADMIN_SESSION_COOKIE_NAME], adminSecret, now);
  if (!payload || typeof payload.uid !== 'number') {
    return null;
  }
  const user = /** @type {any} */ (
    db.prepare('SELECT * FROM users WHERE id = ?').get(payload.uid)
  );
  if (!user || user.is_admin !== 1 || user.disabled_at) {
    return null;
  }
  return user;
}
