import { sign, timingSafeCompare } from './session.js';

export const ADMIN_SESSION_COOKIE_NAME = '__Host-admin_session';

/** Admin sessions expire (unlike the regular session cookie, D4). */
export const ADMIN_SESSION_MAX_AGE_SECONDS = 28800; // 8h

/** Allowed future-dated clock skew, in seconds — mirrors csrf.js's constant. */
const ADMIN_SESSION_CLOCK_SKEW_SECONDS = 60;

/** Reads AUTH_GATEWAY_ADMIN_SESSION_SECRET per call (never cached), matching
 * getSessionSecret()'s rotation property.
 * @returns {string} */
export function getAdminSessionSecret() {
  const secret = process.env.AUTH_GATEWAY_ADMIN_SESSION_SECRET;
  if (!secret) {
    throw new Error('AUTH_GATEWAY_ADMIN_SESSION_SECRET is not set');
  }
  return secret;
}

/** Signed token carrying { uid, iat }. Unlike the regular session token,
 * this DOES expire (D4).
 * @param {number} uid
 * @param {string} adminSecret
 * @param {number} [now]
 * @returns {string} */
export function createAdminSessionToken(uid, adminSecret, now = Date.now()) {
  const payloadObj = { uid, iat: Math.floor(now / 1000) };
  const payload = Buffer.from(JSON.stringify(payloadObj), 'utf8').toString('base64url');
  return `${payload}.${sign(payload, adminSecret)}`;
}

/** Verifies a token from createAdminSessionToken(); null on any failure
 * (malformed, bad signature, invalid JSON, or age outside the window).
 * @param {string | undefined | null} token
 * @param {string} adminSecret
 * @param {number} [now]
 * @returns {{ uid: number } | null} */
export function verifyAdminSessionToken(token, adminSecret, now = Date.now()) {
  if (!token || typeof token !== 'string') {
    return null;
  }
  const separatorIndex = token.indexOf('.');
  if (separatorIndex === -1) {
    return null;
  }
  const payload = token.slice(0, separatorIndex);
  const signature = token.slice(separatorIndex + 1);
  const expected = sign(payload, adminSecret);
  if (!timingSafeCompare(signature, expected)) {
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null) {
    return null;
  }
  if (typeof parsed.uid !== 'number' || !Number.isFinite(parsed.iat)) {
    return null;
  }
  const age = Math.floor(now / 1000) - parsed.iat;
  if (age > ADMIN_SESSION_MAX_AGE_SECONDS || age < -ADMIN_SESSION_CLOCK_SKEW_SECONDS) {
    return null;
  }
  return { uid: parsed.uid };
}

/** Set-Cookie value for __Host-admin_session. D3: SameSite=Strict (not Lax
 * — auth./admin. are same-site siblings) and NO Domain= anywhere, so the
 * __Host- prefix's host-locking makes cookie shadowing impossible.
 * @param {string} token
 * @param {{ secure?: boolean }} [options]
 * @returns {string} */
export function serializeAdminSessionCookie(token, options = {}) {
  const { secure = true } = options;
  const attributes = [
    `${ADMIN_SESSION_COOKIE_NAME}=${token}`,
    'HttpOnly',
    'Path=/',
    'SameSite=Strict',
    `Max-Age=${ADMIN_SESSION_MAX_AGE_SECONDS}`,
  ];
  if (secure) {
    attributes.push('Secure');
  }
  return attributes.join('; ');
}

/** Clears the admin session cookie (Max-Age=0), still with no Domain=.
 * @param {{ secure?: boolean }} [options]
 * @returns {string} */
export function clearAdminSessionCookie(options = {}) {
  const { secure = true } = options;
  const attributes = [
    `${ADMIN_SESSION_COOKIE_NAME}=`,
    'HttpOnly',
    'Path=/',
    'SameSite=Strict',
    'Max-Age=0',
  ];
  if (secure) {
    attributes.push('Secure');
  }
  return attributes.join('; ');
}
