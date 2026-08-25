import crypto from 'node:crypto';

export const SESSION_COOKIE_NAME = 'session';

/**
 * Reads and validates AUTH_GATEWAY_SESSION_SECRET from the environment on
 * every call (never cached), mirroring crypto.js's getKey() so the secret
 * can be rotated without a process restart.
 * @returns {string}
 */
export function getSessionSecret() {
  const secret = process.env.AUTH_GATEWAY_SESSION_SECRET;
  if (!secret) {
    throw new Error('AUTH_GATEWAY_SESSION_SECRET is not set');
  }
  return secret;
}

/**
 * @param {string} payload base64url-encoded string
 * @param {string} secret
 * @returns {string} base64url HMAC-SHA256 signature
 */
function sign(payload, secret) {
  return crypto.createHmac('sha256', secret).update(payload).digest('base64url');
}

/**
 * Creates a signed session token carrying an arbitrary JSON-serializable
 * payload (e.g. { uid: <user id> }). The token has the shape
 * '<base64url-payload>.<base64url-hmac-signature>' and never expires — this
 * slice has no session TTL, matching the "long-lived tokens" requirement.
 * @param {Record<string, unknown>} data
 * @param {string} secret
 * @returns {string}
 */
export function createSessionToken(data, secret) {
  const payload = Buffer.from(JSON.stringify(data), 'utf8').toString('base64url');
  return `${payload}.${sign(payload, secret)}`;
}

/**
 * Verifies a session token produced by createSessionToken(). Returns the
 * decoded payload on success, or null on any failure (malformed shape, bad
 * signature, or invalid JSON) — callers must treat null as unauthenticated.
 * @param {string | undefined | null} token
 * @param {string} secret
 * @returns {Record<string, unknown> | null}
 */
export function verifySessionToken(token, secret) {
  if (!token || typeof token !== 'string') {
    return null;
  }
  const separatorIndex = token.indexOf('.');
  if (separatorIndex === -1) {
    return null;
  }
  const payload = token.slice(0, separatorIndex);
  const signature = token.slice(separatorIndex + 1);
  const expected = sign(payload, secret);
  const provided = Buffer.from(signature);
  const wanted = Buffer.from(expected);
  if (provided.length !== wanted.length || !crypto.timingSafeEqual(provided, wanted)) {
    return null;
  }
  try {
    return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

/**
 * Parses a raw 'Cookie' request header into a plain key/value map.
 * @param {string | undefined} cookieHeader
 * @returns {Record<string, string>}
 */
export function parseCookies(cookieHeader) {
  /** @type {Record<string, string>} */
  const result = {};
  if (!cookieHeader) {
    return result;
  }
  for (const part of cookieHeader.split(';')) {
    const separatorIndex = part.indexOf('=');
    if (separatorIndex === -1) {
      continue;
    }
    const key = part.slice(0, separatorIndex).trim();
    const value = part.slice(separatorIndex + 1).trim();
    if (!key) {
      continue;
    }
    try {
      result[key] = decodeURIComponent(value);
    } catch {
      result[key] = value;
    }
  }
  return result;
}

/**
 * Serializes a Set-Cookie header value for the HttpOnly session cookie.
 * @param {string} token
 * @param {{ secure?: boolean }} [options]
 * @returns {string}
 */
export function serializeSessionCookie(token, options = {}) {
  const { secure = true } = options;
  const attributes = [`${SESSION_COOKIE_NAME}=${token}`, 'HttpOnly', 'Path=/', 'SameSite=Lax'];
  if (secure) {
    attributes.push('Secure');
  }
  return attributes.join('; ');
}
