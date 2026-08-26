import crypto from 'node:crypto';
import { sign, timingSafeCompare } from './session.js';

/** Domain-separation label for deriving the CSRF signing secret. A CSRF
 * token and a session cookie are never signed under the same key, so
 * neither can be replayed as the other (threat matrix R9). */
const CSRF_DOMAIN = 'mcp-gateway.csrf.v1';

/** Default token lifetime, in seconds (12h). */
export const DEFAULT_MAX_AGE_SECONDS = 43200;

/** Allowed future-dated clock skew, in seconds. */
export const CLOCK_SKEW_SECONDS = 60;

/**
 * HMAC-SHA256(sessionSecret, CSRF_DOMAIN) -> base64url. Domain separation:
 * a CSRF token can never be replayed as a session cookie, or vice versa.
 * @param {string} sessionSecret
 * @returns {string}
 */
export function deriveCsrfSecret(sessionSecret) {
  return sign(CSRF_DOMAIN, sessionSecret);
}

/**
 * Splits a token at the first '.' separator (matching verifySessionToken's
 * idiom). Returns null when the separator is absent.
 * @param {string} token
 * @returns {{ payloadB64: string, sig: string } | null}
 */
function splitToken(token) {
  const separatorIndex = token.indexOf('.');
  if (separatorIndex === -1) {
    return null;
  }
  return {
    payloadB64: token.slice(0, separatorIndex),
    sig: token.slice(separatorIndex + 1),
  };
}

/**
 * Issues a stateless HMAC CSRF token bound to a user id.
 * @param {number} uid
 * @param {string} sessionSecret
 * @param {number} [now]
 * @returns {string} '<payloadB64url>.<sigB64url>'
 */
export function issueCsrfToken(uid, sessionSecret, now = Date.now()) {
  const payloadObj = {
    uid,
    nonce: crypto.randomBytes(16).toString('base64url'),
    iat: Math.floor(now / 1000),
  };
  const payloadB64 = Buffer.from(JSON.stringify(payloadObj), 'utf8').toString('base64url');
  const sig = sign(payloadB64, deriveCsrfSecret(sessionSecret));
  return `${payloadB64}.${sig}`;
}

/**
 * Verifies a CSRF token. Never throws — every failure returns false.
 * Ordered per design: signature is checked BEFORE the payload is
 * JSON-parsed, so attacker-controlled bytes are never parsed before the
 * signature holds.
 * @param {string | undefined | null} token
 * @param {{ uid: number, sessionSecret: string, now?: number, maxAgeSeconds?: number }} options
 * @returns {boolean}
 */
export function verifyCsrfToken(token, options) {
  // 1. token is a non-empty string.
  if (!token || typeof token !== 'string') {
    return false;
  }
  if (!options || typeof options.sessionSecret !== 'string') {
    return false;
  }
  const { uid, sessionSecret, now = Date.now(), maxAgeSeconds = DEFAULT_MAX_AGE_SECONDS } = options;

  // 2. Split at the first '.'. No '.' => false.
  const split = splitToken(token);
  if (!split) {
    return false;
  }
  const { payloadB64, sig } = split;

  // 3. Recompute sig over the payload substring; timingSafeCompare.
  const expectedSig = sign(payloadB64, deriveCsrfSecret(sessionSecret));
  if (!timingSafeCompare(sig, expectedSig)) {
    return false;
  }

  // 4. Only now base64url-decode + JSON.parse the payload.
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  } catch {
    return false;
  }
  if (typeof parsed !== 'object' || parsed === null) {
    return false;
  }

  // 5. uid strict match — this is the session binding.
  if (typeof parsed.uid !== 'number' || parsed.uid !== uid) {
    return false;
  }

  // 6. nonce shape.
  if (typeof parsed.nonce !== 'string' || parsed.nonce.length === 0) {
    return false;
  }

  // 7. iat / age bounds.
  if (!Number.isFinite(parsed.iat)) {
    return false;
  }
  const age = Math.floor(now / 1000) - parsed.iat;
  if (age > maxAgeSeconds || age < -CLOCK_SKEW_SECONDS) {
    return false;
  }

  return true;
}

/**
 * Strict Origin/Referer check for CSRF defense-in-depth. Expected origin is
 * always composed from the server-side domain config, never req.headers.host
 * (D7 — the Host header is attacker-influencable).
 * @param {{ origin?: string, referer?: string }} headers
 * @param {{ domain: string, strict: boolean }} options
 * @returns {boolean}
 */
export function isAcceptableOrigin(headers, options) {
  if (!headers || !options || typeof options.domain !== 'string') {
    return false;
  }
  const { origin, referer } = headers;
  const { domain, strict } = options;
  const expected = `https://${domain}`;

  if (origin) {
    // A literal 'null' Origin (sandboxed iframe / file: / opaque origin)
    // never matches — it is treated as invalid, not absent.
    return origin.trim() === expected;
  }

  if (referer) {
    let url;
    try {
      url = new URL(referer);
    } catch {
      return false;
    }
    return `${url.protocol}//${url.host}` === expected;
  }

  return !strict;
}
