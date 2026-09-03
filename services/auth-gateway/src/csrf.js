import crypto from 'node:crypto';
import { sign, timingSafeCompare } from './session.js';

/** Domain-separation label for the user CSRF secret — a CSRF token and a
 * session cookie are never signed under the same key (R9). */
const USER_CSRF_DOMAIN = 'mcp-gateway.csrf.v1';

/** Distinct label for the admin CSRF secret (D5): even with both secret env
 * vars set to the same value, a user-label token never verifies admin, or
 * vice versa (A5). */
const ADMIN_CSRF_DOMAIN = 'mcp-gateway.admin-csrf.v1';

/** Default token lifetime, in seconds (12h), for the user CSRF token. */
export const DEFAULT_MAX_AGE_SECONDS = 43200;

/** Default token lifetime, in seconds (1h), for the admin CSRF token (D6). */
export const DEFAULT_ADMIN_MAX_AGE_SECONDS = 3600;

/** Allowed future-dated clock skew, in seconds. */
export const CLOCK_SKEW_SECONDS = 60;

/**
 * HMAC-SHA256(secret, label) -> base64url. A token derived under one label
 * never verifies under a different label, even with an identical secret (D5).
 * @param {string} secret
 * @param {string} label
 * @returns {string}
 */
function deriveCsrfSecretWithLabel(secret, label) {
  return sign(label, secret);
}

/**
 * HMAC-SHA256(sessionSecret, USER_CSRF_DOMAIN) -> base64url (R9). Thin
 * wrapper, byte-identical to before label-parameterization (D5).
 * @param {string} sessionSecret
 * @returns {string}
 */
export function deriveCsrfSecret(sessionSecret) {
  return deriveCsrfSecretWithLabel(sessionSecret, USER_CSRF_DOMAIN);
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
 * Private core (D5): issues a token under an arbitrary label. Every
 * exported wrapper fixes its own label so a caller can never forget one.
 * @param {number} uid
 * @param {string} secret
 * @param {string} label
 * @param {number} [now]
 * @returns {string}
 */
function issueCsrfTokenWithLabel(uid, secret, label, now = Date.now()) {
  const payloadObj = {
    uid,
    nonce: crypto.randomBytes(16).toString('base64url'),
    iat: Math.floor(now / 1000),
  };
  const payloadB64 = Buffer.from(JSON.stringify(payloadObj), 'utf8').toString('base64url');
  const sig = sign(payloadB64, deriveCsrfSecretWithLabel(secret, label));
  return `${payloadB64}.${sig}`;
}

/**
 * Verifies a CSRF token derived under the given label. Never throws —
 * every failure returns false. Ordered per design: signature is checked
 * BEFORE the payload is JSON-parsed, so attacker-controlled bytes are
 * never parsed before the signature holds.
 * @param {string | undefined | null} token
 * @param {{ uid: number, secret: string, label: string, now?: number, maxAgeSeconds: number }} options
 * @returns {boolean}
 */
function verifyCsrfTokenWithLabel(token, options) {
  // 1. token is a non-empty string.
  if (!token || typeof token !== 'string') {
    return false;
  }
  if (!options || typeof options.secret !== 'string') {
    return false;
  }
  const { uid, secret, label, now = Date.now(), maxAgeSeconds } = options;

  // 2. Split at the first '.'. No '.' => false.
  const split = splitToken(token);
  if (!split) {
    return false;
  }
  const { payloadB64, sig } = split;

  // 3. Recompute sig over the payload substring; timingSafeCompare.
  const expectedSig = sign(payloadB64, deriveCsrfSecretWithLabel(secret, label));
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

/** Thin wrapper fixed to USER_CSRF_DOMAIN — byte-identical to pre-D5 (D5).
 * @param {number} uid
 * @param {string} sessionSecret
 * @param {number} [now]
 * @returns {string} */
export function issueCsrfToken(uid, sessionSecret, now = Date.now()) {
  return issueCsrfTokenWithLabel(uid, sessionSecret, USER_CSRF_DOMAIN, now);
}

/** Thin wrapper fixed to USER_CSRF_DOMAIN — byte-identical to pre-D5 (D5).
 * @param {string | undefined | null} token
 * @param {{ uid: number, sessionSecret: string, now?: number, maxAgeSeconds?: number }} options
 * @returns {boolean} */
export function verifyCsrfToken(token, options) {
  if (!options || typeof options.sessionSecret !== 'string') {
    return false;
  }
  const { uid, sessionSecret, now, maxAgeSeconds = DEFAULT_MAX_AGE_SECONDS } = options;
  return verifyCsrfTokenWithLabel(token, {
    uid,
    secret: sessionSecret,
    label: USER_CSRF_DOMAIN,
    now,
    maxAgeSeconds,
  });
}

/** Thin wrapper fixed to ADMIN_CSRF_DOMAIN, shorter default TTL (D6) — a
 * distinct label AND typically a distinct secret from the user token (A5).
 * @param {number} uid
 * @param {string} adminSecret
 * @param {number} [now]
 * @returns {string} */
export function issueAdminCsrfToken(uid, adminSecret, now = Date.now()) {
  return issueCsrfTokenWithLabel(uid, adminSecret, ADMIN_CSRF_DOMAIN, now);
}

/** Thin wrapper fixed to ADMIN_CSRF_DOMAIN, shorter default TTL (D6).
 * @param {string | undefined | null} token
 * @param {{ uid: number, adminSecret: string, now?: number, maxAgeSeconds?: number }} options
 * @returns {boolean} */
export function verifyAdminCsrfToken(token, options) {
  if (!options || typeof options.adminSecret !== 'string') {
    return false;
  }
  const { uid, adminSecret, now, maxAgeSeconds = DEFAULT_ADMIN_MAX_AGE_SECONDS } = options;
  return verifyCsrfTokenWithLabel(token, {
    uid,
    secret: adminSecret,
    label: ADMIN_CSRF_DOMAIN,
    now,
    maxAgeSeconds,
  });
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
