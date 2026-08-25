import crypto from 'node:crypto';
import bcrypt from 'bcrypt';

// bcrypt cost factor for human-chosen passwords, checked only at login time
// (never on the /verify hot path — see design.md's rationale for SHA-256
// gateway-token hashing instead of bcrypt on every proxied request).
const BCRYPT_ROUNDS = 12;

/**
 * Hashes a gateway Bearer token with SHA-256 for storage/lookup.
 * Gateway tokens are already 256-bit crypto.randomBytes output, so a fast
 * keyed-lookup digest is sufficient (no brute-force entropy concern) and
 * keeps /verify cheap since it runs on every proxied request.
 * @param {string} token
 * @returns {string} hex-encoded SHA-256 digest
 */
export function hashToken(token) {
  return crypto.createHash('sha256').update(String(token), 'utf8').digest('hex');
}

/**
 * Constant-time comparison of a presented token against a stored SHA-256
 * hex digest, preventing timing attacks on the comparison step.
 * @param {string} token
 * @param {string} storedHashHex
 * @returns {boolean}
 */
export function tokensMatch(token, storedHashHex) {
  const candidate = Buffer.from(hashToken(token), 'hex');
  const stored = Buffer.from(String(storedHashHex), 'hex');
  if (candidate.length !== stored.length) {
    return false;
  }
  return crypto.timingSafeEqual(candidate, stored);
}

/**
 * Hashes a human-chosen login password with bcrypt. Only runs at login
 * time, so bcrypt's deliberate slowness is acceptable here (unlike tokens).
 * @param {string} password
 * @returns {Promise<string>}
 */
export function hashPassword(password) {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

/**
 * Verifies a login password against its bcrypt hash.
 * @param {string} password
 * @param {string} hash
 * @returns {Promise<boolean>}
 */
export function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}
