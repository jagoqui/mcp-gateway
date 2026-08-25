import crypto from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const KEY_LENGTH = 32;

/**
 * Reads and validates ATLASSIAN_ENC_KEY from the environment on every call
 * (never cached), so callers can rotate the key without a process restart.
 * @returns {Buffer}
 */
function getKey() {
  const raw = process.env.ATLASSIAN_ENC_KEY;
  if (!raw) {
    throw new Error('ATLASSIAN_ENC_KEY is not set');
  }
  const key = Buffer.from(raw, 'base64');
  if (key.length !== KEY_LENGTH) {
    throw new Error(`ATLASSIAN_ENC_KEY must decode to ${KEY_LENGTH} bytes, got ${key.length}`);
  }
  return key;
}

/**
 * Encrypts plaintext with AES-256-GCM using the key from ATLASSIAN_ENC_KEY.
 * Used to store per-user Atlassian PATs at rest.
 * @param {string} plaintext
 * @returns {string} base64(iv|tag|ciphertext)
 */
export function encrypt(plaintext) {
  const key = getKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ciphertext]).toString('base64');
}

/**
 * Decrypts a base64(iv|tag|ciphertext) payload produced by encrypt().
 * Throws if the key is wrong or the payload was tampered with (GCM auth
 * tag verification failure).
 * @param {string} payload
 * @returns {string} plaintext
 */
export function decrypt(payload) {
  const key = getKey();
  const buf = Buffer.from(payload, 'base64');
  const minLength = IV_LENGTH + TAG_LENGTH;
  if (buf.length < minLength) {
    throw new Error(
      `decrypt payload must decode to at least ${minLength} bytes, got ${buf.length}`,
    );
  }
  const iv = buf.subarray(0, IV_LENGTH);
  const tag = buf.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
  const ciphertext = buf.subarray(IV_LENGTH + TAG_LENGTH);
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}
