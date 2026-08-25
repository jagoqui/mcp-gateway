import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { encrypt, decrypt } from '../src/crypto.js';

before(() => {
  process.env.ATLASSIAN_ENC_KEY = crypto.randomBytes(32).toString('base64');
});

test('encrypt/decrypt round-trip returns the original plaintext', () => {
  const plaintext = 'super-secret-atlassian-pat-12345';
  const ciphertext = encrypt(plaintext);
  assert.notEqual(ciphertext, plaintext);
  assert.equal(decrypt(ciphertext), plaintext);
});

test('encrypt produces a different ciphertext each call for the same plaintext (random IV)', () => {
  const plaintext = 'same-secret-value';
  const a = encrypt(plaintext);
  const b = encrypt(plaintext);
  assert.notEqual(a, b);
  // both must still independently decrypt back to the same plaintext
  assert.equal(decrypt(a), plaintext);
  assert.equal(decrypt(b), plaintext);
});

test('decrypt rejects a tampered ciphertext (GCM authenticity check)', () => {
  const ciphertext = encrypt('another-secret-pat');
  const buf = Buffer.from(ciphertext, 'base64');
  buf[buf.length - 1] ^= 0xff; // flip the last byte of the ciphertext region
  const tampered = buf.toString('base64');
  assert.throws(() => decrypt(tampered));
});

test('encrypt throws a clear error when ATLASSIAN_ENC_KEY is not set', () => {
  const original = process.env.ATLASSIAN_ENC_KEY;
  delete process.env.ATLASSIAN_ENC_KEY;
  try {
    assert.throws(() => encrypt('x'), /ATLASSIAN_ENC_KEY/);
  } finally {
    process.env.ATLASSIAN_ENC_KEY = original;
  }
});

test('encrypt throws a clear error when ATLASSIAN_ENC_KEY does not decode to 32 bytes', () => {
  const original = process.env.ATLASSIAN_ENC_KEY;
  process.env.ATLASSIAN_ENC_KEY = Buffer.from('too-short').toString('base64');
  try {
    assert.throws(() => encrypt('x'), /32 bytes/);
  } finally {
    process.env.ATLASSIAN_ENC_KEY = original;
  }
});
