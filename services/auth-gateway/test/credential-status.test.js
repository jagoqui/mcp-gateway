import { test, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { openDb } from '../src/db.js';
import { encrypt } from '../src/crypto.js';
import { buildCredentialStatus } from '../src/credential-status.js';

before(() => {
  process.env.ATLASSIAN_ENC_KEY = crypto.randomBytes(32).toString('base64');
});

/** @type {import('better-sqlite3').Database} */
let db;

beforeEach(() => {
  db = openDb(':memory:');
});

/**
 * @param {{ username?: string }} [opts]
 * @returns {number} the inserted user id
 */
function insertUser(opts = {}) {
  const { username = 'alice' } = opts;
  const info = db
    .prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)')
    .run(username, 'bcrypt-placeholder');
  return Number(info.lastInsertRowid);
}

test('buildCredentialStatus reports atlassian as not-enrolled when the user has no row', () => {
  const userId = insertUser();
  const status = buildCredentialStatus(db, { id: userId, username: 'alice' }, {});

  assert.equal(status.username, 'alice');
  const atlassian = status.mcps.find((mcp) => mcp.id === 'atlassian');
  assert.ok(atlassian);
  assert.equal(atlassian.perUserCredentials, true);
  assert.equal(atlassian.enrolled, false);
  assert.equal(atlassian.scheme, null);
  assert.equal(atlassian.cloudId, null);
  assert.equal(atlassian.updatedAt, null);
});

test('buildCredentialStatus reports atlassian as enrolled with scheme/cloudId/updatedAt when a row exists', () => {
  const userId = insertUser({ username: 'bob' });
  const ciphertext = encrypt('bobs-plaintext-pat');
  db.prepare(
    `INSERT INTO atlassian_credentials (user_id, scheme, ciphertext, cloud_id, updated_at)
     VALUES (?, ?, ?, ?, datetime('now'))`,
  ).run(userId, 'Token', ciphertext, 'cloud-999');

  const status = buildCredentialStatus(db, { id: userId, username: 'bob' }, {});
  const atlassian = status.mcps.find((mcp) => mcp.id === 'atlassian');
  assert.ok(atlassian);
  assert.equal(atlassian.enrolled, true);
  assert.equal(atlassian.scheme, 'Token');
  assert.equal(atlassian.cloudId, 'cloud-999');
  assert.equal(typeof atlassian.updatedAt, 'string');
  assert.ok(atlassian.updatedAt.length > 0);
});

test('R8: buildCredentialStatus never exposes a ciphertext or plaintext key, for either enrollment state', () => {
  const notEnrolledId = insertUser({ username: 'carol' });
  const enrolledId = insertUser({ username: 'dave' });
  db.prepare(
    `INSERT INTO atlassian_credentials (user_id, scheme, ciphertext, cloud_id, updated_at)
     VALUES (?, ?, ?, ?, datetime('now'))`,
  ).run(enrolledId, 'Token', encrypt('daves-secret-pat'), 'cloud-1');

  for (const [id, username] of [
    [notEnrolledId, 'carol'],
    [enrolledId, 'dave'],
  ]) {
    const status = buildCredentialStatus(db, { id, username }, {});
    const atlassian = status.mcps.find((mcp) => mcp.id === 'atlassian');
    assert.ok(atlassian);
    const keys = Object.keys(atlassian);
    assert.ok(!keys.includes('ciphertext'));
    assert.ok(!keys.includes('token'));
    assert.ok(!keys.includes('plaintext'));
    assert.ok(!JSON.stringify(atlassian).includes('daves-secret-pat'));
  }
});

test('buildCredentialStatus reports configured:true for a shared MCP when its env var is set', () => {
  const userId = insertUser({ username: 'erin' });
  const status = buildCredentialStatus(db, { id: userId, username: 'erin' }, {
    CONTEXT7_API_KEY: 'super-secret-shared-key',
  });

  const context7 = status.mcps.find((mcp) => mcp.id === 'context7');
  assert.ok(context7);
  assert.equal(context7.perUserCredentials, false);
  assert.equal(context7.configured, true);
  assert.equal(typeof context7.note, 'string');
});

test('buildCredentialStatus reports configured:false for a shared MCP when its env var is absent', () => {
  const userId = insertUser({ username: 'frank' });
  const status = buildCredentialStatus(db, { id: userId, username: 'frank' }, {});

  const context7 = status.mcps.find((mcp) => mcp.id === 'context7');
  assert.ok(context7);
  assert.equal(context7.configured, false);
});

test('the shared secret env value itself never appears anywhere in the status output', () => {
  const userId = insertUser({ username: 'grace' });
  const secretValue = 'the-actual-context7-api-key-value';
  const status = buildCredentialStatus(db, { id: userId, username: 'grace' }, {
    CONTEXT7_API_KEY: secretValue,
    ENGRAM_API_KEY: 'the-actual-engram-key-value',
  });

  assert.ok(!JSON.stringify(status).includes(secretValue));
  assert.ok(!JSON.stringify(status).includes('the-actual-engram-key-value'));
});
