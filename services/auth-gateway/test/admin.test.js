import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { openDb } from '../src/db.js';
import { verifyPassword } from '../src/tokens.js';
import { createUser, issueToken, revokeToken } from '../bin/admin.js';

before(() => {
  process.env.ATLASSIAN_ENC_KEY = crypto.randomBytes(32).toString('base64');
});

test('createUser inserts a user with a bcrypt-hashed password', async () => {
  const db = openDb(':memory:');
  const user = await createUser(db, { username: 'alice', password: 'a-strong-password' });
  assert.equal(user.username, 'alice');
  assert.ok(user.id > 0);

  const row = /** @type {any} */ (db.prepare('SELECT * FROM users WHERE id = ?').get(user.id));
  assert.notEqual(row.password_hash, 'a-strong-password');
  assert.equal(await verifyPassword('a-strong-password', row.password_hash), true);
  db.close();
});

test('createUser rejects a duplicate username', async () => {
  const db = openDb(':memory:');
  await createUser(db, { username: 'bob', password: 'pw-one' });
  await assert.rejects(() => createUser(db, { username: 'bob', password: 'pw-two' }));
  db.close();
});

test('issueToken generates a raw token, stores only its hash, and returns the raw token once', async () => {
  const db = openDb(':memory:');
  const user = await createUser(db, { username: 'carol', password: 'irrelevant' });
  const { rawToken } = issueToken(db, { userId: user.id, label: 'laptop' });

  assert.equal(typeof rawToken, 'string');
  assert.ok(rawToken.length >= 32);

  const rows = /** @type {any[]} */ (
    db.prepare('SELECT * FROM tokens WHERE user_id = ?').all(user.id)
  );
  assert.equal(rows.length, 1);
  assert.notEqual(rows[0].token_hash, rawToken);
  assert.equal(rows[0].label, 'laptop');
  db.close();
});

test('revokeToken sets revoked_at for the matching raw token', async () => {
  const db = openDb(':memory:');
  const user = await createUser(db, { username: 'dave', password: 'irrelevant' });
  const { rawToken } = issueToken(db, { userId: user.id });

  const revoked = revokeToken(db, { token: rawToken });
  assert.equal(revoked, true);

  const row = /** @type {any} */ (
    db.prepare('SELECT * FROM tokens WHERE user_id = ?').get(user.id)
  );
  assert.ok(row.revoked_at, 'expected revoked_at to be set');
  db.close();
});

test('revokeToken returns false for an unknown token', () => {
  const db = openDb(':memory:');
  const revoked = revokeToken(db, { token: 'a-token-that-was-never-issued' });
  assert.equal(revoked, false);
  db.close();
});
