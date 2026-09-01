import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from '../src/db.js';
import { verifyPassword } from '../src/tokens.js';
import { createUser, issueToken, revokeToken, main } from '../bin/admin.js';
import * as userAdmin from '../src/user-admin.js';

before(() => {
  process.env.ATLASSIAN_ENC_KEY = crypto.randomBytes(32).toString('base64');
});

test('bin/admin.js re-exports createUser, issueToken, revokeToken from src/user-admin.js (delegation, not reimplementation)', () => {
  assert.deepEqual(
    [createUser, issueToken, revokeToken],
    [userAdmin.createUser, userAdmin.issueToken, userAdmin.revokeToken],
  );
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

// main() opens its own db connection per call, so a real file is required.
/** @param {string[]} args @param {string} dbFile */
async function runMain(args, dbFile) {
  const originalArgv = process.argv;
  const originalDbPath = process.env.AUTH_GATEWAY_DB_PATH;
  const originalLog = console.log;
  const originalError = console.error;
  const logs = /** @type {string[]} */ ([]);
  const errors = /** @type {string[]} */ ([]);
  console.log = (...parts) => logs.push(parts.join(' '));
  console.error = (...parts) => errors.push(parts.join(' '));
  process.argv = ['node', 'admin.js', ...args];
  process.env.AUTH_GATEWAY_DB_PATH = dbFile;
  try {
    await main();
  } finally {
    console.log = originalLog;
    console.error = originalError;
    process.argv = originalArgv;
    if (originalDbPath === undefined) delete process.env.AUTH_GATEWAY_DB_PATH;
    else process.env.AUTH_GATEWAY_DB_PATH = originalDbPath;
  }
  return { logs, errors };
}

function scratchDbFile() {
  return path.join(os.tmpdir(), `auth-gateway-admin-test-${crypto.randomUUID()}.sqlite`);
}

/** @param {string} file */
function cleanupDbFile(file) {
  for (const suffix of ['', '-wal', '-shm']) fs.rmSync(file + suffix, { force: true });
}

test('set-password updates the bcrypt hash for an existing user and prints a confirmation', async () => {
  const file = scratchDbFile();
  try {
    const seedDb = openDb(file);
    await createUser(seedDb, { username: 'erin', password: 'old-password' });
    seedDb.close();

    const { logs } = await runMain(
      ['set-password', '--username', 'erin', '--password', 'new-password'],
      file,
    );
    assert.ok(logs.some((line) => line.includes('erin')));

    const verifyDb = openDb(file);
    const row = /** @type {any} */ (
      verifyDb.prepare('SELECT password_hash FROM users WHERE username = ?').get('erin')
    );
    assert.equal(await verifyPassword('new-password', row.password_hash), true);
    assert.equal(await verifyPassword('old-password', row.password_hash), false);
    verifyDb.close();
  } finally {
    cleanupDbFile(file);
  }
});

test('set-password with an unknown username prints an error and sets process.exitCode = 1', async () => {
  const file = scratchDbFile();
  const originalExitCode = process.exitCode;
  try {
    process.exitCode = undefined;
    const { errors } = await runMain(
      ['set-password', '--username', 'ghost', '--password', 'whatever'],
      file,
    );
    assert.equal(process.exitCode, 1);
    assert.ok(errors.some((line) => line.includes('ghost')));
  } finally {
    process.exitCode = originalExitCode;
    cleanupDbFile(file);
  }
});
