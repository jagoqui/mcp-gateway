import { test } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../src/db.js';
import { verifyPassword } from '../src/tokens.js';
import {
  createUser,
  createManagedUser,
  issueToken,
  revokeToken,
  listManagedUsers,
  setUserDisabled,
  setPassword,
  listTokensForUser,
  revokeTokenById,
  regenerateToken,
} from '../src/user-admin.js';

/** @returns {any[]} */
function allAuditRows(db) {
  return db.prepare('SELECT * FROM admin_audit_log ORDER BY id').all();
}

// 2.1 — byte-for-byte port baseline (D11), reusing test/admin.test.js's assertions.
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

// Unit 8 — POST /admin/users' audited create path.
test('createManagedUser inserts an is_admin=0 user with a bcrypt-hashed password, regardless of any other flag', async () => {
  const db = openDb(':memory:');
  const admin = await createUser(db, {
    username: 'root-admin',
    password: 'irrelevant',
    isAdmin: true,
  });
  const user = await createManagedUser(db, {
    username: 'nadia',
    password: 'a-strong-password',
    actorUserId: admin.id,
    actorLabel: 'root-admin',
  });
  assert.equal(user.username, 'nadia');
  const row = /** @type {any} */ (db.prepare('SELECT * FROM users WHERE id = ?').get(user.id));
  assert.equal(row.is_admin, 0);
  assert.equal(await verifyPassword('a-strong-password', row.password_hash), true);
  db.close();
});

test('createManagedUser writes exactly one user.create audit row naming the actor and the new user', async () => {
  const db = openDb(':memory:');
  const admin = await createUser(db, {
    username: 'root-admin',
    password: 'irrelevant',
    isAdmin: true,
  });
  const user = await createManagedUser(db, {
    username: 'oscar',
    password: 'irrelevant',
    actorUserId: admin.id,
    actorLabel: 'root-admin',
  });

  const rows = allAuditRows(db);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].action, 'user.create');
  assert.equal(rows[0].outcome, 'success');
  assert.equal(rows[0].actor_user_id, admin.id);
  assert.equal(rows[0].actor_label, 'root-admin');
  assert.equal(rows[0].target_user_id, user.id);
  assert.equal(JSON.parse(rows[0].detail).username, 'oscar');
  db.close();
});

test('createManagedUser rejects a duplicate username and writes no audit row (D8)', async () => {
  const db = openDb(':memory:');
  const admin = await createUser(db, {
    username: 'root-admin',
    password: 'irrelevant',
    isAdmin: true,
  });
  await createManagedUser(db, {
    username: 'petra',
    password: 'pw-one',
    actorUserId: admin.id,
    actorLabel: 'root-admin',
  });

  await assert.rejects(() =>
    createManagedUser(db, {
      username: 'petra',
      password: 'pw-two',
      actorUserId: admin.id,
      actorLabel: 'root-admin',
    }),
  );

  assert.equal(allAuditRows(db).length, 1);
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
  assert.equal(revokeToken(db, { token: rawToken }), true);
  const row = /** @type {any} */ (
    db.prepare('SELECT * FROM tokens WHERE user_id = ?').get(user.id)
  );
  assert.ok(row.revoked_at, 'expected revoked_at to be set');
  db.close();
});

test('revokeToken returns false for an unknown token', () => {
  const db = openDb(':memory:');
  assert.equal(revokeToken(db, { token: 'a-token-that-was-never-issued' }), false);
  db.close();
});

// 2.3/2.4 — listManagedUsers
test('listManagedUsers excludes admin rows, orders COLLATE NOCASE, and carries token counts with no raw/hashed token value', async () => {
  const db = openDb(':memory:');
  await createUser(db, { username: 'root-admin', password: 'irrelevant', isAdmin: true });
  const zack = await createUser(db, { username: 'zack', password: 'irrelevant' });
  await createUser(db, { username: 'Amy', password: 'irrelevant' });
  const { rawToken: t1 } = issueToken(db, { userId: zack.id, label: 'one' });
  issueToken(db, { userId: zack.id, label: 'two' });
  revokeToken(db, { token: t1 });

  const rows = listManagedUsers(db);
  assert.equal(rows.length, 2);
  assert.deepEqual(
    rows.map((r) => r.username),
    ['Amy', 'zack'],
  );

  const zackRow = rows.find((r) => r.username === 'zack');
  assert.equal(zackRow.active_token_count, 1);
  assert.equal(zackRow.revoked_token_count, 1);
  const amyRow = rows.find((r) => r.username === 'Amy');
  assert.equal(amyRow.active_token_count, 0);
  assert.equal(amyRow.revoked_token_count, 0);

  for (const row of rows) {
    assert.equal(Object.prototype.hasOwnProperty.call(row, 'token_hash'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(row, 'password_hash'), false);
  }
  db.close();
});

// 2.5/2.6 — setUserDisabled
test('setUserDisabled sets disabled_at and leaves tokens untouched, and re-enabling clears it', async () => {
  const db = openDb(':memory:');
  const user = await createUser(db, { username: 'erin', password: 'irrelevant' });
  issueToken(db, { userId: user.id, label: 'phone' });

  assert.equal(setUserDisabled(db, { userId: user.id, disabled: true }), true);
  let row = /** @type {any} */ (db.prepare('SELECT * FROM users WHERE id = ?').get(user.id));
  assert.ok(row.disabled_at, 'expected disabled_at to be set');
  const tokenRow = /** @type {any} */ (
    db.prepare('SELECT * FROM tokens WHERE user_id = ?').get(user.id)
  );
  assert.equal(tokenRow.revoked_at, null);

  assert.equal(setUserDisabled(db, { userId: user.id, disabled: false }), true);
  row = /** @type {any} */ (db.prepare('SELECT * FROM users WHERE id = ?').get(user.id));
  assert.equal(row.disabled_at, null);
  db.close();
});

test('setUserDisabled is a no-op against an admin row (AND is_admin = 0)', async () => {
  const db = openDb(':memory:');
  const admin = await createUser(db, {
    username: 'root-admin2',
    password: 'irrelevant',
    isAdmin: true,
  });
  assert.equal(setUserDisabled(db, { userId: admin.id, disabled: true }), false);
  const row = /** @type {any} */ (db.prepare('SELECT * FROM users WHERE id = ?').get(admin.id));
  assert.equal(row.disabled_at, null);
  db.close();
});

// 2.7/2.8 — setPassword
test('setPassword updates the bcrypt hash for an existing username', async () => {
  const db = openDb(':memory:');
  await createUser(db, { username: 'frank', password: 'old-password' });
  assert.equal(await setPassword(db, { username: 'frank', password: 'new-password' }), true);
  const row = /** @type {any} */ (
    db.prepare('SELECT password_hash FROM users WHERE username = ?').get('frank')
  );
  assert.equal(await verifyPassword('new-password', row.password_hash), true);
  assert.equal(await verifyPassword('old-password', row.password_hash), false);
  db.close();
});

test('setPassword returns false for an unknown username', async () => {
  const db = openDb(':memory:');
  assert.equal(await setPassword(db, { username: 'nobody', password: 'whatever' }), false);
  db.close();
});

// 2.9/2.10 — listTokensForUser
test('listTokensForUser returns only the explicit projected columns, never token_hash', async () => {
  const db = openDb(':memory:');
  const user = await createUser(db, { username: 'gina', password: 'irrelevant' });
  const { rawToken } = issueToken(db, { userId: user.id, label: 'tablet' });
  revokeToken(db, { token: rawToken });
  issueToken(db, { userId: user.id, label: 'watch' });

  const rows = listTokensForUser(db, user.id);
  assert.equal(rows.length, 2);
  for (const row of rows) {
    assert.equal(Object.prototype.hasOwnProperty.call(row, 'token_hash'), false);
    for (const key of ['id', 'label', 'created_at', 'last_used_at', 'revoked_at']) {
      assert.ok(Object.prototype.hasOwnProperty.call(row, key));
    }
  }
  assert.ok(rows.find((r) => r.label === 'tablet').revoked_at);
  assert.equal(rows.find((r) => r.label === 'watch').revoked_at, null);
  db.close();
});

// 2.11/2.12 — revokeTokenById
test('revokeTokenById sets revoked_at only when the token belongs to userId', async () => {
  const db = openDb(':memory:');
  const owner = await createUser(db, { username: 'henry', password: 'irrelevant' });
  const stranger = await createUser(db, { username: 'ivy', password: 'irrelevant' });
  issueToken(db, { userId: owner.id, label: 'desktop' });
  const tokenRow = /** @type {any} */ (
    db.prepare('SELECT id FROM tokens WHERE user_id = ?').get(owner.id)
  );

  assert.equal(revokeTokenById(db, { tokenId: tokenRow.id, userId: stranger.id }), false);
  let row = /** @type {any} */ (db.prepare('SELECT * FROM tokens WHERE id = ?').get(tokenRow.id));
  assert.equal(row.revoked_at, null);

  assert.equal(revokeTokenById(db, { tokenId: tokenRow.id, userId: owner.id }), true);
  row = /** @type {any} */ (db.prepare('SELECT * FROM tokens WHERE id = ?').get(tokenRow.id));
  assert.ok(row.revoked_at);
  db.close();
});

// 2.13/2.14 — regenerateToken
test('regenerateToken revokes the old token, issues exactly one new active token, and audits the change', async () => {
  const db = openDb(':memory:');
  const admin = await createUser(db, {
    username: 'root-admin3',
    password: 'irrelevant',
    isAdmin: true,
  });
  const user = await createUser(db, { username: 'jack', password: 'irrelevant' });
  issueToken(db, { userId: user.id, label: 'primary' });
  const oldTokenRow = /** @type {any} */ (
    db.prepare('SELECT id FROM tokens WHERE user_id = ?').get(user.id)
  );

  const result = regenerateToken(db, {
    tokenId: oldTokenRow.id,
    userId: user.id,
    actorUserId: admin.id,
    actorLabel: 'root-admin3',
  });
  assert.equal(typeof result.rawToken, 'string');
  assert.ok(result.rawToken.length >= 32);
  assert.ok(result.newTokenId > 0);

  const oldRow = /** @type {any} */ (
    db.prepare('SELECT * FROM tokens WHERE id = ?').get(oldTokenRow.id)
  );
  assert.ok(oldRow.revoked_at, 'expected the old token to be revoked');
  const activeTokens = /** @type {any[]} */ (
    db.prepare('SELECT * FROM tokens WHERE user_id = ? AND revoked_at IS NULL').all(user.id)
  );
  assert.equal(activeTokens.length, 1);
  assert.equal(activeTokens[0].id, result.newTokenId);

  const auditRows = /** @type {any[]} */ (
    db.prepare("SELECT * FROM admin_audit_log WHERE action = 'token.regenerate'").all()
  );
  assert.equal(auditRows.length, 1);
  assert.equal(JSON.parse(auditRows[0].detail).revokedTokenId, oldTokenRow.id);
  db.close();
});

test('regenerateToken throws and touches no row when tokenId/userId do not match', async () => {
  const db = openDb(':memory:');
  const admin = await createUser(db, {
    username: 'root-admin4',
    password: 'irrelevant',
    isAdmin: true,
  });
  const owner = await createUser(db, { username: 'karl', password: 'irrelevant' });
  const stranger = await createUser(db, { username: 'liam', password: 'irrelevant' });
  issueToken(db, { userId: owner.id, label: 'primary' });
  const tokenRow = /** @type {any} */ (
    db.prepare('SELECT id FROM tokens WHERE user_id = ?').get(owner.id)
  );

  assert.throws(() =>
    regenerateToken(db, {
      tokenId: tokenRow.id,
      userId: stranger.id,
      actorUserId: admin.id,
      actorLabel: 'root-admin4',
    }),
  );
  const row = /** @type {any} */ (db.prepare('SELECT * FROM tokens WHERE id = ?').get(tokenRow.id));
  assert.equal(row.revoked_at, null);
  const total = /** @type {any} */ (
    db.prepare('SELECT COUNT(*) AS count FROM tokens WHERE user_id = ?').get(owner.id)
  );
  assert.equal(total.count, 1);
  db.close();
});

test('regenerateToken throws and creates no new token for an already-revoked token', async () => {
  const db = openDb(':memory:');
  const admin = await createUser(db, {
    username: 'root-admin5',
    password: 'irrelevant',
    isAdmin: true,
  });
  const user = await createUser(db, { username: 'mona', password: 'irrelevant' });
  const { rawToken } = issueToken(db, { userId: user.id, label: 'primary' });
  revokeToken(db, { token: rawToken });
  const tokenRow = /** @type {any} */ (
    db.prepare('SELECT id FROM tokens WHERE user_id = ?').get(user.id)
  );

  assert.throws(() =>
    regenerateToken(db, {
      tokenId: tokenRow.id,
      userId: user.id,
      actorUserId: admin.id,
      actorLabel: 'root-admin5',
    }),
  );
  const total = /** @type {any} */ (
    db.prepare('SELECT COUNT(*) AS count FROM tokens WHERE user_id = ?').get(user.id)
  );
  assert.equal(total.count, 1);
  db.close();
});

test('regenerateToken rolls back the whole transaction when the audit insert fails', async () => {
  const db = openDb(':memory:');
  const admin = await createUser(db, {
    username: 'root-admin6',
    password: 'irrelevant',
    isAdmin: true,
  });
  const user = await createUser(db, { username: 'nina', password: 'irrelevant' });
  issueToken(db, { userId: user.id, label: 'primary' });
  const tokenRow = /** @type {any} */ (
    db.prepare('SELECT id FROM tokens WHERE user_id = ?').get(user.id)
  );

  // actorLabel: undefined forces recordAudit's actorLabel.slice(...) to throw
  // inside the same transaction — a real forced failure, no module monkey-patch.
  assert.throws(() =>
    regenerateToken(db, {
      tokenId: tokenRow.id,
      userId: user.id,
      actorUserId: admin.id,
      actorLabel: undefined,
    }),
  );
  const oldRow = /** @type {any} */ (
    db.prepare('SELECT * FROM tokens WHERE id = ?').get(tokenRow.id)
  );
  assert.equal(oldRow.revoked_at, null, 'old token must still be active after rollback');
  const total = /** @type {any} */ (
    db.prepare('SELECT COUNT(*) AS count FROM tokens WHERE user_id = ?').get(user.id)
  );
  assert.equal(total.count, 1, 'no new token must exist after rollback');
  const auditRows = /** @type {any[]} */ (
    db.prepare("SELECT * FROM admin_audit_log WHERE action = 'token.regenerate'").all()
  );
  assert.equal(auditRows.length, 0);
  db.close();
});
