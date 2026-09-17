import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { openDb } from '../src/db.js';
import { verifyPassword } from '../src/tokens.js';
import { decrypt } from '../src/crypto.js';
import {
  createUser,
  createManagedUser,
  importEngramCloudPrincipal,
  issueToken,
  issueManagedToken,
  getManagedUser,
  revokeToken,
  listManagedUsers,
  setUserDisabled,
  setManagedUserDisabled,
  setPassword,
  listTokensForUser,
  revokeTokenById,
  revokeManagedToken,
  regenerateToken,
} from '../src/user-admin.js';

// admin-identity-unification's importEngramCloudPrincipal needs a real
// encryption key — set once, module-wide (no other test in this file uses
// crypto.js, so no existing hook to piggyback on).
process.env.ATLASSIAN_ENC_KEY = crypto.randomBytes(32).toString('base64');

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

// Unit 10 — getManagedUser + POST /admin/tokens/issue's audited path.
test('getManagedUser returns the row for a regular user, and undefined for an admin row or an unknown id', async () => {
  const db = openDb(':memory:');
  const admin = await createUser(db, {
    username: 'root-admin7',
    password: 'irrelevant',
    isAdmin: true,
  });
  const user = await createUser(db, { username: 'helen', password: 'irrelevant' });

  const found = getManagedUser(db, user.id);
  assert.equal(found.username, 'helen');
  assert.equal(getManagedUser(db, admin.id), undefined);
  assert.equal(getManagedUser(db, 999999), undefined);
  db.close();
});

test('issueManagedToken generates a raw token, stores only its hash, and audits token.issue', async () => {
  const db = openDb(':memory:');
  const admin = await createUser(db, {
    username: 'root-admin8',
    password: 'irrelevant',
    isAdmin: true,
  });
  const user = await createUser(db, { username: 'ivan', password: 'irrelevant' });

  const result = issueManagedToken(db, {
    userId: user.id,
    label: 'laptop',
    actorUserId: admin.id,
    actorLabel: 'root-admin8',
  });
  assert.ok(result);
  assert.equal(typeof result.rawToken, 'string');
  assert.ok(result.rawToken.length >= 32);
  assert.equal(result.username, 'ivan');

  const rows = /** @type {any[]} */ (
    db.prepare('SELECT * FROM tokens WHERE user_id = ?').all(user.id)
  );
  assert.equal(rows.length, 1);
  assert.notEqual(rows[0].token_hash, result.rawToken);
  assert.equal(rows[0].label, 'laptop');

  const auditRows = allAuditRows(db);
  assert.equal(auditRows.length, 1);
  assert.equal(auditRows[0].action, 'token.issue');
  assert.equal(auditRows[0].outcome, 'success');
  assert.equal(auditRows[0].actor_user_id, admin.id);
  assert.equal(auditRows[0].target_user_id, user.id);
  assert.equal(auditRows[0].target_token_id, result.tokenId);
  assert.equal(JSON.parse(auditRows[0].detail).label, 'laptop');
  db.close();
});

test('issueManagedToken against an unknown or admin-owned userId returns null, writes no row, no audit', async () => {
  const db = openDb(':memory:');
  const admin = await createUser(db, {
    username: 'root-admin9',
    password: 'irrelevant',
    isAdmin: true,
  });

  assert.equal(
    issueManagedToken(db, {
      userId: 999999,
      actorUserId: admin.id,
      actorLabel: 'root-admin9',
    }),
    null,
  );
  assert.equal(
    issueManagedToken(db, {
      userId: admin.id,
      actorUserId: admin.id,
      actorLabel: 'root-admin9',
    }),
    null,
  );

  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM tokens').get().n, 0);
  assert.equal(allAuditRows(db).length, 0);
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

// Unit 9 — POST /admin/users/disable + POST /admin/users/enable's audited path.
test('setManagedUserDisabled sets disabled_at, leaves tokens untouched, and audits user.disable', async () => {
  const db = openDb(':memory:');
  const admin = await createUser(db, {
    username: 'root-admin3',
    password: 'irrelevant',
    isAdmin: true,
  });
  const user = await createUser(db, { username: 'faye', password: 'irrelevant' });
  issueToken(db, { userId: user.id, label: 'phone' });

  const result = setManagedUserDisabled(db, {
    userId: user.id,
    disabled: true,
    actorUserId: admin.id,
    actorLabel: 'root-admin3',
  });
  assert.equal(result, true);

  const row = /** @type {any} */ (db.prepare('SELECT * FROM users WHERE id = ?').get(user.id));
  assert.ok(row.disabled_at, 'expected disabled_at to be set');
  const tokenRow = /** @type {any} */ (
    db.prepare('SELECT * FROM tokens WHERE user_id = ?').get(user.id)
  );
  assert.equal(tokenRow.revoked_at, null);

  const auditRows = allAuditRows(db);
  assert.equal(auditRows.length, 1);
  assert.equal(auditRows[0].action, 'user.disable');
  assert.equal(auditRows[0].outcome, 'success');
  assert.equal(auditRows[0].actor_user_id, admin.id);
  assert.equal(auditRows[0].target_user_id, user.id);
  db.close();
});

test('setManagedUserDisabled(disabled: false) clears disabled_at and audits user.enable', async () => {
  const db = openDb(':memory:');
  const admin = await createUser(db, {
    username: 'root-admin4',
    password: 'irrelevant',
    isAdmin: true,
  });
  const user = await createUser(db, { username: 'greg', password: 'irrelevant' });
  setManagedUserDisabled(db, {
    userId: user.id,
    disabled: true,
    actorUserId: admin.id,
    actorLabel: 'root-admin4',
  });

  const result = setManagedUserDisabled(db, {
    userId: user.id,
    disabled: false,
    actorUserId: admin.id,
    actorLabel: 'root-admin4',
  });
  assert.equal(result, true);

  const row = /** @type {any} */ (db.prepare('SELECT * FROM users WHERE id = ?').get(user.id));
  assert.equal(row.disabled_at, null);

  const auditRows = allAuditRows(db);
  assert.equal(auditRows.length, 2);
  assert.equal(auditRows[1].action, 'user.enable');
  db.close();
});

test('setManagedUserDisabled against the admin row (A14) returns false and writes no audit row', async () => {
  const db = openDb(':memory:');
  const admin = await createUser(db, {
    username: 'root-admin5',
    password: 'irrelevant',
    isAdmin: true,
  });
  const result = setManagedUserDisabled(db, {
    userId: admin.id,
    disabled: true,
    actorUserId: admin.id,
    actorLabel: 'root-admin5',
  });
  assert.equal(result, false);
  const row = /** @type {any} */ (db.prepare('SELECT * FROM users WHERE id = ?').get(admin.id));
  assert.equal(row.disabled_at, null);
  assert.equal(allAuditRows(db).length, 0);
  db.close();
});

test('setManagedUserDisabled against an unknown userId returns false and writes no audit row', async () => {
  const db = openDb(':memory:');
  const admin = await createUser(db, {
    username: 'root-admin6',
    password: 'irrelevant',
    isAdmin: true,
  });
  const result = setManagedUserDisabled(db, {
    userId: 999999,
    disabled: true,
    actorUserId: admin.id,
    actorLabel: 'root-admin6',
  });
  assert.equal(result, false);
  assert.equal(allAuditRows(db).length, 0);
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

// Unit 11 — POST /admin/tokens/revoke's audited path.
test('revokeManagedToken sets revoked_at and audits token.revoke', async () => {
  const db = openDb(':memory:');
  const admin = await createUser(db, {
    username: 'root-admin10',
    password: 'irrelevant',
    isAdmin: true,
  });
  const user = await createUser(db, { username: 'kara', password: 'irrelevant' });
  issueToken(db, { userId: user.id, label: 'tablet' });
  const tokenRow = /** @type {any} */ (
    db.prepare('SELECT id FROM tokens WHERE user_id = ?').get(user.id)
  );

  const result = revokeManagedToken(db, {
    tokenId: tokenRow.id,
    userId: user.id,
    actorUserId: admin.id,
    actorLabel: 'root-admin10',
  });
  assert.equal(result, true);

  const row = /** @type {any} */ (db.prepare('SELECT * FROM tokens WHERE id = ?').get(tokenRow.id));
  assert.ok(row.revoked_at);

  const auditRows = allAuditRows(db);
  assert.equal(auditRows.length, 1);
  assert.equal(auditRows[0].action, 'token.revoke');
  assert.equal(auditRows[0].outcome, 'success');
  assert.equal(auditRows[0].actor_user_id, admin.id);
  assert.equal(auditRows[0].target_user_id, user.id);
  assert.equal(auditRows[0].target_token_id, tokenRow.id);
  db.close();
});

test("revokeManagedToken has no side effect on the target user's other tokens", async () => {
  const db = openDb(':memory:');
  const admin = await createUser(db, {
    username: 'root-admin11',
    password: 'irrelevant',
    isAdmin: true,
  });
  const user = await createUser(db, { username: 'liam', password: 'irrelevant' });
  issueToken(db, { userId: user.id, label: 'one' });
  issueToken(db, { userId: user.id, label: 'two' });
  const rows = /** @type {any[]} */ (
    db.prepare('SELECT id FROM tokens WHERE user_id = ? ORDER BY id').all(user.id)
  );

  revokeManagedToken(db, {
    tokenId: rows[0].id,
    userId: user.id,
    actorUserId: admin.id,
    actorLabel: 'root-admin11',
  });

  const untouched = /** @type {any} */ (
    db.prepare('SELECT * FROM tokens WHERE id = ?').get(rows[1].id)
  );
  assert.equal(untouched.revoked_at, null);
  db.close();
});

test('revokeManagedToken against a token owned by a different user (A15) returns false, writes no audit row', async () => {
  const db = openDb(':memory:');
  const admin = await createUser(db, {
    username: 'root-admin12',
    password: 'irrelevant',
    isAdmin: true,
  });
  const owner = await createUser(db, { username: 'mona', password: 'irrelevant' });
  const stranger = await createUser(db, { username: 'noah', password: 'irrelevant' });
  issueToken(db, { userId: owner.id, label: 'desktop' });
  const tokenRow = /** @type {any} */ (
    db.prepare('SELECT id FROM tokens WHERE user_id = ?').get(owner.id)
  );

  const result = revokeManagedToken(db, {
    tokenId: tokenRow.id,
    userId: stranger.id,
    actorUserId: admin.id,
    actorLabel: 'root-admin12',
  });
  assert.equal(result, false);
  const row = /** @type {any} */ (db.prepare('SELECT * FROM tokens WHERE id = ?').get(tokenRow.id));
  assert.equal(row.revoked_at, null);
  assert.equal(allAuditRows(db).length, 0);
  db.close();
});

test('revokeManagedToken against the admin row as userId returns false, writes no audit row', async () => {
  const db = openDb(':memory:');
  const admin = await createUser(db, {
    username: 'root-admin13',
    password: 'irrelevant',
    isAdmin: true,
  });
  const result = revokeManagedToken(db, {
    tokenId: 1,
    userId: admin.id,
    actorUserId: admin.id,
    actorLabel: 'root-admin13',
  });
  assert.equal(result, false);
  assert.equal(allAuditRows(db).length, 0);
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

// admin-identity-unification, Unit 2 — importEngramCloudPrincipal: the
// mirror image of createManagedUser, for a Cloud principal that already
// exists and needs a NEW local account created for it (D4).

test('importEngramCloudPrincipal creates an is_admin=1 local user, encrypted-linked to the given principal, in one transaction', async () => {
  const db = openDb(':memory:');
  const admin = await createUser(db, { username: 'root-admin', password: 'irrelevant', isAdmin: true });
  const user = await importEngramCloudPrincipal(db, {
    username: 'imported-bob',
    password: 'a-strong-password',
    principalId: 'p-import-1',
    token: 'issued-at-import-token',
    actorUserId: admin.id,
    actorLabel: 'root-admin',
  });
  assert.equal(user.username, 'imported-bob');

  const userRow = /** @type {any} */ (
    db.prepare('SELECT * FROM users WHERE id = ?').get(user.id)
  );
  assert.equal(userRow.is_admin, 1);
  assert.equal(await verifyPassword('a-strong-password', userRow.password_hash), true);

  const linkRow = /** @type {any} */ (
    db.prepare('SELECT * FROM engram_cloud_credentials WHERE user_id = ?').get(user.id)
  );
  assert.equal(linkRow.principal_id, 'p-import-1');
  assert.equal(decrypt(linkRow.ciphertext), 'issued-at-import-token');
  db.close();
});

test('importEngramCloudPrincipal writes exactly one user.create audit row', async () => {
  const db = openDb(':memory:');
  const admin = await createUser(db, { username: 'root-admin', password: 'irrelevant', isAdmin: true });
  const user = await importEngramCloudPrincipal(db, {
    username: 'imported-carol',
    password: 'a-strong-password',
    principalId: 'p-import-2',
    token: 'another-token',
    actorUserId: admin.id,
    actorLabel: 'root-admin',
  });
  const auditRows = /** @type {any[]} */ (
    db.prepare("SELECT * FROM admin_audit_log WHERE action = 'user.create' AND target_user_id = ?").all(user.id)
  );
  assert.equal(auditRows.length, 1);
  assert.equal(auditRows[0].actor_label, 'root-admin');
  db.close();
});

test('importEngramCloudPrincipal rolls back entirely on a duplicate local username — no user row, no link row, no audit row', async () => {
  const db = openDb(':memory:');
  const admin = await createUser(db, { username: 'root-admin', password: 'irrelevant', isAdmin: true });
  await createUser(db, { username: 'dave', password: 'already-taken' });

  await assert.rejects(() =>
    importEngramCloudPrincipal(db, {
      username: 'dave',
      password: 'a-strong-password',
      principalId: 'p-import-3',
      token: 'yet-another-token',
      actorUserId: admin.id,
      actorLabel: 'root-admin',
    }),
  );

  const linkRows = /** @type {any} */ (
    db.prepare('SELECT COUNT(*) AS count FROM engram_cloud_credentials WHERE principal_id = ?').get('p-import-3')
  );
  assert.equal(linkRows.count, 0);
  const auditRows = /** @type {any[]} */ (
    db.prepare("SELECT * FROM admin_audit_log WHERE action = 'user.create'").all()
  );
  assert.equal(auditRows.length, 0);
  db.close();
});
