import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../src/db.js';
import { recordAudit, AUDIT_ACTIONS } from '../src/admin-audit.js';

/** @type {import('better-sqlite3').Database} */
let db;

beforeEach(() => {
  db = openDb(':memory:');
});

/** @returns {number} the inserted user id */
function insertUser() {
  const info = db
    .prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)')
    .run('alice', 'bcrypt-placeholder');
  return Number(info.lastInsertRowid);
}

/** @returns {any[]} */
function allAuditRows() {
  return db.prepare('SELECT * FROM admin_audit_log').all();
}

test('recordAudit inserts one row with the given action/outcome/actorUserId/targetUserId/targetTokenId', () => {
  const userId = insertUser();
  recordAudit(db, {
    actorUserId: userId,
    actorLabel: 'alice',
    action: 'user.disable',
    outcome: 'success',
    targetUserId: userId,
    targetTokenId: 7,
  });

  const rows = allAuditRows();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].actor_user_id, userId);
  assert.equal(rows[0].actor_label, 'alice');
  assert.equal(rows[0].action, 'user.disable');
  assert.equal(rows[0].outcome, 'success');
  assert.equal(rows[0].target_user_id, userId);
  assert.equal(rows[0].target_token_id, 7);
});

test('an action not in the frozen AUDIT_ACTIONS list throws and inserts nothing', () => {
  assert.throws(() => {
    recordAudit(db, { actorUserId: null, actorLabel: 'alice', action: 'user.delete', outcome: 'success' });
  });
  assert.equal(allAuditRows().length, 0);
});

test('AUDIT_ACTIONS is the frozen list from the design', () => {
  assert.deepEqual(AUDIT_ACTIONS, [
    'login', 'logout', 'user.create', 'user.disable',
    'user.enable', 'token.issue', 'token.revoke', 'token.regenerate',
  ]);
  assert.ok(Object.isFrozen(AUDIT_ACTIONS));
});

test('detail strips any key outside the allow-list before JSON.stringify', () => {
  recordAudit(db, {
    actorUserId: null,
    actorLabel: 'alice',
    action: 'login',
    outcome: 'failure',
    detail: {
      username: 'alice',
      label: 'my token',
      reason: 'bad_credentials',
      revokedTokenId: 9,
      password: 'super-secret',
      token_hash: 'should-never-appear',
      rawToken: 'should-never-appear-either',
    },
  });

  const rows = allAuditRows();
  const detail = JSON.parse(rows[0].detail);
  assert.deepEqual(Object.keys(detail).sort(), ['label', 'reason', 'revokedTokenId', 'username']);
  assert.ok(!rows[0].detail.includes('super-secret'));
  assert.ok(!rows[0].detail.includes('should-never-appear'));
});

test('actorUserId: null is accepted (failed-login case)', () => {
  recordAudit(db, {
    actorUserId: null,
    actorLabel: 'unknown-user',
    action: 'login',
    outcome: 'failure',
    detail: { reason: 'bad_credentials' },
  });

  const rows = allAuditRows();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].actor_user_id, null);
});

test('actorLabel longer than 200 chars is truncated', () => {
  const longLabel = 'a'.repeat(250);
  recordAudit(db, { actorUserId: null, actorLabel: longLabel, action: 'login', outcome: 'failure' });

  const rows = allAuditRows();
  assert.equal(rows[0].actor_label.length, 200);
  assert.equal(rows[0].actor_label, 'a'.repeat(200));
});
