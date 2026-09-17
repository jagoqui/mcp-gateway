import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import { openDb, applySchema } from '../src/db.js';

test('openDb creates the users, tokens, atlassian_credentials, engram_cloud_credentials, and admin_audit_log tables', () => {
  const db = openDb(':memory:');
  const tables = /** @type {{ name: string }[]} */ (
    db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all()
  ).map((row) => row.name);
  assert.deepEqual(tables, [
    'admin_audit_log', 'atlassian_credentials', 'engram_cloud_credentials', 'tokens', 'users',
  ]);
  db.close();
});

test('admin_audit_log has the expected columns', () => {
  const db = openDb(':memory:');
  const columns = /** @type {{ name: string }[]} */ (
    db.prepare('PRAGMA table_info(admin_audit_log)').all()
  ).map((row) => row.name);
  assert.deepEqual(columns, [
    'id', 'created_at', 'actor_user_id', 'actor_label', 'action',
    'outcome', 'target_user_id', 'target_token_id', 'detail',
  ]);
  db.close();
});

test('admin_audit_log.outcome CHECK constraint rejects a value outside success/failure', () => {
  const db = openDb(':memory:');
  assert.throws(() => {
    db.prepare("INSERT INTO admin_audit_log (actor_label, action, outcome) VALUES ('admin', 'login', 'bogus')").run();
  }, /CHECK constraint failed/);
  db.close();
});

test('admin_audit_log.outcome CHECK constraint accepts success and failure', () => {
  const db = openDb(':memory:');
  db.prepare("INSERT INTO admin_audit_log (actor_label, action, outcome) VALUES ('admin', 'login', 'success')").run();
  db.prepare("INSERT INTO admin_audit_log (actor_label, action, outcome) VALUES ('admin', 'login', 'failure')").run();
  const count = /** @type {{ n: number }} */ (db.prepare('SELECT COUNT(*) AS n FROM admin_audit_log').get());
  assert.equal(count.n, 2);
  db.close();
});

test('admin_audit_log has idx_admin_audit_created and idx_admin_audit_target_user indexes', () => {
  const db = openDb(':memory:');
  const indexes = /** @type {{ name: string }[]} */ (
    db.prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'admin_audit_log' ORDER BY name").all()
  ).map((row) => row.name);
  assert.ok(indexes.includes('idx_admin_audit_created'));
  assert.ok(indexes.includes('idx_admin_audit_target_user'));
  db.close();
});

test('tokens.token_hash enforces a UNIQUE constraint', () => {
  const db = openDb(':memory:');
  db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run('alice', 'hash');
  db.prepare('INSERT INTO tokens (user_id, token_hash) VALUES (1, ?)').run('dup-hash');
  assert.throws(() => {
    db.prepare('INSERT INTO tokens (user_id, token_hash) VALUES (1, ?)').run('dup-hash');
  }, /UNIQUE constraint failed/);
  db.close();
});

test('deleting a user cascades to delete their tokens (foreign keys enforced)', () => {
  const db = openDb(':memory:');
  db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run('bob', 'hash');
  db.prepare('INSERT INTO tokens (user_id, token_hash) VALUES (1, ?)').run('bob-token-hash');
  db.prepare('DELETE FROM users WHERE id = 1').run();
  const remaining = /** @type {{ n: number }} */ (
    db.prepare('SELECT COUNT(*) AS n FROM tokens').get()
  );
  assert.equal(remaining.n, 0);
  db.close();
});

test('openDb enables WAL journal mode for on-disk databases (concurrent access safety)', () => {
  // ':memory:' databases cannot use WAL (SQLite constraint) — a real
  // on-disk file is required to observe this pragma taking effect.
  const file = path.join(os.tmpdir(), `auth-gateway-test-${crypto.randomUUID()}.sqlite`);
  const db = openDb(file);
  try {
    const journalMode = db.pragma('journal_mode', { simple: true });
    assert.equal(journalMode, 'wal');
  } finally {
    db.close();
    for (const suffix of ['', '-wal', '-shm']) {
      fs.rmSync(file + suffix, { force: true });
    }
  }
});

test('atlassian_credentials.user_id is unique per user (one credential row per person)', () => {
  const db = openDb(':memory:');
  db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run('carol', 'hash');
  db.prepare(
    "INSERT INTO atlassian_credentials (user_id, scheme, ciphertext, updated_at) VALUES (1, 'token', 'cipher-a', datetime('now'))",
  ).run();
  assert.throws(() => {
    db.prepare(
      "INSERT INTO atlassian_credentials (user_id, scheme, ciphertext, updated_at) VALUES (1, 'token', 'cipher-b', datetime('now'))",
    ).run();
  });
  db.close();
});

test('applySchema migrates a pre-existing users table (created before the role column existed) by adding role, backfilling existing rows to admin', () => {
  // Simulates a real production database: CREATE TABLE IF NOT EXISTS is a
  // no-op against a table that already exists (it does NOT retroactively
  // add new columns) — this is exactly the bug found live, 2026-09-17:
  // every pre-existing admin got 403 admin_role_required after this
  // column shipped, because their actual on-disk `users` table never
  // gained it.
  const db = new Database(':memory:');
  db.exec(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY,
      username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      is_admin INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      disabled_at TEXT
    );
  `);
  db.prepare('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)').run(
    'pre-existing-admin',
    'hash',
  );

  applySchema(db);

  const columns = /** @type {{ name: string }[]} */ (db.prepare('PRAGMA table_info(users)').all()).map(
    (c) => c.name,
  );
  assert.ok(columns.includes('role'));
  const row = /** @type {any} */ (
    db.prepare('SELECT role FROM users WHERE username = ?').get('pre-existing-admin')
  );
  assert.equal(row.role, 'admin');
  db.close();
});

test('engram_cloud_credentials has the expected columns', () => {
  const db = openDb(':memory:');
  const columns = /** @type {{ name: string }[]} */ (
    db.prepare('PRAGMA table_info(engram_cloud_credentials)').all()
  ).map((row) => row.name);
  assert.deepEqual(columns, ['user_id', 'principal_id', 'ciphertext', 'updated_at']);
  db.close();
});

test('engram_cloud_credentials.user_id is unique per user (one Cloud identity per admin)', () => {
  const db = openDb(':memory:');
  db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run('dave', 'hash');
  db.prepare(
    "INSERT INTO engram_cloud_credentials (user_id, principal_id, ciphertext, updated_at) VALUES (1, 'p1', 'cipher-a', datetime('now'))",
  ).run();
  assert.throws(() => {
    db.prepare(
      "INSERT INTO engram_cloud_credentials (user_id, principal_id, ciphertext, updated_at) VALUES (1, 'p2', 'cipher-b', datetime('now'))",
    ).run();
  });
  db.close();
});

test('users has a role column defaulting to admin, distinct from is_admin', () => {
  const db = openDb(':memory:');
  db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run('frank', 'hash');
  const row = /** @type {any} */ (
    db.prepare('SELECT role FROM users WHERE username = ?').get('frank')
  );
  assert.equal(row.role, 'admin');
  db.close();
});

test('users.role CHECK constraint accepts admin and member, rejects anything else', () => {
  const db = openDb(':memory:');
  db.prepare("INSERT INTO users (username, password_hash, role) VALUES ('grace', 'hash', 'member')").run();
  const row = /** @type {any} */ (
    db.prepare('SELECT role FROM users WHERE username = ?').get('grace')
  );
  assert.equal(row.role, 'member');
  assert.throws(() => {
    db.prepare("INSERT INTO users (username, password_hash, role) VALUES ('heidi', 'hash', 'bogus')").run();
  }, /CHECK constraint failed/);
  db.close();
});

test('deleting a user cascades to delete their engram_cloud_credentials row', () => {
  const db = openDb(':memory:');
  db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run('erin', 'hash');
  db.prepare(
    "INSERT INTO engram_cloud_credentials (user_id, principal_id, ciphertext, updated_at) VALUES (1, 'p1', 'cipher-a', datetime('now'))",
  ).run();
  db.prepare('DELETE FROM users WHERE id = 1').run();
  const remaining = /** @type {{ n: number }} */ (
    db.prepare('SELECT COUNT(*) AS n FROM engram_cloud_credentials').get()
  );
  assert.equal(remaining.n, 0);
  db.close();
});
