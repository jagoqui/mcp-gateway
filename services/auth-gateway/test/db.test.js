import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDb } from '../src/db.js';

test('openDb creates the users, tokens, and atlassian_credentials tables', () => {
  const db = openDb(':memory:');
  const tables = /** @type {{ name: string }[]} */ (
    db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all()
  ).map((row) => row.name);
  assert.deepEqual(tables, ['atlassian_credentials', 'tokens', 'users']);
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
