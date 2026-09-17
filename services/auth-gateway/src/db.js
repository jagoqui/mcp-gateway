import Database from 'better-sqlite3';

// Schema per design.md. tokens.token_hash carries a UNIQUE constraint,
// which SQLite backs with an implicit index — that is the fast lookup path
// GET /verify needs on every proxied request (PR2b).
const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  role TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin', 'member')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  disabled_at TEXT
);

CREATE TABLE IF NOT EXISTS tokens (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  label TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_tokens_user ON tokens(user_id);

CREATE TABLE IF NOT EXISTS atlassian_credentials (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  scheme TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  cloud_id TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS engram_cloud_credentials (
  user_id      INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  principal_id TEXT NOT NULL,
  ciphertext   TEXT NOT NULL,
  updated_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_audit_log (
  id              INTEGER PRIMARY KEY,
  created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
  actor_user_id   INTEGER          REFERENCES users(id) ON DELETE RESTRICT,
  actor_label     TEXT    NOT NULL,
  action          TEXT    NOT NULL,
  outcome         TEXT    NOT NULL CHECK (outcome IN ('success','failure')),
  target_user_id  INTEGER          REFERENCES users(id) ON DELETE SET NULL,
  target_token_id INTEGER,
  detail          TEXT
);
CREATE INDEX IF NOT EXISTS idx_admin_audit_created ON admin_audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_admin_audit_target_user ON admin_audit_log(target_user_id);
`;

/**
 * Applies the auth-gateway schema (idempotent, CREATE ... IF NOT EXISTS) to
 * an already-open database handle.
 * @param {import('better-sqlite3').Database} db
 * @returns {void}
 */
export function applySchema(db) {
  db.exec(SCHEMA);
}

/**
 * Opens (or creates) the SQLite database at the given path and applies the
 * schema. Pass ':memory:' for an ephemeral in-process database (tests).
 * @param {string} filename
 * @returns {import('better-sqlite3').Database}
 */
export function openDb(filename) {
  const db = new Database(filename);
  db.pragma('foreign_keys = ON');
  // WAL + a busy timeout let /verify (every proxied request) and bin/admin.js
  // access the same file concurrently without blocking the event loop under
  // SQLite's default rollback-journal locking (PR2a resilience finding).
  // ':memory:' databases ignore 'journal_mode = WAL' (SQLite constraint) and
  // stay in 'memory' mode, which is fine — WAL only matters for on-disk files.
  db.pragma('journal_mode = WAL');
  db.pragma('busy_timeout = 5000');
  applySchema(db);
  return db;
}
