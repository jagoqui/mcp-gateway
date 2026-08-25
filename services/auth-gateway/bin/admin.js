#!/usr/bin/env node
import crypto from 'node:crypto';
import readline from 'node:readline/promises';
import { fileURLToPath } from 'node:url';
import { openDb } from '../src/db.js';
import { hashPassword, hashToken } from '../src/tokens.js';

const DEFAULT_DB_PATH = '/data/auth-gateway.sqlite';
const TOKEN_BYTES = 32;

/**
 * Creates a user with a bcrypt-hashed password.
 * @param {import('better-sqlite3').Database} db
 * @param {{ username: string, password: string, isAdmin?: boolean }} opts
 * @returns {Promise<{ id: number, username: string }>}
 */
export async function createUser(db, opts) {
  const { username, password, isAdmin = false } = opts;
  const passwordHash = await hashPassword(password);
  const info = db
    .prepare('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)')
    .run(username, passwordHash, isAdmin ? 1 : 0);
  return { id: Number(info.lastInsertRowid), username };
}

/**
 * Generates a new gateway token for a user. Only the SHA-256 hash is
 * persisted (see tokens.js) — the raw token is returned exactly once and
 * MUST be shown to the operator immediately; it is never logged or stored
 * anywhere else.
 * @param {import('better-sqlite3').Database} db
 * @param {{ userId: number, label?: string }} opts
 * @returns {{ rawToken: string }}
 */
export function issueToken(db, opts) {
  const { userId, label = null } = opts;
  const rawToken = crypto.randomBytes(TOKEN_BYTES).toString('base64url');
  db.prepare('INSERT INTO tokens (user_id, token_hash, label) VALUES (?, ?, ?)').run(
    userId,
    hashToken(rawToken),
    label,
  );
  return { rawToken };
}

/**
 * Revokes the token matching the given raw token value.
 * @param {import('better-sqlite3').Database} db
 * @param {{ token: string }} opts
 * @returns {boolean} true if a token was found and revoked
 */
export function revokeToken(db, opts) {
  const { token } = opts;
  const result = db
    .prepare(
      "UPDATE tokens SET revoked_at = datetime('now') WHERE token_hash = ? AND revoked_at IS NULL",
    )
    .run(hashToken(token));
  return result.changes > 0;
}

/**
 * @param {import('better-sqlite3').Database} db
 * @param {string} username
 * @returns {number | undefined}
 */
function findUserId(db, username) {
  const row = /** @type {any} */ (
    db.prepare('SELECT id FROM users WHERE username = ?').get(username)
  );
  return row?.id;
}

/**
 * Minimal '--key value' argv parser — this CLI has only a handful of flags,
 * so a full argument-parsing dependency is not warranted.
 * @param {string[]} argv
 * @returns {Record<string, string>}
 */
function parseFlags(argv) {
  /** @type {Record<string, string>} */
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const value = argv[i + 1];
      flags[key] = value;
      i += 1;
    }
  }
  return flags;
}

/**
 * @param {string} question
 * @returns {Promise<string>}
 */
async function prompt(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    return await rl.question(question);
  } finally {
    rl.close();
  }
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  const flags = parseFlags(rest);
  const db = openDb(process.env.AUTH_GATEWAY_DB_PATH || DEFAULT_DB_PATH);

  try {
    if (command === 'create-user') {
      const username = flags.username || (await prompt('Username: '));
      const password = flags.password || (await prompt('Password: '));
      const user = await createUser(db, { username, password, isAdmin: flags.admin === 'true' });
      console.log(`Created user '${user.username}' (id ${user.id}).`);
      return;
    }

    if (command === 'issue-token') {
      const username = flags.username || (await prompt('Username: '));
      const userId = findUserId(db, username);
      if (!userId) {
        console.error(`No such user: '${username}'.`);
        process.exitCode = 1;
        return;
      }
      const { rawToken } = issueToken(db, { userId, label: flags.label });
      console.log(`Token issued for '${username}'.`);
      console.log('COPY THIS TOKEN NOW — it will not be shown again:');
      console.log(rawToken);
      return;
    }

    if (command === 'revoke-token') {
      const token = flags.token || (await prompt('Token to revoke: '));
      const revoked = revokeToken(db, { token });
      console.log(revoked ? 'Token revoked.' : 'No matching active token found.');
      return;
    }

    console.error('Usage: admin.js <create-user|issue-token|revoke-token> [--flag value ...]');
    process.exitCode = 1;
  } finally {
    db.close();
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main();
}
