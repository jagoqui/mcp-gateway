#!/usr/bin/env node
import readline from 'node:readline/promises';
import { fileURLToPath } from 'node:url';
import { openDb } from '../src/db.js';
import { createUser, issueToken, revokeToken, setPassword } from '../src/user-admin.js';

const DEFAULT_DB_PATH = '/data/auth-gateway.sqlite';

// Delegated to src/user-admin.js (D11) — this CLI is a thin wrapper, not a
// second implementation.
export { createUser, issueToken, revokeToken };

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

export async function main() {
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

    if (command === 'set-password') {
      const username = flags.username || (await prompt('Username: '));
      const password = flags.password || (await prompt('Password: '));
      const updated = await setPassword(db, { username, password });
      if (!updated) {
        console.error(`No such user: '${username}'.`);
        process.exitCode = 1;
        return;
      }
      console.log(`Password updated for '${username}'.`);
      return;
    }

    console.error(
      'Usage: admin.js <create-user|issue-token|revoke-token|set-password> [--flag value ...]',
    );
    process.exitCode = 1;
  } finally {
    db.close();
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main();
}
