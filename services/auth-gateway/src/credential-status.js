import { MCP_REGISTRY } from './mcp-registry.js';

/**
 * @typedef {{
 *   id: string,
 *   label: string,
 *   perUserCredentials: true,
 *   enrolled: boolean,
 *   scheme: string | null,
 *   cloudId: string | null,
 *   updatedAt: string | null,
 * }} PerUserStatus
 *
 * @typedef {{
 *   id: string,
 *   label: string,
 *   perUserCredentials: false,
 *   configured: boolean,
 *   note: string,
 * }} SharedStatus
 */

/**
 * Loads the caller's own atlassian_credentials row, if any. The column list
 * is explicit and deliberately excludes `ciphertext` — R8 (credential
 * material must never leave this module) — so there is no accidental path
 * for the secret to reach a JSON response, unlike a `SELECT *`.
 * @param {import('better-sqlite3').Database} db
 * @param {number} userId
 * @returns {{ scheme: string, cloud_id: string | null, updated_at: string } | undefined}
 */
function loadAtlassianRow(db, userId) {
  return /** @type {any} */ (
    db
      .prepare('SELECT scheme, cloud_id, updated_at FROM atlassian_credentials WHERE user_id = ?')
      .get(userId)
  );
}

/**
 * Projects a registry MCP entry plus DB/env state into the exact shape the
 * credential panel and GET /me/credentials expose. Never includes
 * ciphertext, decrypted plaintext, or a sharedSecretEnv's actual value —
 * only presence booleans and the allow-listed columns above.
 * @param {import('better-sqlite3').Database} db
 * @param {{ id: number, username: string }} user
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} [env]
 * @returns {{ username: string, mcps: Array<PerUserStatus | SharedStatus> }}
 */
export function buildCredentialStatus(db, user, env = process.env) {
  const mcps = MCP_REGISTRY.map((entry) => {
    if (entry.perUserCredentials) {
      const row = loadAtlassianRow(db, user.id);
      /** @type {PerUserStatus} */
      const status = {
        id: entry.id,
        label: entry.label,
        perUserCredentials: true,
        enrolled: Boolean(row),
        scheme: row ? row.scheme : null,
        cloudId: row ? row.cloud_id : null,
        updatedAt: row ? row.updated_at : null,
      };
      return status;
    }

    /** @type {SharedStatus} */
    const status = {
      id: entry.id,
      label: entry.label,
      perUserCredentials: false,
      configured: Boolean(env[/** @type {string} */ (entry.sharedSecretEnv)]),
      note: /** @type {string} */ (entry.note),
    };
    return status;
  });

  return { username: user.username, mcps };
}
