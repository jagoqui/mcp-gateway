import crypto from 'node:crypto';
import { hashPassword, hashToken } from './tokens.js';
import { recordAudit } from './admin-audit.js';

const TOKEN_BYTES = 32;

// Shared ownership predicate for token-scoped admin writes (D11/A15):
// revokeTokenById and regenerateToken both key on this exact fragment.
const OWNED_ACTIVE_TOKEN_PREDICATE = 'user_id = ? AND revoked_at IS NULL';

/**
 * Creates a user with a bcrypt-hashed password. Ported verbatim from
 * bin/admin.js (D11); bin/admin.js re-exports this in Unit 3.
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
 * Issues a token; only its SHA-256 hash is persisted. Ported verbatim from
 * bin/admin.js (D11).
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
 * Revokes the token matching a raw token value. CLI-only (an admin operator
 * never holds a regular user's raw token). Ported verbatim from bin/admin.js
 * (D11).
 * @param {import('better-sqlite3').Database} db
 * @param {{ token: string }} opts
 * @returns {boolean}
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
 * Updates the bcrypt hash for an existing username (bin/admin.js
 * set-password, Unit 3 — never exposed by the panel itself).
 * @param {import('better-sqlite3').Database} db
 * @param {{ username: string, password: string }} opts
 * @returns {Promise<boolean>}
 */
export async function setPassword(db, opts) {
  const { username, password } = opts;
  const passwordHash = await hashPassword(password);
  const result = db
    .prepare('UPDATE users SET password_hash = ? WHERE username = ?')
    .run(passwordHash, username);
  return result.changes > 0;
}

/**
 * Sets or clears disabled_at for a regular user. `is_admin = 0` makes
 * targeting the admin's own row a no-op by construction (A14).
 * @param {import('better-sqlite3').Database} db
 * @param {{ userId: number, disabled: boolean }} opts
 * @returns {boolean}
 */
export function setUserDisabled(db, opts) {
  const { userId, disabled } = opts;
  const sql = disabled
    ? "UPDATE users SET disabled_at = datetime('now') WHERE id = ? AND is_admin = 0"
    : 'UPDATE users SET disabled_at = NULL WHERE id = ? AND is_admin = 0';
  const result = db.prepare(sql).run(userId);
  return result.changes > 0;
}

/**
 * Lists every regular (non-admin) user with a token-count summary — never a
 * raw/hashed token value (A11). `t.id IS NOT NULL` guards the active count
 * against the LEFT JOIN's phantom all-NULL row for a user with no tokens.
 * @param {import('better-sqlite3').Database} db
 * @returns {Array<{ id: number, username: string, created_at: string, disabled_at: string | null,
 *   active_token_count: number, revoked_token_count: number }>}
 */
export function listManagedUsers(db) {
  return /** @type {any[]} */ (
    db
      .prepare(
        `SELECT
         u.id, u.username, u.created_at, u.disabled_at,
         COALESCE(SUM(CASE WHEN t.id IS NOT NULL AND t.revoked_at IS NULL THEN 1 ELSE 0 END), 0) AS active_token_count,
         COALESCE(SUM(CASE WHEN t.revoked_at IS NOT NULL THEN 1 ELSE 0 END), 0) AS revoked_token_count
       FROM users u
       LEFT JOIN tokens t ON t.user_id = u.id
       WHERE u.is_admin = 0
       GROUP BY u.id
       ORDER BY u.username COLLATE NOCASE`,
      )
      .all()
  );
}

/**
 * Lists a user's tokens via an explicit column list — token_hash never
 * reaches this projection (A11, R8-style precedent).
 * @param {import('better-sqlite3').Database} db
 * @param {number} userId
 * @returns {Array<{ id: number, label: string | null, created_at: string,
 *   last_used_at: string | null, revoked_at: string | null }>}
 */
export function listTokensForUser(db, userId) {
  return /** @type {any[]} */ (
    db
      .prepare(
        'SELECT id, label, created_at, last_used_at, revoked_at FROM tokens WHERE user_id = ? ORDER BY created_at DESC',
      )
      .all(userId)
  );
}

/**
 * Revokes a token by id, scoped to its owning user (A15).
 * @param {import('better-sqlite3').Database} db
 * @param {{ tokenId: number, userId: number }} opts
 * @returns {boolean}
 */
export function revokeTokenById(db, opts) {
  const { tokenId, userId } = opts;
  const result = db
    .prepare(
      `UPDATE tokens SET revoked_at = datetime('now') WHERE id = ? AND ${OWNED_ACTIVE_TOKEN_PREDICATE}`,
    )
    .run(tokenId, userId);
  return result.changes > 0;
}

/**
 * Issues a replacement token and revokes the original in one atomic
 * transaction (design's "Regenerate Transaction Shape"). Insert-new happens
 * before revoke-old, so a rollback always leaves the original token intact.
 * recordAudit runs inside the same transaction (D8); the raw value is
 * handed back only after commit.
 * @param {import('better-sqlite3').Database} db
 * @param {{ tokenId: number, userId: number, actorUserId: number | null, actorLabel: string }} opts
 * @returns {{ rawToken: string, newTokenId: number }}
 */
export function regenerateToken(db, opts) {
  const { tokenId, userId, actorUserId, actorLabel } = opts;
  const rawToken = crypto.randomBytes(TOKEN_BYTES).toString('base64url');
  const tokenHash = hashToken(rawToken);

  const runTransaction = db.transaction(() => {
    const old = /** @type {any} */ (
      db
        .prepare(
          `SELECT id, user_id, label FROM tokens WHERE id = ? AND ${OWNED_ACTIVE_TOKEN_PREDICATE}`,
        )
        .get(tokenId, userId)
    );
    if (!old) {
      throw new Error(
        'regenerateToken: token not found, not owned by this user, or already revoked',
      );
    }
    const insertInfo = db
      .prepare('INSERT INTO tokens (user_id, token_hash, label) VALUES (?, ?, ?)')
      .run(userId, tokenHash, old.label);
    const newTokenId = Number(insertInfo.lastInsertRowid);
    const revokeResult = db
      .prepare(
        `UPDATE tokens SET revoked_at = datetime('now') WHERE id = ? AND ${OWNED_ACTIVE_TOKEN_PREDICATE}`,
      )
      .run(tokenId, userId);
    if (revokeResult.changes !== 1) {
      throw new Error('regenerateToken: failed to revoke the original token');
    }
    recordAudit(db, {
      actorUserId,
      actorLabel,
      action: 'token.regenerate',
      outcome: 'success',
      targetUserId: userId,
      targetTokenId: newTokenId,
      detail: { revokedTokenId: old.id },
    });

    return { newTokenId };
  });

  const { newTokenId } = runTransaction();
  return { rawToken, newTokenId };
}
