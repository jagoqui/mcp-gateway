import crypto from 'node:crypto';
import { hashPassword, hashToken } from './tokens.js';
import { recordAudit } from './admin-audit.js';
import { encrypt } from './crypto.js';

const TOKEN_BYTES = 32;

// Shared ownership predicate for token-scoped admin writes (D11/A15):
// revokeTokenById and regenerateToken both key on this exact fragment.
const OWNED_ACTIVE_TOKEN_PREDICATE = 'user_id = ? AND revoked_at IS NULL';

/**
 * Creates a user with a bcrypt-hashed password. Ported verbatim from
 * bin/admin.js (D11); bin/admin.js re-exports this in Unit 3. `role` only
 * matters for an admin (`isAdmin: true`) account — it is the same
 * admin/member distinction Unit 3 introduced elsewhere, exposed here too
 * so `bin/admin.js create-user` can provision a member directly.
 * @param {import('better-sqlite3').Database} db
 * @param {{ username: string, password: string, isAdmin?: boolean, role?: string }} opts
 * @returns {Promise<{ id: number, username: string }>}
 */
export async function createUser(db, opts) {
  const { username, password, isAdmin = false, role = 'admin' } = opts;
  const passwordHash = await hashPassword(password);
  const info = db
    .prepare('INSERT INTO users (username, password_hash, is_admin, role) VALUES (?, ?, ?, ?)')
    .run(username, passwordHash, isAdmin ? 1 : 0, role);
  return { id: Number(info.lastInsertRowid), username };
}

/**
 * Creates a regular (is_admin=0, hardcoded — never settable via `opts`) user
 * and records its `user.create` audit row atomically (D8) — the admin
 * panel's `POST /admin/users` uses this instead of the plain `createUser`
 * above, which is CLI-only, unaudited, and can create admins.
 *
 * `hashPassword` runs BEFORE `db.transaction(...)`: bcrypt is genuinely
 * async (libuv thread pool), but better-sqlite3 transactions must be a
 * synchronous callback — the same split `regenerateToken` below uses for
 * its (synchronous) `crypto.randomBytes` call. A duplicate username throws
 * inside the transaction, which better-sqlite3 rolls back whole — the audit
 * insert, ordered after the user insert, never runs, so a failed create
 * writes nothing at all (not even a partial audit row).
 * @param {import('better-sqlite3').Database} db
 * @param {{ username: string, password: string, actorUserId: number | null, actorLabel: string }} opts
 * @returns {Promise<{ id: number, username: string }>}
 */
export async function createManagedUser(db, opts) {
  const { username, password, actorUserId, actorLabel } = opts;
  const passwordHash = await hashPassword(password);

  const runTransaction = db.transaction(() => {
    const info = db
      .prepare('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 0)')
      .run(username, passwordHash);
    const id = Number(info.lastInsertRowid);
    recordAudit(db, {
      actorUserId,
      actorLabel,
      action: 'user.create',
      outcome: 'success',
      targetUserId: id,
      detail: { username },
    });
    return { id, username };
  });

  return runTransaction();
}

/**
 * Creates a local admin account for a Cloud principal that already exists
 * (admin-identity-unification, the mirror image of createManagedUser: there
 * a local account exists and a Cloud principal gets created for it, here a
 * Cloud principal exists and a local account gets created for it). The
 * caller (admin-app.js) has already issued `token` via engram-cloud-client's
 * `issueToken` BEFORE calling this — this function's own job is purely the
 * synchronous local write (D4): `is_admin = 1` user row + encrypted
 * `engram_cloud_credentials` link + audit row, in one transaction. A
 * duplicate `username` throws and rolls back all three; the already-issued
 * Cloud token itself is not revoked by that rollback (accepted trade-off,
 * see design.md D4 — the network call had to happen before this sync
 * transaction could run).
 * @param {import('better-sqlite3').Database} db
 * @param {{ username: string, password: string, principalId: string, token: string, role?: string, actorUserId: number | null, actorLabel: string }} opts
 * @returns {Promise<{ id: number, username: string }>}
 */
export async function importEngramCloudPrincipal(db, opts) {
  const { username, password, principalId, token, role = 'admin', actorUserId, actorLabel } = opts;
  const passwordHash = await hashPassword(password);
  const ciphertext = encrypt(token);

  const runTransaction = db.transaction(() => {
    const info = db
      .prepare('INSERT INTO users (username, password_hash, is_admin, role) VALUES (?, ?, 1, ?)')
      .run(username, passwordHash, role);
    const id = Number(info.lastInsertRowid);
    db.prepare(
      `INSERT INTO engram_cloud_credentials (user_id, principal_id, ciphertext, updated_at)
       VALUES (?, ?, ?, datetime('now'))`,
    ).run(id, principalId, ciphertext);
    recordAudit(db, {
      actorUserId,
      actorLabel,
      action: 'user.create',
      outcome: 'success',
      targetUserId: id,
      detail: { username, principalId, source: 'engram_cloud_import' },
    });
    return { id, username };
  });

  return runTransaction();
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
 * Looks up one regular (is_admin=0) user by id — used to resolve the
 * `userId` query/body parameter on every Unit 10/11 route into a real,
 * eligible target before doing anything else with it. Returns undefined
 * for an unknown id OR the admin's own row (never distinguishing the two
 * to the caller, same A14 reasoning as setManagedUserDisabled's predicate).
 * @param {import('better-sqlite3').Database} db
 * @param {number} userId
 * @returns {{ id: number, username: string, created_at: string, disabled_at: string | null } | undefined}
 */
export function getManagedUser(db, userId) {
  return /** @type {any} */ (
    db
      .prepare(
        'SELECT id, username, created_at, disabled_at FROM users WHERE id = ? AND is_admin = 0',
      )
      .get(userId)
  );
}

/**
 * issueToken's audited counterpart (D8, same pattern as createManagedUser/
 * setManagedUserDisabled above) — the admin panel's POST /admin/tokens/issue
 * uses this instead of the plain issueToken, which stays unaudited for any
 * other caller. Unlike issueToken, this also re-validates the target
 * user's eligibility (is_admin=0) INSIDE the same transaction as the
 * insert — resolving `userId` into a real target is an eligibility
 * predicate the write itself must enforce (design.md's "every write
 * resolves its target with an ownership/eligibility predicate" rule),
 * not something the caller can be trusted to have already checked, even
 * though admin-app.js's handler also checks it via getManagedUser first
 * for a nicer error path (TOCTOU is not a real concern here — better-sqlite3
 * is synchronous and Node is single-threaded, so nothing can change the row
 * between that check and this transaction — but re-checking here means
 * issueManagedToken is correct even called on its own).
 *
 * Returns null (not throwing) when the target user doesn't exist or isn't
 * eligible — a real, expected outcome the caller branches on, not the
 * "something broke" case a thrown error implies.
 * @param {import('better-sqlite3').Database} db
 * @param {{ userId: number, label?: string | null, actorUserId: number | null, actorLabel: string }} opts
 * @returns {{ rawToken: string, tokenId: number, username: string } | null}
 */
export function issueManagedToken(db, opts) {
  const { userId, label = null, actorUserId, actorLabel } = opts;
  const rawToken = crypto.randomBytes(TOKEN_BYTES).toString('base64url');
  const tokenHash = hashToken(rawToken);

  const runTransaction = db.transaction(() => {
    const targetUser = getManagedUser(db, userId);
    if (!targetUser) {
      return null;
    }
    const info = db
      .prepare('INSERT INTO tokens (user_id, token_hash, label) VALUES (?, ?, ?)')
      .run(userId, tokenHash, label);
    const tokenId = Number(info.lastInsertRowid);
    recordAudit(db, {
      actorUserId,
      actorLabel,
      action: 'token.issue',
      outcome: 'success',
      targetUserId: userId,
      targetTokenId: tokenId,
      detail: label ? { label } : null,
    });
    return { tokenId, username: targetUser.username };
  });

  const result = runTransaction();
  if (!result) {
    return null;
  }
  return { rawToken, tokenId: result.tokenId, username: result.username };
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
 * setUserDisabled's audited counterpart (D8, same reasoning as
 * createManagedUser above) — the admin panel's POST /admin/users/disable
 * and POST /admin/users/enable use this instead of the plain
 * setUserDisabled, which stays unaudited for any other caller.
 *
 * No async step here (unlike createManagedUser's bcrypt hash), so the
 * whole thing is one plain synchronous db.transaction: the UPDATE and its
 * audit row commit or roll back together. When the WHERE predicate matches
 * nothing — an unknown id, or the admin's own row (A14, `is_admin = 0`) —
 * `changes` is 0, the function returns false, and NO audit row is written:
 * an action that didn't happen must never look like it did in the trail.
 * @param {import('better-sqlite3').Database} db
 * @param {{ userId: number, disabled: boolean, actorUserId: number | null, actorLabel: string }} opts
 * @returns {boolean}
 */
export function setManagedUserDisabled(db, opts) {
  const { userId, disabled, actorUserId, actorLabel } = opts;
  const runTransaction = db.transaction(() => {
    const sql = disabled
      ? "UPDATE users SET disabled_at = datetime('now') WHERE id = ? AND is_admin = 0"
      : 'UPDATE users SET disabled_at = NULL WHERE id = ? AND is_admin = 0';
    const result = db.prepare(sql).run(userId);
    if (result.changes === 0) {
      return false;
    }
    recordAudit(db, {
      actorUserId,
      actorLabel,
      action: disabled ? 'user.disable' : 'user.enable',
      outcome: 'success',
      targetUserId: userId,
    });
    return true;
  });
  return runTransaction();
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
 * Lists every admin-panel account (is_admin=1) — the mirror of
 * listManagedUsers for the accounts that can log into this panel itself
 * (admin-identity-unification Unit 3), each with its admin/member role.
 * User-requested (2026-09-17): these accounts and their role were
 * previously invisible anywhere in the UI. No token-count join — the
 * per-user Bearer tokens `listManagedUsers` counts are for regular
 * gateway users, a wholly separate concept from an admin-panel login.
 * @param {import('better-sqlite3').Database} db
 * @returns {Array<{ id: number, username: string, role: string, created_at: string, disabled_at: string | null }>}
 */
export function listAdminAccounts(db) {
  return /** @type {any[]} */ (
    db
      .prepare(
        `SELECT id, username, role, created_at, disabled_at
       FROM users
       WHERE is_admin = 1
       ORDER BY username COLLATE NOCASE`,
      )
      .all()
  );
}

/**
 * Looks up one admin-panel account (is_admin=1) by id, with its role —
 * the mirror of getManagedUser, used to resolve a profile page's
 * `?userId=` into a real, eligible target (mcp-profile-page).
 * @param {import('better-sqlite3').Database} db
 * @param {number} userId
 * @returns {{ id: number, username: string, role: string, disabled_at: string | null } | undefined}
 */
export function getAdminAccount(db, userId) {
  return /** @type {any} */ (
    db
      .prepare('SELECT id, username, role, disabled_at FROM users WHERE id = ? AND is_admin = 1')
      .get(userId)
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
 * revokeTokenById's audited counterpart (D8, same pattern as
 * createManagedUser/setManagedUserDisabled/issueManagedToken above) — the
 * admin panel's POST /admin/tokens/revoke uses this instead of the plain
 * revokeTokenById, which stays unaudited for any other caller. Re-checks
 * target eligibility (getManagedUser, is_admin=0) INSIDE the same
 * transaction as the UPDATE, same reasoning as issueManagedToken — belt
 * and braces on top of OWNED_ACTIVE_TOKEN_PREDICATE's user_id ownership
 * check (A15), which is the real cross-user boundary either way.
 *
 * Deliberately NOT touching regenerateToken below to add the same
 * eligibility re-check: it already has its own audited transaction from
 * Unit 2, predating this file's `*Managed*` naming convention but
 * following the identical D8 shape — admin-app.js's handler pre-checks
 * eligibility via getManagedUser before calling it instead, matching how
 * every GET route here already does.
 * @param {import('better-sqlite3').Database} db
 * @param {{ tokenId: number, userId: number, actorUserId: number | null, actorLabel: string }} opts
 * @returns {boolean}
 */
export function revokeManagedToken(db, opts) {
  const { tokenId, userId, actorUserId, actorLabel } = opts;
  const runTransaction = db.transaction(() => {
    const targetUser = getManagedUser(db, userId);
    if (!targetUser) {
      return false;
    }
    const result = db
      .prepare(
        `UPDATE tokens SET revoked_at = datetime('now') WHERE id = ? AND ${OWNED_ACTIVE_TOKEN_PREDICATE}`,
      )
      .run(tokenId, userId);
    if (result.changes === 0) {
      return false;
    }
    recordAudit(db, {
      actorUserId,
      actorLabel,
      action: 'token.revoke',
      outcome: 'success',
      targetUserId: userId,
      targetTokenId: tokenId,
    });
    return true;
  });
  return runTransaction();
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
