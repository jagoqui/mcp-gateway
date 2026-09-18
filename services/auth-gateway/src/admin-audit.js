// Admin audit log module. recordAudit MUST be called inside the caller's
// own db.transaction (D8) so a mutation and its audit row are never
// observed independently of each other.

const ACTOR_LABEL_MAX_LENGTH = 200;

/**
 * Frozen allow-list of every action recordAudit accepts. Any other value
 * throws, inserting nothing.
 * @type {ReadonlyArray<string>}
 */
export const AUDIT_ACTIONS = Object.freeze([
  'login',
  'logout',
  'user.create',
  'user.disable',
  'user.enable',
  'token.issue',
  'token.revoke',
  'token.regenerate',
  'cloud_token.revoke',
  'project.grant',
  'password.reset',
  'password.change',
]);

/**
 * `detail` allow-list, enforced by construction: a raw token, password, or
 * bcrypt hash must never reach this table (R8-style precedent).
 * @type {ReadonlyArray<string>}
 */
const DETAIL_ALLOWED_KEYS = Object.freeze([
  'username',
  'label',
  'reason',
  'revokedTokenId',
  'cloudTokenId',
  'project',
]);

/**
 * @param {Record<string, unknown> | null | undefined} detail
 * @returns {string | null}
 */
function buildDetailJson(detail) {
  if (!detail) {
    return null;
  }
  /** @type {Record<string, unknown>} */
  const allowed = {};
  for (const key of DETAIL_ALLOWED_KEYS) {
    if (Object.prototype.hasOwnProperty.call(detail, key)) {
      allowed[key] = detail[key];
    }
  }
  return JSON.stringify(allowed);
}

/**
 * Appends one row to admin_audit_log. Throws (inserting nothing) when
 * `action` is not in AUDIT_ACTIONS.
 * @param {import('better-sqlite3').Database} db
 * @param {{
 *   actorUserId: number | null,
 *   actorLabel: string,
 *   action: string,
 *   outcome: 'success' | 'failure',
 *   targetUserId?: number | null,
 *   targetTokenId?: number | null,
 *   detail?: Record<string, unknown> | null,
 * }} params
 * @returns {void}
 */
export function recordAudit(
  db,
  { actorUserId, actorLabel, action, outcome, targetUserId = null, targetTokenId = null, detail = null },
) {
  if (!AUDIT_ACTIONS.includes(action)) {
    throw new Error(`recordAudit: unrecognized action "${action}"`);
  }

  const truncatedLabel = actorLabel.slice(0, ACTOR_LABEL_MAX_LENGTH);
  const detailJson = buildDetailJson(detail);

  db.prepare(
    `INSERT INTO admin_audit_log
       (actor_user_id, actor_label, action, outcome, target_user_id, target_token_id, detail)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(actorUserId, truncatedLabel, action, outcome, targetUserId, targetTokenId, detailJson);
}
