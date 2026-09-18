/**
 * A gateway identity/subproject segment is safe to use verbatim as (part
 * of) an Engram project name — bounded length, and critically, NO run of
 * two or more consecutive `-`/`_`. Engram itself normalizes project names
 * by lowercasing and collapsing consecutive `-`/`_` runs into one (verified
 * against its actual source, not assumed): a segment like "ab--cd" would
 * silently become "ab-cd" server-side, which could collide with a
 * genuinely different segment that was always "ab-cd" — exactly the
 * cross-identity merge this whole module exists to prevent. Requiring
 * every separator to be immediately surrounded by alphanumerics makes that
 * collapse a no-op for anything this pattern accepts. No dot either: `.`
 * is reserved as deriveProject's own identity/subproject join separator
 * (engram does NOT collapse dots, so it survives untouched, but only if
 * neither segment can ever contain one itself — otherwise the join
 * wouldn't be unambiguous).
 */
const IDENTITY_PATTERN = /^(?=.{1,64}$)[a-zA-Z0-9]+(?:[_-][a-zA-Z0-9]+)*$/;

/**
 * Derives the Engram project identity for a request from ONLY the
 * server-verified X-Gateway-User header (as set by auth-gateway's /verify
 * and forwarded by Caddy's forward_auth `copy_headers` — never anything
 * else in the request). Any other header, including a client-supplied
 * project-like one, has no effect: this function never reads them.
 * @param {Record<string, unknown>} headers
 * @returns {string | null} the identity, or null if absent/invalid
 */
export function deriveIdentity(headers) {
  const value = headers?.['x-gateway-user'];
  if (typeof value !== 'string' || value.length === 0) {
    return null;
  }
  if (!IDENTITY_PATTERN.test(value)) {
    return null;
  }
  return value;
}

/**
 * Derives the requested Engram project (engram-shared-projects, replacing
 * the earlier always-prefixed design — see git history for that version
 * and why it changed). `X-Engram-Subproject`, when present and valid, now
 * names a SHARED, bare project directly — no identity prefix — because
 * real-time collaboration across identities was the whole point; access
 * to it is gated by an actual Engram Cloud grant, checked elsewhere
 * (process-manager.js's getOrCreateChild, NOT here — this function has no
 * way to check grants and must stay a pure, synchronous, testable string
 * decision). No subproject header at all still means the private,
 * always-available identity-scoped default (`isShared: false`) — zero
 * grant, zero admin setup, exactly as before. An invalid/malformed
 * subproject falls back to that same private default rather than
 * rejecting the request: it is not a trust boundary the way identity
 * itself is.
 *
 * Known consequence, deliberately accepted (see
 * odd/tasks/engram-shared-projects.md): a shared project's bare name can
 * collide with another identity's own private default (e.g. someone
 * granted a project literally named "yenny-fernanda" lands in the exact
 * same project as identity "yenny-fernanda"'s own private space). Never
 * grant a shared project a name matching a real gateway username.
 * @param {Record<string, unknown>} headers
 * @returns {{ identity: string, project: string, isShared: boolean } | null} null if the identity itself is absent/invalid
 */
export function deriveProject(headers) {
  const identity = deriveIdentity(headers);
  if (identity === null) {
    return null;
  }
  const subproject = headers?.['x-engram-subproject'];
  if (typeof subproject !== 'string' || !IDENTITY_PATTERN.test(subproject)) {
    return { identity, project: identity, isShared: false };
  }
  return { identity, project: subproject, isShared: true };
}
