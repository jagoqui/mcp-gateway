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
 * Derives the final Engram project: the trusted identity, optionally
 * suffixed with a client-supplied sub-project (X-Engram-Subproject) so one
 * gateway user can separate memories per repo without any VPS-side config
 * per project. The identity ALWAYS prefixes the result — a subproject can
 * never stand alone or collide with another user's namespace, no matter
 * what value the client sends. The join uses a single literal `.` — never
 * collapsed by engram's own normalization, and unambiguous BECAUSE neither
 * identity nor subproject can contain a dot (IDENTITY_PATTERN forbids it).
 * An invalid/malformed subproject is silently dropped (falls back to the
 * bare identity) rather than rejecting the whole request: it is not a
 * trust boundary the way the identity itself is.
 * @param {Record<string, unknown>} headers
 * @returns {string | null} the final project, or null if the identity itself is absent/invalid
 */
export function deriveProject(headers) {
  const identity = deriveIdentity(headers);
  if (identity === null) {
    return null;
  }
  const subproject = headers?.['x-engram-subproject'];
  if (typeof subproject !== 'string' || !IDENTITY_PATTERN.test(subproject)) {
    return identity;
  }
  return `${identity}.${subproject}`;
}
