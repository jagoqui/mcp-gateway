// Thin fetch wrapper for engram-cloud's admin API (`engram cloud serve`).
// Proxied by auth-gateway's own /admin/engram-cloud/* routes (admin-app.js)
// so the browser never sees ENGRAM_CLOUD_ADMIN_TOKEN directly — the token
// is held only in this process's env and used only in outbound server-side
// requests (design.md's Threat Matrix: "Engram Cloud admin token exposure").
//
// Route/payload shapes confirmed against engram's own source (deepwiki),
// not guessed — see design.md's Interfaces/Open Questions sections.

/** Reads ENGRAM_CLOUD_ADMIN_TOKEN per call (never cached), matching every
 * other secret-reading function in this codebase's rotation property.
 * @returns {string}
 */
function getEngramCloudAdminToken() {
  const token = process.env.ENGRAM_CLOUD_ADMIN_TOKEN;
  if (!token) {
    throw new Error('ENGRAM_CLOUD_ADMIN_TOKEN is not set');
  }
  return token;
}

/** Same env var (and default) engram-router/engram-serve-bridge already use
 * for this same backend — no new naming convention introduced.
 * @returns {string}
 */
function getEngramCloudServerUrl() {
  return process.env.ENGRAM_CLOUD_SERVER || 'http://engram-cloud:18080';
}

/**
 * @param {string} path
 * @param {{ method?: string, body?: Record<string, unknown> }} [options]
 * @returns {Promise<any>}
 */
async function engramCloudRequest(path, options = {}) {
  // Read/throw on a missing token BEFORE touching the network — the
  // "every client function throws when unset, before ever sending a
  // request" test above depends on this ordering.
  const adminToken = getEngramCloudAdminToken();
  const { method = 'GET', body } = options;

  const res = await fetch(`${getEngramCloudServerUrl()}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${adminToken}`,
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  const text = await res.text();
  /** @type {any} */
  let json = null;
  if (text) {
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
  }

  if (!res.ok) {
    // Deliberately no adminToken/header interpolation anywhere in this
    // message — only the response's own status/path, both attacker- and
    // secret-free.
    throw new Error(`engram-cloud admin API ${method} ${path} failed with status ${res.status}`);
  }

  return json;
}

/**
 * Lists every managed human user (GET /admin/users).
 * @returns {Promise<Array<{ principal_id: string, username: string, email?: string, display_name?: string, role: string, enabled: boolean, created_at: string }>>}
 */
export function listUsers() {
  return engramCloudRequest('/admin/users');
}

/**
 * Creates a managed user (POST /admin/users). Only `username` is required;
 * `role` defaults server-side to 'member' when omitted.
 * @param {{ username: string, email?: string, displayName?: string, role?: string }} opts
 * @returns {Promise<{ principal_id: string, username: string, email?: string, display_name?: string, role: string, enabled: boolean, created_at: string }>}
 */
export function createUser({ username, email, displayName, role }) {
  return engramCloudRequest('/admin/users', {
    method: 'POST',
    body: { username, email, display_name: displayName, role },
  });
}

/**
 * Grants a project to a user (POST /admin/users/{id}/grants).
 * @param {{ principalId: string, project: string }} opts
 * @returns {Promise<{ principal_id: string, project: string, granted_by_principal_id: string, created_at: string }>}
 */
export function grantProject({ principalId, project }) {
  return engramCloudRequest(`/admin/users/${encodeURIComponent(principalId)}/grants`, {
    method: 'POST',
    body: { project },
  });
}

/**
 * Issues a token for a user (POST /admin/users/{id}/tokens) — the raw value
 * is returned exactly once in the response body, never persisted here or
 * anywhere upstream of the caller.
 * @param {{ principalId: string, name?: string }} opts
 * @returns {Promise<{ raw_token: string, token: { id: string, principal_id: string, token_prefix: string, name: string | null, created_by_principal_id: string, created_at: string, last_used_at: string | null, revoked_at: string | null, revoked_by_principal_id: string | null, revocation_reason: string | null } }>}
 */
export function issueToken({ principalId, name }) {
  return engramCloudRequest(`/admin/users/${encodeURIComponent(principalId)}/tokens`, {
    method: 'POST',
    body: name ? { name } : {},
  });
}

/**
 * Logs a principal into Engram Cloud's own built-in dashboard
 * (`POST /dashboard/login`) using THAT principal's own token — never the
 * shared `ENGRAM_CLOUD_ADMIN_TOKEN` (Phase 5, per-admin SSO). Confirmed via
 * deepwiki against engram's own source: the token goes in a `token` form
 * field, NOT an Authorization header, and a successful login responds `303`
 * (never followed here — `redirect: 'manual'`) carrying the
 * `engram_dashboard_token` cookie this function hands back verbatim for the
 * caller to relay to the browser.
 * @param {string} token
 * @returns {Promise<{ setCookie: string | null }>}
 */
export async function loginDashboard(token) {
  const res = await fetch(`${getEngramCloudServerUrl()}/dashboard/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `token=${encodeURIComponent(token)}`,
    redirect: 'manual',
  });

  // Deliberately no response-body interpolation in this message — a 401
  // body could itself echo back caller input.
  if (res.status !== 303) {
    throw new Error(`engram-cloud dashboard login failed with status ${res.status}`);
  }

  const cookies = res.headers.getSetCookie();
  return { setCookie: cookies.find((c) => c.startsWith('engram_dashboard_token=')) ?? null };
}
