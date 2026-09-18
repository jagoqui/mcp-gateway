import { escapeHtml, renderDocument } from './html.js';

/**
 * Allow-list of `?error=` codes the admin users page will render a banner
 * for — the reflected-XSS guard (A13), mirroring panel.js's PANEL_ERRORS:
 * an unrecognized `errorCode` renders no banner at all, the raw query value
 * is never echoed into the page.
 * @type {Readonly<Record<string, string>>}
 */
export const ADMIN_PANEL_ERRORS = Object.freeze({
  invalid: 'Enter a username and password.',
  duplicate: 'That username is already taken.',
  csrf: 'Your page expired. Reload and try again.',
  not_found: 'That user could not be found.',
  mismatch: 'Password and confirmation must match.',
  unreachable: 'Engram Cloud is unreachable right now. Try again shortly.',
  invalid_project: 'Enter a project name.',
});

/**
 * Shared nav for every authenticated admin page: who is logged in (user-
 * requested, 2026-09-18 — no page showed this before), back to Users,
 * cross-links to /dashboard (Engram Cloud's own UI) and /monitor
 * (engram-monitor) — both already reachable from here without a second
 * login, since they sit behind the SAME admin session on this same host
 * (single perimeter, single login) — and a Log out form reusing the
 * page's own admin CSRF token (same uid, same admin CSRF domain — no
 * separate token issuance needed for it).
 * @param {string} csrfToken
 * @param {{ username: string, role: string }} viewer
 * @returns {string}
 */
function renderAdminNav(csrfToken, viewer) {
  return `<nav class="nav">
  <span class="note">Logged in as ${escapeHtml(viewer.username)} (${escapeHtml(viewer.role)})</span>
  <a href="/admin/users">Users</a>
  <a href="/admin/console?view=cloud">Engram Cloud dashboard</a>
  <a href="/admin/console?view=monitor">Monitor</a>
  <a href="/admin/engram-cloud/import">Import from Engram Cloud</a>
  <a href="/admin/profile">Profile</a>
  <form method="post" action="/admin/logout">
    <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
    <button type="submit">Log out</button>
  </form>
</nav>`;
}

/**
 * GET /admin/console?view=monitor|cloud (Phase 5) — the shared
 * header+sidebar+main shell requested alongside SSO: Monitor and Engram
 * Cloud's own dashboard render inside `<main>` via `<iframe>` instead of two
 * unrelated full-page products. Neither is this app's own frontend source
 * (Monitor: separate repo; Cloud: vendored binary), so a true shared shell —
 * not just matching chrome — needs framing; confirmed via deepwiki that
 * neither sends X-Frame-Options/frame-ancestors (design.md Phase 5). The
 * `cloud` view's iframe src IS the SSO route (`/admin/engram-cloud/sso`),
 * so opening that tab performs the per-admin login and lands the iframe on
 * `/dashboard` in one step — no separate "log in first" click.
 * @param {{ view?: string | null, csrfToken: string, role?: string }} options
 * @returns {string}
 */
export function renderConsolePage({ view, csrfToken, role = 'admin', username = '' }) {
  const isAdmin = role === 'admin';
  // Unit 3: a member only ever reaches this page for the cloud view — the
  // handler already forces it server-side (handleGetAdminConsole), so the
  // Monitor tab and Users link would only ever 403 if a member clicked
  // them. Hidden here for UX, not as the actual enforcement boundary.
  const activeView = isAdmin && view === 'cloud' ? 'cloud' : isAdmin ? 'monitor' : 'cloud';
  const iframeSrc = activeView === 'cloud' ? '/admin/engram-cloud/sso' : '/monitor';
  const usersLink = isAdmin ? '<a href="/admin/users">Users</a>' : '';
  const monitorTab = isAdmin
    ? `<a href="/admin/console?view=monitor"${activeView === 'monitor' ? ' class="active"' : ''}>Monitor</a>`
    : '';
  const body = `<div class="shell">
  <header class="shell-header">
    <span class="note">Logged in as ${escapeHtml(username)} (${escapeHtml(role)})</span>
    ${usersLink}
    <a href="/admin/profile">Profile</a>
    <form method="post" action="/admin/logout">
      <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
      <button type="submit">Log out</button>
    </form>
  </header>
  <aside class="shell-sidebar">
    ${monitorTab}
    <a href="/admin/console?view=cloud"${activeView === 'cloud' ? ' class="active"' : ''}>Engram Cloud</a>
  </aside>
  <main class="shell-main">
    <iframe src="${escapeHtml(iframeSrc)}" title="${activeView === 'cloud' ? 'Engram Cloud' : 'Monitor'}"></iframe>
  </main>
</div>`;
  return renderDocument({ title: 'Admin — Console', body });
}

/**
 * One row of the users table, plus its disable/enable form (Unit 9) —
 * whichever action is valid for the row's current state, mirroring
 * panel.js's renderPerUserSection delete-form convention: a tiny
 * single-button `<form>` carrying the hidden `userId` + `csrf` fields
 * needed by POST /admin/users/disable or /admin/users/enable.
 * `active_token_count`/`revoked_token_count` are SQL-aggregated integers
 * (listManagedUsers), never user input, so they are interpolated directly —
 * only `username` goes through escapeHtml (A12: stored XSS via a malicious
 * username).
 * @param {{ id: number, username: string, disabled_at: string | null, active_token_count: number, revoked_token_count: number }} user
 * @param {string} csrfToken
 * @returns {string}
 */
function renderUserRow(user, csrfToken) {
  const disabled = Boolean(user.disabled_at);
  const badge = disabled ? 'disabled' : 'active';
  const action = disabled ? 'enable' : 'disable';
  const label = disabled ? 'Enable' : 'Disable';
  const actionFormMarkup = `<form method="post" action="/admin/users/${action}">
    <input type="hidden" name="userId" value="${user.id}">
    <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
    <button type="submit">${label}</button>
  </form>`;
  return `<tr>
    <td>${escapeHtml(user.username)}</td>
    <td><span class="badge">${badge}</span></td>
    <td>${user.active_token_count}</td>
    <td>${user.revoked_token_count}</td>
    <td><a href="/admin/users/tokens?userId=${user.id}">Tokens</a></td>
    <td>${actionFormMarkup}</td>
  </tr>`;
}

/**
 * One row of the admin-panel accounts (admin/member) portion of the
 * unified users table — same 6-column shape `renderUserRow` uses, so
 * both kinds sit in ONE `<table>` (user-requested, 2026-09-18: the two
 * separate tables this page used to have were confusing — "admin panel
 * accounts is the source of truth", one list). Role and Cloud-link
 * status stand in for the "Active/Revoked tokens" columns (an admin
 * account's own MCP token is managed on its own Profile page, not
 * counted here); no Disable/Enable form yet for this kind of account —
 * left blank rather than a dead-end action.
 * @param {{ id: number, username: string, role: string, disabled_at: string | null }} account
 * @param {string | null} cloudPrincipalId
 * @returns {string}
 */
function renderAdminAccountRow(account, cloudPrincipalId) {
  const status = account.disabled_at ? 'disabled' : 'active';
  return `<tr>
    <td>${escapeHtml(account.username)}</td>
    <td><span class="badge">${status}</span> <span class="badge">${escapeHtml(account.role)}</span></td>
    <td colspan="2">${cloudPrincipalId ? `Cloud: ${escapeHtml(cloudPrincipalId)}` : 'Not linked to Engram Cloud'}</td>
    <td><a href="/admin/profile?userId=${account.id}">Profile</a></td>
    <td></td>
  </tr>`;
}

/**
 * Renders the zero-JavaScript `/admin/users` page: ONE unified table (see
 * `renderAdminAccountRow`'s own note) mixing regular gateway users
 * (MCP-tool access, token counts) and admin-panel accounts (admin/member,
 * Engram Cloud link) — previously two separate tables — plus the
 * create-user form. `isAdmin` is never a field on that form (design.md's
 * Create a Regular User requirement) — the handler that posts here
 * forces is_admin=0 unconditionally, so there is nothing here for a
 * submitted body field to override even if one were added.
 * @param {{
 *   users: Array<{ id: number, username: string, created_at: string, disabled_at: string | null, active_token_count: number, revoked_token_count: number }>,
 *   adminAccounts?: Array<{ id: number, username: string, role: string, created_at: string, disabled_at: string | null }>,
 *   cloudLinksByUserId?: Map<number, string>,
 *   csrfToken: string,
 *   errorCode?: string | null,
 *   viewer: { username: string, role: string },
 * }} options
 * @returns {string}
 */
export function renderUsersPage({
  users,
  adminAccounts = [],
  cloudLinksByUserId = new Map(),
  unlinkedCloudPrincipalCount = 0,
  csrfToken,
  errorCode,
  viewer,
}) {
  const errorMessage =
    errorCode && Object.prototype.hasOwnProperty.call(ADMIN_PANEL_ERRORS, errorCode)
      ? ADMIN_PANEL_ERRORS[errorCode]
      : null;
  const errorMarkup = errorMessage ? `<p class="error">${escapeHtml(errorMessage)}</p>` : '';
  // cloud-first-identity-and-passwords: surfaced HERE, not just behind the
  // nav's separate "Import from Engram Cloud" link — user-requested
  // (2026-09-18), Cloud is now the only place a new human identity gets
  // created, so this is the first place an admin should notice one needs
  // a local login attached.
  const importBanner =
    unlinkedCloudPrincipalCount > 0
      ? `<p class="note">${unlinkedCloudPrincipalCount} Engram Cloud principal(s) with no local login yet — <a href="/admin/engram-cloud/import">Import</a>.</p>`
      : '';
  const regularRows = users.map((user) => renderUserRow(user, csrfToken)).join('\n');
  const adminRows = adminAccounts
    .map((account) => renderAdminAccountRow(account, cloudLinksByUserId.get(account.id) ?? null))
    .join('\n');
  const body = `<main>
  ${renderAdminNav(csrfToken, viewer)}
  <h1>Users</h1>
  ${errorMarkup}
  ${importBanner}
  <div class="table-wrap">
  <table>
    <thead>
      <tr><th>Username</th><th>Status</th><th>Active tokens</th><th>Revoked tokens</th><th></th><th></th></tr>
    </thead>
    <tbody>
      ${regularRows}
      ${adminRows}
    </tbody>
  </table>
  </div>
  <h2>Create user</h2>
  <form method="post" action="/admin/users">
    <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
    <label>Username <input type="text" name="username" required autofocus autocomplete="off"></label>
    <label>Password <input type="password" name="password" required autocomplete="new-password"></label>
    <label>Confirm password <input type="password" name="passwordConfirm" required autocomplete="new-password"></label>
    <button type="submit">Create user</button>
  </form>
</main>`;
  return renderDocument({ title: 'Admin — Users', body });
}

/**
 * One row of the import list — a Cloud principal with no local admin
 * account yet, and its own create-account form (admin-identity-unification,
 * `engram-cloud-principal-import` spec). `principalId`/`username`/`role`
 * come from Engram Cloud's own API response, never user input at render
 * time — still escaped (A12 precedent, same reasoning as every other
 * server-sourced value rendered in this panel).
 * @param {{ principal_id: string, username: string, role: string }} principal
 * @param {string} csrfToken
 * @returns {string}
 */
function renderImportRow(principal, csrfToken) {
  // Never trust an unrecognized Cloud role value into a silent local
  // admin grant (Unit 3) — anything but the exact string 'admin' becomes
  // 'member', the least-privileged option.
  const localRole = principal.role === 'admin' ? 'admin' : 'member';
  return `<tr>
    <td>${escapeHtml(principal.username)}</td>
    <td>${escapeHtml(principal.role)}</td>
    <td>
      <form method="post" action="/admin/engram-cloud/import">
        <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
        <input type="hidden" name="principalId" value="${escapeHtml(principal.principal_id)}">
        <input type="hidden" name="role" value="${escapeHtml(localRole)}">
        <label>New local username <input type="text" name="username" required autocomplete="off"></label>
        <label>Password <input type="password" name="password" required autocomplete="new-password"></label>
        <label>Confirm password <input type="password" name="passwordConfirm" required autocomplete="new-password"></label>
        <button type="submit">Import</button>
      </form>
    </td>
  </tr>`;
}

/**
 * GET /admin/engram-cloud/import — lists Engram Cloud principals that have
 * no local admin account yet, each with its own import form.
 * @param {{ principals: Array<{ principal_id: string, username: string, role: string }>, csrfToken: string, errorCode?: string | null, viewer: { username: string, role: string } }} options
 * @returns {string}
 */
export function renderImportPage({ principals, csrfToken, errorCode, viewer }) {
  const errorMessage =
    errorCode && Object.prototype.hasOwnProperty.call(ADMIN_PANEL_ERRORS, errorCode)
      ? ADMIN_PANEL_ERRORS[errorCode]
      : null;
  const errorMarkup = errorMessage ? `<p class="error">${escapeHtml(errorMessage)}</p>` : '';
  const rows = principals.map((p) => renderImportRow(p, csrfToken)).join('\n');
  const body = `<main>
  ${renderAdminNav(csrfToken, viewer)}
  <h1>Import from Engram Cloud</h1>
  <p class="note">Engram Cloud principals with no local account yet.</p>
  ${errorMarkup}
  <div class="table-wrap">
  <table>
    <thead>
      <tr><th>Cloud username</th><th>Cloud role</th><th></th></tr>
    </thead>
    <tbody>
      ${rows}
    </tbody>
  </table>
  </div>
</main>`;
  return renderDocument({ title: 'Admin — Import from Engram Cloud', body });
}

/**
 * One row of the tokens table — label, created_at, last_used_at, and
 * revoked state (spec's View a User's Tokens requirement) — no token_hash
 * or raw token column exists in `listTokensForUser`'s projection at all,
 * so there is nothing here that could leak one even by mistake. Revoke and
 * Regenerate only render for an active token: revoking or regenerating an
 * already-revoked one can never succeed
 * (OWNED_ACTIVE_TOKEN_PREDICATE requires revoked_at IS NULL), so the panel
 * never even offers the dead-end action.
 * @param {{ id: number, label: string | null, created_at: string, last_used_at: string | null, revoked_at: string | null }} token
 * @param {number} userId
 * @param {string} csrfToken
 * @returns {string}
 */
function renderTokenRow(token, userId, csrfToken) {
  const active = !token.revoked_at;
  const badge = active ? 'active' : 'revoked';
  const actionsMarkup = active
    ? `<form method="post" action="/admin/tokens/revoke">
      <input type="hidden" name="userId" value="${userId}">
      <input type="hidden" name="tokenId" value="${token.id}">
      <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
      <button type="submit">Revoke</button>
    </form>
    <form method="post" action="/admin/tokens/regenerate">
      <input type="hidden" name="userId" value="${userId}">
      <input type="hidden" name="tokenId" value="${token.id}">
      <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
      <button type="submit">Regenerate</button>
    </form>`
    : '';
  return `<tr>
    <td>${escapeHtml(token.label ?? '(no label)')}</td>
    <td>${escapeHtml(token.created_at)}</td>
    <td>${escapeHtml(token.last_used_at ?? 'never')}</td>
    <td><span class="badge">${badge}</span></td>
    <td>${actionsMarkup}</td>
  </tr>`;
}

/**
 * Renders the zero-JavaScript `GET /admin/users/tokens?userId=N` page: one
 * target user's token list plus the issue-new-token form. `userId` is
 * always the caller-resolved, already-eligibility-checked id (admin-app.js
 * calls getManagedUser before this ever renders) — never trusted input
 * re-echoed from the query string itself.
 * @param {{
 *   username: string,
 *   userId: number,
 *   tokens: Array<{ id: number, label: string | null, created_at: string, last_used_at: string | null, revoked_at: string | null }>,
 *   csrfToken: string,
 *   errorCode?: string | null,
 *   viewer: { username: string, role: string },
 * }} options
 * @returns {string}
 */
export function renderTokensPage({ username, userId, tokens, csrfToken, errorCode, viewer }) {
  const errorMessage =
    errorCode && Object.prototype.hasOwnProperty.call(ADMIN_PANEL_ERRORS, errorCode)
      ? ADMIN_PANEL_ERRORS[errorCode]
      : null;
  const errorMarkup = errorMessage ? `<p class="error">${escapeHtml(errorMessage)}</p>` : '';
  const rows = tokens.map((token) => renderTokenRow(token, userId, csrfToken)).join('\n');
  const body = `<main>
  ${renderAdminNav(csrfToken, viewer)}
  <h1>Tokens for ${escapeHtml(username)}</h1>
  <p><a href="/admin/users">Back to users</a></p>
  ${errorMarkup}
  <div class="table-wrap">
  <table>
    <thead>
      <tr><th>Label</th><th>Created</th><th>Last used</th><th>Status</th><th></th></tr>
    </thead>
    <tbody>
      ${rows}
    </tbody>
  </table>
  </div>
  <h2>Issue token</h2>
  <form method="post" action="/admin/tokens/issue">
    <input type="hidden" name="userId" value="${userId}">
    <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
    <label>Label (optional) <input type="text" name="label" autocomplete="off"></label>
    <button type="submit">Issue token</button>
  </form>
</main>`;
  return renderDocument({ title: `Admin — Tokens for ${username}`, body });
}

/**
 * Renders POST /admin/tokens/issue's success response directly, in place —
 * never a redirect (D10: "breaking POST/Redirect/GET"). The show-once raw
 * token value cannot survive a 302 without traveling in a Location query
 * string, which would land it in Caddy access logs, browser history, and
 * Referer; ADMIN_PAGE_HEADERS already carries Referrer-Policy: no-referrer
 * as the second layer of that same defense. Shown exactly once — no route
 * this change adds will ever return this value again.
 * @param {{ username: string, userId: number, rawToken: string }} options
 * @returns {string}
 */
export function renderTokenIssuedPage({ username, userId, rawToken }) {
  const body = `<main>
  <h1>Token issued for ${escapeHtml(username)}</h1>
  <p class="error">Copy this token now — it will not be shown again.</p>
  <p><code>${escapeHtml(rawToken)}</code></p>
  <p><a href="/admin/users/tokens?userId=${userId}">Back to tokens</a></p>
</main>`;
  return renderDocument({ title: 'Admin — Token issued', body });
}

/**
 * POST /admin/engram-cloud/import's success response, rendered directly
 * (200, D10 show-once) — mirrors `renderTokenIssuedPage` above exactly
 * (D11): the generated default LOGIN password (cloud-first-identity-
 * and-passwords) is shown exactly once, here, and never persisted
 * anywhere but its bcrypt hash.
 * @param {{ username: string, rawPassword: string }} options
 * @returns {string}
 */
export function renderImportedPage({ username, rawPassword }) {
  const body = `<main>
  <h1>Login created for ${escapeHtml(username)}</h1>
  <p class="error">Copy this password now — it will not be shown again.</p>
  <p><code>${escapeHtml(rawPassword)}</code></p>
  <p><a href="/admin/users">Back to users</a></p>
</main>`;
  return renderDocument({ title: 'Admin — Login created', body });
}

/**
 * One copyable MCP client config block — a read-only `<textarea>`
 * (click-to-select-all, then Ctrl/Cmd+C) is the closest zero-JS
 * equivalent to a real "click to copy" button under this app's CSP
 * (`default-src 'none'`, no `script-src`) — the same constraint already
 * accepted for the password show/hide toggle.
 *
 * `subproject: null` renders the account's own PRIVATE default project
 * (engram-shared-projects: omitting `X-Engram-Subproject` entirely is
 * what makes engram-router fall back to the identity-scoped default, no
 * grant required) — a non-null value renders one granted SHARED project,
 * with the header set to that exact bare name.
 * @param {{ mcpUrl: string, rawToken: string, subproject: string | null }} options
 * @returns {string}
 */
function renderMcpConfigBlock({ mcpUrl, rawToken, subproject }) {
  const headers = { Authorization: `Bearer ${rawToken}` };
  if (subproject) {
    headers['X-Engram-Subproject'] = subproject;
  }
  const config = { 'engram-remote-mcp': { type: 'http', url: mcpUrl, headers } };
  return `<div class="mcp">
  <h2>${escapeHtml(subproject ?? 'Default (private)')}</h2>
  <textarea readonly rows="8">${escapeHtml(JSON.stringify(config, null, 2))}</textarea>
</div>`;
}

/**
 * One row of the profile page's OWN gateway-token history table — same
 * visual shape as `renderTokenRow` above (regular users' `/admin/users/
 * tokens` page), but the actions post to the `/admin/profile/*` routes,
 * which use `resolveProfileTarget` (self for anyone, `userId` admin-only)
 * instead of `getManagedUser`/is_admin=0 eligibility.
 *
 * `userId` is only emitted when `target.id !== viewerId` — a REAL bug,
 * found while adding this table (2026-09-18): the old single-token
 * markup always emitted `userId`, even for a member looking at their
 * OWN profile, and `resolveProfileTarget` rejects ANY non-null `userId`
 * from a non-admin, even one matching their own id. A member clicking
 * Regenerate/Revoke through the real rendered form got a 403 — never
 * caught because every existing test built its POST body by hand,
 * without a `userId` key, instead of submitting what this form actually
 * emits.
 * @param {{ id: number, label: string | null, created_at: string, last_used_at: string | null, revoked_at: string | null }} token
 * @param {{ id: number }} target
 * @param {number} viewerId
 * @param {string} csrfToken
 * @returns {string}
 */
function renderProfileTokenRow(token, target, viewerId, csrfToken) {
  const active = !token.revoked_at;
  const badge = active ? 'active' : 'revoked';
  const userIdField =
    target.id !== viewerId ? `<input type="hidden" name="userId" value="${target.id}">` : '';
  const actionsMarkup = active
    ? `<form method="post" action="/admin/profile/regenerate-token">
      <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
      <input type="hidden" name="tokenId" value="${token.id}">
      ${userIdField}
      <button type="submit">Regenerate</button>
    </form>
    <form method="post" action="/admin/profile/revoke-token">
      <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
      <input type="hidden" name="tokenId" value="${token.id}">
      ${userIdField}
      <button type="submit">Revoke</button>
    </form>`
    : '';
  return `<tr>
    <td>${escapeHtml(token.label ?? '(no label)')}</td>
    <td>${escapeHtml(token.created_at)}</td>
    <td>${escapeHtml(token.last_used_at ?? 'never')}</td>
    <td>${escapeHtml(token.last_used_project ?? 'default (private)')}</td>
    <td><span class="badge">${badge}</span></td>
    <td>${actionsMarkup}</td>
  </tr>`;
}

/**
 * Full gateway-token history (all rows from `listTokensForUser`, active
 * and revoked) — replaces the old single "Current token" block, which
 * only ever showed the one active token and hid everything before it.
 * @param {Array<{ id: number, label: string | null, created_at: string, last_used_at: string | null, last_used_project: string | null, revoked_at: string | null }>} gatewayTokens
 * @param {{ id: number }} target
 * @param {number} viewerId
 * @param {string} csrfToken
 * @returns {string}
 */
function renderProfileGatewayTokensSection(gatewayTokens, target, viewerId, csrfToken) {
  const rows = gatewayTokens
    .map((token) => renderProfileTokenRow(token, target, viewerId, csrfToken))
    .join('\n');
  return `<h2>Gateway tokens</h2>
  <p class="note">Authenticates into /mcp/engram — the value shown in the config block(s) above, when freshly issued or regenerated. A raw value is never shown again after that one request (D10) — Regenerate to get a fresh, copyable one. "Last project" is the raw X-Engram-Subproject value the client last requested, verbatim — not re-checked against grants here.</p>
  <div class="table-wrap">
  <table>
    <thead>
      <tr><th>Label</th><th>Created</th><th>Last used</th><th>Last project</th><th>Status</th><th></th></tr>
    </thead>
    <tbody>
      ${rows}
    </tbody>
  </table>
  </div>`;
}

/**
 * One row of Engram Cloud's OWN token list (`GET /admin/users/{id}/
 * tokens`, confirmed via deepwiki against `Gentleman-Programming/engram`
 * — `adminTokenMetadata`). Only `token_prefix` is ever returned by Cloud,
 * never the full secret (D10 holds there too, just enforced server-side
 * by Cloud itself). Cloud tracks NO usage count and NO client/machine/IP
 * for a token — nothing here claims otherwise.
 * @param {{ id: string, name: string | null, token_prefix: string, created_at: string, last_used_at: string | null, revoked_at: string | null, revocation_reason: string | null }} token
 * @param {{ id: number }} target
 * @param {number} viewerId
 * @param {string} csrfToken
 * @returns {string}
 */
function renderProfileCloudTokenRow(token, target, viewerId, csrfToken) {
  const active = !token.revoked_at;
  const badge = active ? 'active' : 'revoked';
  const revokedDetail = !active
    ? ` — ${escapeHtml(token.revocation_reason ?? 'no reason given')}`
    : '';
  const userIdField =
    target.id !== viewerId ? `<input type="hidden" name="userId" value="${target.id}">` : '';
  const actionsMarkup = active
    ? `<form method="post" action="/admin/profile/cloud-token/revoke">
      <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
      <input type="hidden" name="tokenId" value="${escapeHtml(token.id)}">
      ${userIdField}
      <button type="submit">Revoke</button>
    </form>`
    : '';
  return `<tr>
    <td>${escapeHtml(token.name ?? '(no name)')}</td>
    <td><code>${escapeHtml(token.token_prefix)}…</code></td>
    <td>${escapeHtml(token.created_at)}</td>
    <td><span class="badge">${badge}</span>${revokedDetail}</td>
    <td>${actionsMarkup}</td>
  </tr>`;
}

/**
 * Engram Cloud's own token section — separate from the gateway tokens
 * above on purpose: this is a DIFFERENT system (Cloud's own admin API,
 * not auth-gateway's SQLite `tokens` table), used only for single
 * sign-on into Cloud's own dashboard, not for MCP access at all.
 * `cloudTokens === null` (no Cloud link at all — `ensureEngramCloudLink`
 * failed and never self-healed) hides the section entirely; an empty
 * array still renders the (empty) table, distinct states on purpose.
 * @param {Array<{ id: string, name: string | null, token_prefix: string, created_at: string, last_used_at: string | null, revoked_at: string | null, revocation_reason: string | null }> | null} cloudTokens
 * @param {{ id: number }} target
 * @param {number} viewerId
 * @param {string} csrfToken
 * @returns {string}
 */
function renderProfileCloudTokensSection(cloudTokens, target, viewerId, csrfToken) {
  if (cloudTokens === null) {
    return '';
  }
  const rows = cloudTokens
    .map((token) => renderProfileCloudTokenRow(token, target, viewerId, csrfToken))
    .join('\n');
  return `<h2>Engram Cloud token</h2>
  <p class="note">Used only for single sign-on into the Cloud dashboard — separate from the gateway token(s) above. Cloud does not track usage count, which device/IP used a token, or when it was last used (confirmed: that field is never written by Cloud's own server, for any route — not shown here since it would always read "never").</p>
  <div class="table-wrap">
  <table>
    <thead>
      <tr><th>Name</th><th>Prefix</th><th>Created</th><th>Status</th><th></th></tr>
    </thead>
    <tbody>
      ${rows}
    </tbody>
  </table>
  </div>`;
}

/**
 * One row of the Projects table — a grant's full metadata (`project`,
 * who granted it, when), not just the bare name already used in the MCP
 * config blocks above.
 * @param {{ project: string, granted_by_principal_id: string, created_at: string }} grant
 * @returns {string}
 */
function renderProfileGrantRow(grant) {
  return `<tr>
    <td>${escapeHtml(grant.project)}</td>
    <td>${escapeHtml(grant.granted_by_principal_id)}</td>
    <td>${escapeHtml(grant.created_at)}</td>
  </tr>`;
}

/**
 * Projects section — full grant metadata, plus (admin only) a "Grant" form.
 * Deny-by-default (user-requested 2026-09-18, quoting Cloud's own model:
 * "New managed users are deny-by-default: they cannot sync any project
 * until an admin grants one explicitly"): granting is ALWAYS admin-only,
 * even when an admin is viewing (or granting to) their own profile — a
 * member never sees this form at all, regardless of whose profile page
 * they're on (self is the only profile a member can ever reach anyway).
 * @param {Array<{ project: string, granted_by_principal_id: string, created_at: string }>} grants
 * @param {{ id: number }} target
 * @param {{ id: number, role: string }} viewer
 * @param {string} csrfToken
 * @param {string[]} [knownProjects]
 * @returns {string}
 */
function renderProfileProjectsSection(grants, target, viewer, csrfToken, knownProjects = []) {
  const rows = grants.map((grant) => renderProfileGrantRow(grant)).join('\n');
  const table =
    grants.length > 0
      ? `<div class="table-wrap">
  <table>
    <thead>
      <tr><th>Project</th><th>Granted by</th><th>Granted at</th></tr>
    </thead>
    <tbody>
      ${rows}
    </tbody>
  </table>
  </div>`
      : '<p class="note">No shared Engram Cloud project grants yet.</p>';
  const userIdField =
    target.id !== viewer.id ? `<input type="hidden" name="userId" value="${target.id}">` : '';
  // A native <datalist> — zero-JS-compatible (this app's CSP forbids any
  // <script>), just autocomplete suggestions off every known project any
  // linked principal has a grant for; the <input> stays free-text so a
  // genuinely new project name still works (Cloud has no "list all
  // projects" endpoint to offer a closed set instead — confirmed via
  // deepwiki, see odd/tasks/cloud-first-identity-and-passwords.md).
  const knownProjectsDatalist =
    knownProjects.length > 0
      ? `<datalist id="known-projects">${knownProjects
          .map((project) => `<option value="${escapeHtml(project)}">`)
          .join('')}</datalist>`
      : '';
  const grantForm =
    viewer.role === 'admin'
      ? `<form method="post" action="/admin/profile/grant-project">
      <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
      ${userIdField}
      <label>Project <input type="text" name="project" list="known-projects" autocomplete="off" required></label>
      ${knownProjectsDatalist}
      <button type="submit">Grant</button>
    </form>`
      : '';
  return `<h2>Projects</h2>
  <p class="note">The default (private) project above is always usable, no grant needed — this list is only SHARED projects, each gated by an explicit grant.</p>
  ${table}
  ${grantForm}`;
}

/**
 * Password section (cloud-first-identity-and-passwords) — "Change my
 * password" is always visible (self-service, any viewer); "Reset
 * password" is admin-only, for the account being VIEWED (self or another
 * admin-panel account) — the two forms are deliberately separate routes
 * (`/admin/profile/change-password` self-only, `/admin/profile/
 * reset-password` admin-only-any-target), not one form with a role branch
 * inside a single handler.
 * @param {{ id: number }} target
 * @param {{ id: number, role: string }} viewer
 * @param {string | null} rawPassword
 * @param {string} csrfToken
 * @returns {string}
 */
function renderProfilePasswordSection(target, viewer, rawPassword, csrfToken) {
  const rawPasswordMarkup = rawPassword
    ? `<p class="error">Copy this now — the password will not be shown again.</p>
    <p><code>${escapeHtml(rawPassword)}</code></p>`
    : '';
  const userIdField =
    target.id !== viewer.id ? `<input type="hidden" name="userId" value="${target.id}">` : '';
  const resetForm =
    viewer.role === 'admin'
      ? `<form method="post" action="/admin/profile/reset-password">
      <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
      ${userIdField}
      <button type="submit">Reset password</button>
    </form>`
      : '';
  const changeForm =
    target.id === viewer.id
      ? `<form method="post" action="/admin/profile/change-password">
      <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
      <label>New password <input type="password" name="password" autocomplete="new-password" required></label>
      <label>Confirm <input type="password" name="passwordConfirm" autocomplete="new-password" required></label>
      <button type="submit">Change my password</button>
    </form>`
      : '';
  return `<h2>Password</h2>
  ${rawPasswordMarkup}
  ${changeForm}
  ${resetForm}`;
}

/**
 * GET /admin/profile[?userId=N] (mcp-profile-page) — one account's MCP
 * client config (Bearer token + granted subprojects), self-service for
 * both admin and member, PLUS full lifecycle for both token systems this
 * account has: the gateway token(s) that actually authenticate into
 * /mcp/engram, and Engram Cloud's own separate token (dashboard SSO
 * only). `rawToken` is only ever non-null on the request that just
 * issued/regenerated a gateway token (D10) — every later view shows
 * `gatewayTokens` metadata instead, with no live secret anywhere on the
 * page.
 *
 * No real "click to copy" button exists here — this app's CSP
 * (`default-src 'none'`, no `script-src`) makes that impossible, the
 * same constraint already accepted for the password show/hide toggle.
 * The read-only `<textarea>` is the closest equivalent: click inside,
 * Ctrl/Cmd+A, then copy.
 * @param {{
 *   target: { id: number, username: string, role: string },
 *   viewer: { username: string, role: string, id: number },
 *   subprojects: string[],
 *   grants: Array<{ project: string, granted_by_principal_id: string, created_at: string }>,
 *   knownProjects?: string[],
 *   rawToken: string | null,
 *   gatewayTokens: Array<{ id: number, label: string | null, created_at: string, last_used_at: string | null, last_used_project: string | null, revoked_at: string | null }>,
 *   cloudTokens: Array<{ id: string, name: string | null, token_prefix: string, created_at: string, last_used_at: string | null, revoked_at: string | null, revocation_reason: string | null }> | null,
 *   rawPassword?: string | null,
 *   mcpUrl: string,
 *   csrfToken: string,
 *   errorCode?: string | null,
 * }} options
 * @returns {string}
 */
export function renderProfilePage({
  target,
  viewer,
  subprojects,
  grants,
  knownProjects = [],
  rawToken,
  gatewayTokens,
  cloudTokens,
  rawPassword = null,
  mcpUrl,
  csrfToken,
  errorCode,
}) {
  const configBlocks = rawToken
    ? [
        renderMcpConfigBlock({ mcpUrl, rawToken, subproject: null }),
        ...subprojects.map((subproject) => renderMcpConfigBlock({ mcpUrl, rawToken, subproject })),
      ].join('\n')
    : '';
  const errorMessage =
    errorCode && Object.prototype.hasOwnProperty.call(ADMIN_PANEL_ERRORS, errorCode)
      ? ADMIN_PANEL_ERRORS[errorCode]
      : null;
  const errorMarkup = errorMessage ? `<p class="error">${escapeHtml(errorMessage)}</p>` : '';
  const body = `<main>
  <p class="note">Logged in as ${escapeHtml(viewer.username)} (${escapeHtml(viewer.role)})</p>
  ${viewer.role === 'admin' ? '<p><a href="/admin/users">Back to users</a></p>' : ''}
  <h1>Profile: ${escapeHtml(target.username)} (${escapeHtml(target.role)})</h1>
  ${errorMarkup}
  ${rawToken ? '<p class="error">Copy this now — the token will not be shown again.</p>' : ''}
  ${configBlocks}
  <section class="mcp">
  ${renderProfileProjectsSection(grants, target, viewer, csrfToken, knownProjects)}
  </section>
  <section class="mcp">
  ${renderProfileGatewayTokensSection(gatewayTokens, target, viewer.id, csrfToken)}
  </section>
  <section class="mcp">
  ${renderProfileCloudTokensSection(cloudTokens, target, viewer.id, csrfToken)}
  </section>
  <section class="mcp">
  ${renderProfilePasswordSection(target, viewer, rawPassword, csrfToken)}
  </section>
</main>`;
  return renderDocument({ title: `Admin — Profile: ${target.username}`, body });
}
