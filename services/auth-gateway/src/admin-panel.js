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
});

/**
 * Shared nav for every authenticated admin page: back to Users, cross-links
 * to /dashboard (Engram Cloud's own UI) and /monitor (engram-monitor) —
 * both already reachable from here without a second login, since they sit
 * behind the SAME admin session on this same host (single perimeter,
 * single login) — and a Log out form reusing the page's own admin CSRF
 * token (same uid, same admin CSRF domain — no separate token issuance
 * needed for it).
 * @param {string} csrfToken
 * @returns {string}
 */
function renderAdminNav(csrfToken) {
  return `<nav class="nav">
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
export function renderConsolePage({ view, csrfToken, role = 'admin' }) {
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
 * One row of the admin-panel accounts table — username, role, status.
 * `role`/`disabled_at` are server-sourced (listAdminAccounts), still
 * escaped (A12 precedent).
 * @param {{ username: string, role: string, disabled_at: string | null }} account
 * @returns {string}
 */
function renderAdminAccountRow(account) {
  const status = account.disabled_at ? 'disabled' : 'active';
  return `<tr>
    <td>${escapeHtml(account.username)}</td>
    <td>${escapeHtml(account.role)}</td>
    <td><span class="badge">${status}</span></td>
  </tr>`;
}

/**
 * Renders the zero-JavaScript `/admin/users` page: the regular-user list
 * with a token-count summary, the create-user form, and (user-requested,
 * 2026-09-17) a read-only list of admin-panel accounts themselves
 * (admin/member, admin-identity-unification) with their role — previously
 * invisible anywhere in the UI. `isAdmin` is never a field on the
 * create-user form (design.md's Create a Regular User requirement) — the
 * handler that posts here forces is_admin=0 unconditionally, so there is
 * nothing here for a submitted body field to override even if one were
 * added.
 * @param {{
 *   users: Array<{ id: number, username: string, created_at: string, disabled_at: string | null, active_token_count: number, revoked_token_count: number }>,
 *   adminAccounts?: Array<{ id: number, username: string, role: string, created_at: string, disabled_at: string | null }>,
 *   csrfToken: string,
 *   errorCode?: string | null,
 * }} options
 * @returns {string}
 */
export function renderUsersPage({ users, adminAccounts = [], csrfToken, errorCode }) {
  const errorMessage =
    errorCode && Object.prototype.hasOwnProperty.call(ADMIN_PANEL_ERRORS, errorCode)
      ? ADMIN_PANEL_ERRORS[errorCode]
      : null;
  const errorMarkup = errorMessage ? `<p class="error">${escapeHtml(errorMessage)}</p>` : '';
  const rows = users.map((user) => renderUserRow(user, csrfToken)).join('\n');
  const adminAccountRows = adminAccounts.map((account) => renderAdminAccountRow(account)).join('\n');
  const body = `<main>
  ${renderAdminNav(csrfToken)}
  <h1>Users</h1>
  ${errorMarkup}
  <div class="table-wrap">
  <table>
    <thead>
      <tr><th>Username</th><th>Status</th><th>Active tokens</th><th>Revoked tokens</th><th></th><th></th></tr>
    </thead>
    <tbody>
      ${rows}
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
  <h2>Admin panel accounts</h2>
  <p class="note">Who can log into this panel, and with which role (Import from Engram Cloud, above, links each to a Cloud principal).</p>
  <div class="table-wrap">
  <table>
    <thead>
      <tr><th>Username</th><th>Role</th><th>Status</th></tr>
    </thead>
    <tbody>
      ${adminAccountRows}
    </tbody>
  </table>
  </div>
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
 * @param {{ principals: Array<{ principal_id: string, username: string, role: string }>, csrfToken: string, errorCode?: string | null }} options
 * @returns {string}
 */
export function renderImportPage({ principals, csrfToken, errorCode }) {
  const errorMessage =
    errorCode && Object.prototype.hasOwnProperty.call(ADMIN_PANEL_ERRORS, errorCode)
      ? ADMIN_PANEL_ERRORS[errorCode]
      : null;
  const errorMarkup = errorMessage ? `<p class="error">${escapeHtml(errorMessage)}</p>` : '';
  const rows = principals.map((p) => renderImportRow(p, csrfToken)).join('\n');
  const body = `<main>
  ${renderAdminNav(csrfToken)}
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
 * }} options
 * @returns {string}
 */
export function renderTokensPage({ username, userId, tokens, csrfToken, errorCode }) {
  const errorMessage =
    errorCode && Object.prototype.hasOwnProperty.call(ADMIN_PANEL_ERRORS, errorCode)
      ? ADMIN_PANEL_ERRORS[errorCode]
      : null;
  const errorMarkup = errorMessage ? `<p class="error">${escapeHtml(errorMessage)}</p>` : '';
  const rows = tokens.map((token) => renderTokenRow(token, userId, csrfToken)).join('\n');
  const body = `<main>
  ${renderAdminNav(csrfToken)}
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
 * One copyable MCP client config block for a single granted subproject —
 * a read-only `<textarea>` (click-to-select-all, then Ctrl/Cmd+C) is the
 * closest zero-JS equivalent to a real "click to copy" button under this
 * app's CSP (`default-src 'none'`, no `script-src`) — the same
 * constraint already accepted for the password show/hide toggle.
 * @param {{ mcpUrl: string, rawToken: string, subproject: string }} options
 * @returns {string}
 */
function renderMcpConfigBlock({ mcpUrl, rawToken, subproject }) {
  const config = {
    'engram-remote-mcp': {
      type: 'http',
      url: mcpUrl,
      headers: {
        Authorization: `Bearer ${rawToken}`,
        'X-Engram-Subproject': subproject,
      },
    },
  };
  return `<div class="mcp">
  <h2>${escapeHtml(subproject)}</h2>
  <textarea readonly rows="8">${escapeHtml(JSON.stringify(config, null, 2))}</textarea>
</div>`;
}

/**
 * GET /admin/profile[?userId=N] (mcp-profile-page) — one account's MCP
 * client config (Bearer token + granted subprojects), self-service for
 * both admin and member. `rawToken` is only ever non-null on the
 * request that just issued/regenerated it (D10) — every later view
 * shows `tokenMeta` instead, with no live secret anywhere on the page.
 *
 * No real "click to copy" button exists here — this app's CSP
 * (`default-src 'none'`, no `script-src`) makes that impossible, the
 * same constraint already accepted for the password show/hide toggle.
 * The read-only `<textarea>` is the closest equivalent: click inside,
 * Ctrl/Cmd+A, then copy.
 * @param {{
 *   target: { id: number, username: string, role: string },
 *   subprojects: string[],
 *   rawToken: string | null,
 *   tokenMeta: { id: number, label: string | null, created_at: string, last_used_at: string | null } | null,
 *   mcpUrl: string,
 *   csrfToken: string,
 * }} options
 * @returns {string}
 */
export function renderProfilePage({ target, subprojects, rawToken, tokenMeta, mcpUrl, csrfToken }) {
  const configBlocks = rawToken
    ? subprojects.map((subproject) => renderMcpConfigBlock({ mcpUrl, rawToken, subproject })).join('\n')
    : '';
  const noGrantsNote =
    rawToken && subprojects.length === 0
      ? '<p class="note">No Engram Cloud project grants yet — ask an admin, then reload this page.</p>'
      : '';
  const existingTokenMarkup =
    !rawToken && tokenMeta
      ? `<div class="mcp">
    <h2>Current token</h2>
    <p class="note">Label: ${escapeHtml(tokenMeta.label ?? '(no label)')} — created ${escapeHtml(tokenMeta.created_at)} — last used ${escapeHtml(tokenMeta.last_used_at ?? 'never')}.</p>
    <p class="note">The raw value is never shown again after it was issued — regenerate to get a fresh, copyable one.</p>
    ${
      subprojects.length > 0
        ? `<p>Granted subprojects: ${subprojects.map((s) => escapeHtml(s)).join(', ')}</p>`
        : '<p class="note">No Engram Cloud project grants yet.</p>'
    }
    <form method="post" action="/admin/profile/regenerate-token">
      <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
      <input type="hidden" name="tokenId" value="${tokenMeta.id}">
      <input type="hidden" name="userId" value="${target.id}">
      <button type="submit">Regenerate</button>
    </form>
  </div>`
      : '';
  const body = `<main>
  <h1>Profile: ${escapeHtml(target.username)} (${escapeHtml(target.role)})</h1>
  ${rawToken ? '<p class="error">Copy this now — the token will not be shown again.</p>' : ''}
  ${configBlocks}
  ${noGrantsNote}
  ${existingTokenMarkup}
</main>`;
  return renderDocument({ title: `Admin — Profile: ${target.username}`, body });
}
