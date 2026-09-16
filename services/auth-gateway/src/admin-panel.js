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
});

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
 * Renders the zero-JavaScript `/admin/users` page: the regular-user list
 * with a token-count summary, plus the create-user form. `isAdmin` is
 * never a field on this form (design.md's Create a Regular User
 * requirement) — the handler that posts here forces is_admin=0
 * unconditionally, so there is nothing here for a submitted body field to
 * override even if one were added.
 * @param {{
 *   users: Array<{ id: number, username: string, created_at: string, disabled_at: string | null, active_token_count: number, revoked_token_count: number }>,
 *   csrfToken: string,
 *   errorCode?: string | null,
 * }} options
 * @returns {string}
 */
export function renderUsersPage({ users, csrfToken, errorCode }) {
  const errorMessage =
    errorCode && Object.prototype.hasOwnProperty.call(ADMIN_PANEL_ERRORS, errorCode)
      ? ADMIN_PANEL_ERRORS[errorCode]
      : null;
  const errorMarkup = errorMessage ? `<p class="error">${escapeHtml(errorMessage)}</p>` : '';
  const rows = users.map((user) => renderUserRow(user, csrfToken)).join('\n');
  const body = `<main>
  <h1>Users</h1>
  ${errorMarkup}
  <table>
    <thead>
      <tr><th>Username</th><th>Status</th><th>Active tokens</th><th>Revoked tokens</th><th></th><th></th></tr>
    </thead>
    <tbody>
      ${rows}
    </tbody>
  </table>
  <h2>Create user</h2>
  <form method="post" action="/admin/users">
    <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
    <label>Username <input type="text" name="username" required autofocus autocomplete="off"></label>
    <label>Password <input type="password" name="password" required autocomplete="new-password"></label>
    <button type="submit">Create user</button>
  </form>
</main>`;
  return renderDocument({ title: 'Admin — Users', body });
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
  <h1>Tokens for ${escapeHtml(username)}</h1>
  <p><a href="/admin/users">Back to users</a></p>
  ${errorMarkup}
  <table>
    <thead>
      <tr><th>Label</th><th>Created</th><th>Last used</th><th>Status</th><th></th></tr>
    </thead>
    <tbody>
      ${rows}
    </tbody>
  </table>
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
